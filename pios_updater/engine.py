"""The update engine: check, install (versioned releases + atomic switch), health check, rollback, recovery."""
import fcntl
import json
import os
import shutil
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from . import UPDATER_API, crypto, manifest as mf, package
from .package import PackageError
from .source import Cancelled, SourceError
from .state import Store, atomic_write
from .version import Version

STEPS = [
    ("download", "Update wird heruntergeladen"),
    ("verify", "Signatur wird überprüft"),
    ("compat", "Systemkompatibilität wird geprüft"),
    ("backup", "Backup wird erstellt"),
    ("install", "Neue Version wird installiert"),
    ("restart", "Dienste werden neu gestartet"),
    ("health", "Systemprüfung läuft"),
    ("done", "Update erfolgreich abgeschlossen"),
]
KEEP_RELEASES = 3
KEEP_BACKUPS = 3
SNOOZE_DEFAULT_H = 24


class UpdateError(Exception):
    """A user-presentable failure of an operation."""
    def __init__(self, msg, code="error"):
        super().__init__(msg)
        self.code = code


@dataclass
class Paths:
    root: Path            # /opt/pios        (releases/, current)
    state: Path           # /var/lib/pios-updater
    data: Path            # /var/lib/pios    (pios.db, secret.key, files/)
    keys: Path            # /usr/share/pios/update-keys
    conf: Path = Path("/etc/pios")

    @property
    def releases(self): return self.root / "releases"
    @property
    def current(self): return self.root / "current"
    @property
    def previous(self): return self.root / "previous"
    @property
    def downloads(self): return self.state / "downloads"
    @property
    def backups(self): return self.state / "backups"
    @property
    def db(self): return self.data / "pios.db"


class Env:
    """Everything that touches the running system; replaced by fakes in tests."""
    def restart_backend(self): raise NotImplementedError
    def stop_backend(self): raise NotImplementedError
    def start_backend(self): raise NotImplementedError
    def health(self, target_version: str, db_path: Path) -> tuple[bool, dict]: raise NotImplementedError
    def os_codename(self) -> str: raise NotImplementedError
    def arch(self) -> str: raise NotImplementedError
    def free_bytes(self, path: Path) -> int: return shutil.disk_usage(path).free


def db_user_version(path: Path) -> int | None:
    try:
        c = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
        try:
            return c.execute("PRAGMA user_version").fetchone()[0]
        finally:
            c.close()
    except sqlite3.Error:
        return None


def db_quick_check(path: Path) -> bool:
    try:
        c = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
        try:
            return c.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        finally:
            c.close()
    except sqlite3.Error:
        return False


class Updater:
    def __init__(self, paths: Paths, source, env: Env, health_timeout=90, health_interval=2.0, async_jobs=True):
        self.p, self.source, self.env = paths, source, env
        self.health_timeout, self.health_interval, self.async_jobs = health_timeout, health_interval, async_jobs
        self.store = Store(paths.state)
        self.keys = crypto.load_trusted_keys(paths.keys)
        self._mutex = threading.Lock()
        self._cancel = False
        self._thread = None
        paths.downloads.mkdir(parents=True, exist_ok=True)
        paths.backups.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ installed state
    def _release_meta(self, d: Path) -> dict | None:
        try:
            return json.loads((d / "release.json").read_text())
        except (OSError, ValueError):
            return None

    def installed(self) -> dict:
        d = self.p.current.resolve() if self.p.current.exists() else None
        m = self._release_meta(d) if d else None
        return {"version": m["version"], "db_schema": m.get("db_schema", 1), "dir": d.name} if m else {"version": None, "db_schema": None, "dir": None}

    def previous_release(self) -> dict | None:
        if not self.p.previous.exists():
            return None
        d = self.p.previous.resolve()
        m = self._release_meta(d)
        return {"version": m["version"], "db_schema": m.get("db_schema", 1), "dir": d.name} if m and d != self.p.current.resolve() else None

    # ------------------------------------------------------------------ status
    def status(self) -> dict:
        cfg, cache, job = self.store.config(), self.store.cache(), self.store.job()
        inst = self.installed()
        avail = cache.get("available")
        now = time.time()
        snooze = cfg.get("snoozed", {}).get(avail["version"], 0) if avail else 0
        return {
            "updater_api": UPDATER_API, "installed": inst, "previous": self.previous_release(),
            "channel": cfg["channel"], "auto_check": cfg["auto_check"],
            "available": avail, "snoozed_until": snooze if snooze > now else 0,
            "last_check": cache.get("checked_at"), "last_success": cache.get("success_at"), "last_error": cache.get("error"),
            "retry_at": cache.get("retry_at"), "job": job, "history": self.store.history()[:20],
            "failed_versions": cfg.get("failed", {}), "busy": self._mutex.locked(),
        }

    def set_config(self, channel=None, auto_check=None):
        cfg = self.store.config()
        if channel is not None:
            if channel not in mf.CHANNELS:
                raise UpdateError("Unbekannter Kanal", "bad_request")
            if channel != cfg["channel"]:
                cache = self.store.cache(); cache.pop("available", None); cache.pop("etag", None)
                self.store.save_cache(cache)
            cfg["channel"] = channel
        if auto_check is not None:
            cfg["auto_check"] = bool(auto_check)
        self.store.save_config(cfg)
        return self.status()

    def snooze(self, version, hours=SNOOZE_DEFAULT_H):
        cfg = self.store.config()
        cfg.setdefault("snoozed", {})[version] = time.time() + hours * 3600
        self.store.save_config(cfg)

    # ------------------------------------------------------------------ check
    def _fetch_manifest(self, release):
        a_m = release.assets.get(f"PiOS-NOVA-update-{release.tag.lstrip('v')}.manifest.json")
        a_s = release.assets.get(f"PiOS-NOVA-update-{release.tag.lstrip('v')}.manifest.json.sig")
        if not a_m or not a_s:
            return None
        raw = self.source.fetch_small(a_m.url, 200_000)
        sig = self.source.fetch_small(a_s.url, 4_096).decode("ascii", "ignore")
        kid = crypto.verify(raw, sig, self.keys)           # raises SignatureError
        m = mf.parse(raw)
        if release.tag != "v" + m.version:
            raise mf.ManifestError("Release-Tag passt nicht zur signierten Version")
        return m, kid, raw

    def compat_problems(self, m: mf.Manifest) -> list[str]:
        inst = self.installed()
        out = []
        if inst["version"] is None:
            return ["Installierte Version unbekannt"]
        if Version(m.min_version) > Version(inst["version"]):
            out.append(f"Zuerst Version {m.min_version} oder neuer installieren (installiert: {inst['version']})")
        if m.os_codename != self.env.os_codename():
            out.append(f"Betriebssystem {m.os_codename} erforderlich (vorhanden: {self.env.os_codename()})")
        if m.arch != self.env.arch():
            out.append(f"Architektur {m.arch} erforderlich")
        return out

    def check(self, force=False) -> dict:
        cfg, cache = self.store.config(), self.store.cache()
        inst = self.installed()
        now = int(time.time())
        cache["checked_at"] = now
        try:
            if inst["version"] is None:
                raise UpdateError("Installierte Version unbekannt")
            if not force and cache.get("retry_at", 0) > now:
                raise SourceError("Wartezeit nach GitHub-Limit", retry_after=cache["retry_at"] - now)
            releases, etag = self.source.list_releases(None if force else cache.get("etag"))
            if releases is None and cache.get("channel_checked") == cfg["channel"] and cache.get("installed_checked") == inst["version"]:
                cache["error"] = None; cache["success_at"] = now           # unchanged since last time
            else:
                if releases is None:
                    releases, etag = self.source.list_releases(None)
                cache["available"] = self._pick(releases or [], cfg["channel"], inst["version"], cache)
                cache.update(etag=etag, error=None, success_at=now, retry_at=0,
                             channel_checked=cfg["channel"], installed_checked=inst["version"])
        except SourceError as e:
            cache["error"] = str(e)
            cache["retry_at"] = now + e.retry_after if e.retry_after else 0
        except UpdateError as e:
            cache["error"] = str(e)
        self.store.save_cache(cache)
        return self.status()

    def _pick(self, releases, channel, installed, cache):
        best = None
        rejected = cache.setdefault("rejected", {})
        for rel in releases:
            tag = rel.tag
            try:
                tv = Version(tag[1:] if tag.startswith("v") else tag)
            except ValueError:
                continue
            if tv <= Version(installed):
                continue
            if channel == "stable" and (tv.is_prerelease or rel.prerelease):
                continue
            try:
                got = self._fetch_manifest(rel)
            except (crypto.SignatureError, mf.ManifestError) as e:
                rejected[tag] = str(e)             # never offered; visible in diagnostics
                continue
            if not got:
                continue
            m, kid, _ = got
            if channel == "stable" and m.channel != "stable":
                continue
            rejected.pop(tag, None)
            if best is None or m.v > best[0].v:
                best = (m, kid)
        if not best:
            return None
        m, kid = best
        problems = self.compat_problems(m)
        return {**m.to_public(), "sha256": m.sha256, "unpacked_size": m.unpacked_size, "key_id": kid, "compatible": not problems, "problems": problems,
                "prerelease": m.v.is_prerelease, "tag": "v" + m.version}

    # ------------------------------------------------------------------ install
    def install(self, version: str) -> dict:
        """Validate, then run the job (in a worker thread unless async_jobs=False)."""
        if not self._mutex.acquire(blocking=False):
            raise UpdateError("Es läuft bereits ein Update", "busy")
        lock = None
        try:
            lock = open(self.p.state / "update.lock", "w")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise UpdateError("Es läuft bereits ein Update", "busy") from None
            job = self.store.job()
            if job and job.get("state") == "running":
                raise UpdateError("Ein unterbrochenes Update wird noch wiederhergestellt", "busy")
            avail = self.store.cache().get("available")
            if not avail or avail["version"] != version:
                raise UpdateError("Diese Version ist nicht verfügbar. Bitte zuerst nach Updates suchen.", "not_available")
            if not avail["compatible"]:
                raise UpdateError("; ".join(avail["problems"]), "incompatible")
            if Version(version) <= Version(self.installed()["version"]):
                raise UpdateError("Diese Version ist bereits installiert oder älter", "not_newer")
            self._check_space(avail)
        except BaseException:
            if lock:
                lock.close()
            self._mutex.release()
            raise
        job = self._new_job("update", self.installed()["version"], version)
        self._cancel = False
        if self.async_jobs:
            self._thread = threading.Thread(target=self._run_update, args=(job, avail, lock), daemon=True, name="pios-update")
            self._thread.start()
        else:
            self._run_update(job, avail, lock)
        return self.status()

    def _check_space(self, avail):
        need = avail["size"] + avail.get("unpacked_size", avail["size"] * 4) + 64 * 1024 * 1024
        for path in (self.p.state, self.p.root):
            if self.env.free_bytes(path) < need:
                raise UpdateError("Nicht genügend freier Speicherplatz für das Update", "no_space")

    def cancel(self):
        job = self.store.job()
        if job and job.get("state") == "running" and job["step"] in ("download",):
            self._cancel = True
            return True
        return False

    # job bookkeeping -------------------------------------------------------
    def _new_job(self, kind, frm, to):
        job = {"id": uuid.uuid4().hex[:12], "kind": kind, "from": frm, "to": to, "state": "running", "step": "download",
               "started": int(time.time()), "steps": [{"id": i, "label": l, "status": "pending", "percent": None} for i, l in STEPS],
               "error": None, "log": [], "pending": None}
        if kind == "rollback":
            job["steps"] = [s for s in job["steps"] if s["id"] in ("backup", "install", "restart", "health", "done")]
            job["step"] = "backup"
        self.store.save_job(job)
        return job

    def _log(self, job, msg):
        job["log"].append(f"{time.strftime('%H:%M:%S')} {msg}")
        job["log"] = job["log"][-200:]
        self.store.save_job(job)

    def _step(self, job, step, status="running", percent=None):
        job["step"] = step
        for s in job["steps"]:
            if s["id"] == step:
                s["status"], s["percent"] = status, percent
                break
        self.store.save_job(job)

    def _progress(self, job, step, last=[0.0]):
        def cb(frac):
            now = time.monotonic()
            if now - last[0] > 0.4 or frac >= 1.0:
                last[0] = now
                self._step(job, step, "running", round(frac * 100))
        return cb

    # the update itself ------------------------------------------------------
    def _run_update(self, job, avail, lock):
        old = self.installed()
        version = avail["version"]
        try:
            try:
                m, raw = self._phase_download_verify(job, avail)
                self._phase_compat(job, m)
                backup = self._phase_backup(job, old, m)
                self._phase_install(job, m, old, backup)
            except Cancelled:
                self._fail(job, "Download abgebrochen", None, keep_state="failed")
                return
            except (SourceError, PackageError, crypto.SignatureError, mf.ManifestError, UpdateError, OSError) as e:
                if self.installed()["version"] != version:        # nothing activated yet: plain failure
                    self._fail(job, str(e) or e.__class__.__name__, None)
                    return
                self._log(job, f"Fehler nach der Aktivierung: {e}")  # activated: continue to health check / rollback
            self._phase_restart_health(job, version, old, backup)
        finally:
            try:
                lock.close()
            finally:
                if self._mutex.locked():
                    self._mutex.release()

    def _fail(self, job, error, cleanup, keep_state="failed"):
        job["state"], job["error"] = keep_state, error
        for s in job["steps"]:
            if s["id"] == job["step"] and s["status"] == "running":
                s["status"] = "error"
        self._log(job, f"FEHLER: {error}")
        shutil.rmtree(self.p.releases / f".{job['to']}.partial", ignore_errors=True)
        self.store.add_history({"version": job["to"], "from": job["from"], "result": "failed", "error": error})
        self._mark_failed(job["to"], error)

    def _mark_failed(self, version, reason):
        cfg = self.store.config()
        cfg.setdefault("failed", {})[version] = {"reason": reason, "time": int(time.time())}
        self.store.save_config(cfg)

    def _phase_download_verify(self, job, avail):
        self._step(job, "download", "running", 0)
        rel = next((r for r in (self.source.list_releases(None)[0] or []) if r.tag == avail["tag"]), None)
        if not rel:
            raise UpdateError("Release auf GitHub nicht mehr gefunden")
        # Re-fetch + re-verify the signed manifest: nothing cached on disk is trusted.
        got = self._fetch_manifest(rel)
        if not got:
            raise UpdateError("Release enthält kein signiertes Manifest")
        m, _kid, raw = got
        if m.version != avail["version"] or m.sha256 != self._cached_sha(avail):
            raise UpdateError("Manifest hat sich seit der Prüfung geändert; bitte erneut suchen")
        asset = rel.assets.get(m.file)
        if not asset or asset.size != m.size:
            raise UpdateError("Paket fehlt im Release oder die Größe stimmt nicht mit dem Manifest überein")
        d = self.p.downloads / m.version
        d.mkdir(parents=True, exist_ok=True)
        part, final = d / (m.file + ".part"), d / m.file
        if not final.exists():
            self._log(job, f"Lade {m.file} ({m.size} Bytes)")
            self.source.download(asset.url, part, m.size, self._progress(job, "download"), cancel=lambda: self._cancel)
            os.replace(part, final)
        self._step(job, "download", "done", 100)
        self._step(job, "verify", "running")
        if final.stat().st_size != m.size or package.sha256_file(final) != m.sha256:
            final.unlink(missing_ok=True)
            raise PackageError("Prüfsumme des Pakets stimmt nicht mit dem signierten Manifest überein; Paket verworfen")
        self._log(job, f"Signatur gültig, SHA-256 stimmt ({m.sha256[:12]}…)")
        self._step(job, "verify", "done")
        return m, raw

    def _cached_sha(self, avail):
        return avail.get("sha256") or ""

    def _phase_compat(self, job, m):
        self._step(job, "compat", "running")
        problems = self.compat_problems(m)
        if problems:
            raise UpdateError("; ".join(problems))
        if Version(m.version) <= Version(self.installed()["version"]):
            raise UpdateError("Versionsstand hat sich geändert")
        self._check_space({"size": m.size, "unpacked_size": m.unpacked_size})
        self._step(job, "compat", "done")

    def _phase_backup(self, job, old, m) -> Path:
        self._step(job, "backup", "running")
        b = self._make_backup(old, label=f"{old['version']}-to-{m.version}")
        job["pending"] = {"backup": b.name}
        self._log(job, f"Backup: {b.name}")
        self._step(job, "backup", "done")
        return b

    def _make_backup(self, old, label) -> Path:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        b = self.p.backups / f"{stamp}-{label}"
        b.mkdir(parents=True)
        meta = {"from": old["version"], "from_schema": old["db_schema"], "time": int(time.time()), "label": label,
                "db_user_version": db_user_version(self.p.db), "files": []}
        if self.p.db.exists():
            src = sqlite3.connect(f"file:{self.p.db}?mode=ro", uri=True, timeout=30)
            dst = sqlite3.connect(b / "pios.db")
            try:
                src.backup(dst)                   # consistent online copy (WAL-safe)
            finally:
                dst.close(); src.close()
            meta["files"].append("pios.db")
            if not db_quick_check(b / "pios.db"):
                raise UpdateError("Backup der Datenbank ist inkonsistent; Update abgebrochen")
        for rel in ("secret.key", "setup-complete"):
            f = self.p.data / rel
            if f.is_file():
                shutil.copy2(f, b / rel); meta["files"].append(rel)
        conf = self.p.conf / "pios.conf"
        if conf.is_file():
            shutil.copy2(conf, b / "pios.conf"); meta["files"].append("pios.conf")
        atomic_write(b / "meta.json", meta)
        # user files in data/files are never copied nor touched by updates or rollbacks
        for old_b in sorted(self.p.backups.iterdir())[:-KEEP_BACKUPS]:
            shutil.rmtree(old_b, ignore_errors=True)
        return b

    def _phase_install(self, job, m, old, backup):
        self._step(job, "install", "running", 0)
        partial = self.p.releases / f".{m.version}.partial"
        final = self.p.releases / m.version
        self.p.releases.mkdir(parents=True, exist_ok=True)
        shutil.rmtree(partial, ignore_errors=True)
        pkg = self.p.downloads / m.version / m.file
        package.unpack(pkg, partial, m.unpacked_size, self._progress(job, "install"))
        package.validate_tree(partial, m.version, m.db_schema)
        if final.exists():
            shutil.rmtree(final)
        os.replace(partial, final)
        self._fsync_dir(self.p.releases)
        # journal first, then the single atomic switch
        job["pending"] = {"backup": backup.name, "from": old["version"], "from_dir": old["dir"], "to_dir": m.version}
        self._log(job, f"Aktiviere {m.version} (vorher {old['version']})")
        self._switch(final.name, old["dir"])
        self._step(job, "install", "done", 100)

    def _fsync_dir(self, d):
        fd = os.open(d, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _symlink(self, link: Path, target: str):
        tmp = link.with_name(link.name + ".new")
        tmp.unlink(missing_ok=True)
        os.symlink(f"releases/{target}", tmp)
        os.replace(tmp, link)                                # atomic: readers see old or new, never nothing
        self._fsync_dir(link.parent)

    def _switch(self, new_dir: str, prev_dir: str | None):
        if prev_dir:
            self._symlink(self.p.previous, prev_dir)
        self._symlink(self.p.current, new_dir)

    # activation, health, commit/rollback -----------------------------------
    def _phase_restart_health(self, job, version, old, backup):
        self._step(job, "restart", "running")
        try:
            self.env.restart_backend()
        except Exception as e:                                    # noqa: BLE001
            self._log(job, f"Neustart fehlgeschlagen: {e}")
        self._step(job, "restart", "done")
        self._step(job, "health", "running")
        ok, details = self._wait_health(version)
        self._log(job, f"Systemprüfung: {json.dumps(details, ensure_ascii=False)[:300]}")
        if ok:
            self._commit(job, version, old)
        else:
            failing = ", ".join(k for k, v in details.items() if v is not True)
            reason = "Systemprüfung fehlgeschlagen: " + (failing or "keine Antwort")
            self._rollback(job, old, backup, reason)

    def _wait_health(self, version):
        deadline = time.monotonic() + self.health_timeout
        details, stable = {}, 0
        while True:
            ok, details = self.env.health(version, self.p.db)
            stable = stable + 1 if ok else 0
            if stable >= 2:                    # two consecutive passes: not a crash-restart loop
                return True, details
            if time.monotonic() > deadline:
                return False, details
            time.sleep(self.health_interval)

    def _commit(self, job, version, old):
        job["pending"] = None
        job["state"] = "success"
        self._step(job, "health", "done")
        self._step(job, "done", "done", 100)
        self.store.add_history({"version": version, "from": old["version"], "result": "success"})
        cfg = self.store.config(); cfg.get("failed", {}).pop(version, None); self.store.save_config(cfg)
        cache = self.store.cache(); cache["available"] = None; self.store.save_cache(cache)
        shutil.rmtree(self.p.downloads / version, ignore_errors=True)
        self._prune_releases()
        self._log(job, f"Update auf {version} abgeschlossen")

    def _prune_releases(self):
        keep = {self.p.current.resolve().name}
        if self.p.previous.exists():
            keep.add(self.p.previous.resolve().name)
        others = sorted((d for d in self.p.releases.iterdir() if d.is_dir() and d.name not in keep and not d.name.startswith(".")),
                        key=lambda d: Version(d.name) if self._valid(d.name) else Version("0.0.0"), reverse=True)
        for d in others[max(0, KEEP_RELEASES - len(keep)):]:
            shutil.rmtree(d, ignore_errors=True)
        for d in self.p.releases.glob(".*.partial"):
            shutil.rmtree(d, ignore_errors=True)

    @staticmethod
    def _valid(name):
        try:
            Version(name); return True
        except ValueError:
            return False

    def _rollback(self, job, old, backup, reason):
        """Automatic application rollback after a failed update. Never loops: runs once, records the failure."""
        pend = job.get("pending") or {}
        job["state"] = "rolling_back"
        self._log(job, f"ROLLBACK auf {old['version']}: {reason}")
        failed_version = job["to"]
        try:
            self.env.stop_backend()
            self._switch(pend.get("from_dir") or old["dir"], None)
            self._maybe_restore_db(job, old, backup)
            self.env.start_backend()
            ok, details = self._wait_health(old["version"])
        except Exception as e:                                    # noqa: BLE001
            ok, details = False, {"exception": str(e)}
        job["pending"] = None
        if ok:
            job["state"], job["error"] = "rolled_back", reason
            self.store.add_history({"version": failed_version, "from": old["version"], "result": "rolled_back", "error": reason})
            self._log(job, f"Rollback erfolgreich, {old['version']} läuft wieder")
        else:
            job["state"], job["error"] = "failed_critical", reason + f" | Rollback ebenfalls fehlgeschlagen: {details}"
            self.store.add_history({"version": failed_version, "from": old["version"], "result": "failed_critical", "error": job["error"]})
            self._log(job, "Rollback fehlgeschlagen: manuelles Eingreifen nötig")
        self._mark_failed(failed_version, reason)
        self.store.save_job(job)

    def _maybe_restore_db(self, job, old, backup):
        """Restore the pre-update database only when the old release cannot use the current one."""
        have = db_user_version(self.p.db)
        need = old.get("db_schema") or 1
        corrupt = self.p.db.exists() and not db_quick_check(self.p.db)
        too_new = have is not None and have > need
        if (too_new or corrupt) and backup and (backup / "pios.db").exists():
            self._log(job, "Datenbank wird aus dem Backup wiederhergestellt " + ("(Schema zu neu)" if too_new else "(beschädigt)"))
            shutil.copy2(backup / "pios.db", self.p.db.with_name("pios.db.restore"))
            for ext in ("-wal", "-shm"):
                self.p.db.with_name("pios.db" + ext).unlink(missing_ok=True)
            os.replace(self.p.db.with_name("pios.db.restore"), self.p.db)
            try:
                st = self.p.data.stat()
                os.chown(self.p.db, st.st_uid, st.st_gid)
            except (PermissionError, OSError):
                pass
        elif too_new:
            raise UpdateError("Datenbank-Schema zu neu für die alte Version und kein Backup verfügbar")

    # ------------------------------------------------------------------ manual rollback
    def rollback(self, restore_backup=False):
        prev = self.previous_release()
        if not prev:
            raise UpdateError("Keine frühere Version vorhanden", "no_previous")
        if not self._mutex.acquire(blocking=False):
            raise UpdateError("Es läuft bereits ein Update", "busy")
        try:
            cur = self.installed()
            have = db_user_version(self.p.db)
            incompatible = have is not None and have > (prev["db_schema"] or 1)
            if incompatible and not restore_backup:
                raise UpdateError("Die Datenbank wurde von der neueren Version verändert. Ein Rollback ist nur mit "
                                  "Wiederherstellung des Backups möglich (neuere Notizen/Einstellungen gehen verloren). "
                                  "Dateien bleiben erhalten.", "db_incompatible")
            backup = None
            if restore_backup:
                cands = [b for b in sorted(self.p.backups.iterdir(), reverse=True)
                         if (b / "meta.json").exists() and json.loads((b / "meta.json").read_text())["from"] == prev["version"]]
                if not cands:
                    raise UpdateError("Kein passendes Backup vorhanden", "no_backup")
                backup = cands[0]
            job = self._new_job("rollback", cur["version"], prev["version"])
            self._step(job, "backup", "running")
            pre = self._make_backup(cur, label=f"{cur['version']}-before-rollback")
            self._step(job, "backup", "done")
            self._step(job, "install", "running")
            self.env.stop_backend()
            self._switch(prev["dir"], cur["dir"])
            if restore_backup:
                self._maybe_restore_db(job, prev, backup if incompatible else None)
            self._step(job, "install", "done")
            self._step(job, "restart", "running")
            self.env.start_backend()
            self._step(job, "restart", "done"); self._step(job, "health", "running")
            ok, details = self._wait_health(prev["version"])
            if ok:
                job["state"] = "success"; self._step(job, "health", "done"); self._step(job, "done", "done", 100)
                self.store.add_history({"version": prev["version"], "from": cur["version"], "result": "rollback_manual"})
            else:
                # go back to where we were
                self.env.stop_backend(); self._switch(cur["dir"], prev["dir"]); self.env.start_backend()
                job["state"], job["error"] = "failed", f"Rollback-Prüfung fehlgeschlagen: {details}"
                self.store.add_history({"version": prev["version"], "from": cur["version"], "result": "failed", "error": job["error"]})
            self.store.save_job(job)
            return self.status()
        finally:
            self._mutex.release()

    # ------------------------------------------------------------------ recovery after crash / power loss
    def recover(self):
        """Called once at service start. Brings a half-finished update to a consistent state."""
        job = self.store.job()
        if not job or job.get("state") not in ("running", "rolling_back"):
            return None
        self._mutex.acquire()
        try:
            self._log(job, f"Wiederherstellung nach Unterbrechung (Schritt {job['step']})")
            pend = job.get("pending") or {}
            cur = self.installed()
            backup = (self.p.backups / pend["backup"]) if pend.get("backup") and (self.p.backups / pend["backup"]).exists() else None
            old = {"version": job["from"], "dir": pend.get("from_dir") or job["from"], "db_schema": None}
            m = self._release_meta(self.p.releases / old["dir"]) if old["dir"] else None
            old["db_schema"] = (m or {}).get("db_schema", 1)
            switched = cur["version"] == job["to"] and job["kind"] == "update"
            if job["kind"] == "update" and not switched:
                # power loss before the atomic switch: nothing changed, just clean up
                shutil.rmtree(self.p.releases / f".{job['to']}.partial", ignore_errors=True)
                job["state"], job["error"] = "failed", "Update wurde unterbrochen; es wurde nichts verändert"
                self.store.add_history({"version": job["to"], "from": job["from"], "result": "failed", "error": job["error"]})
                self.store.save_job(job)
                return job
            if job["kind"] == "update":
                ok, details = self._wait_health(job["to"])
                if ok:
                    self._commit(job, job["to"], old)
                else:
                    self._rollback(job, old, backup, "Systemprüfung nach Unterbrechung fehlgeschlagen")
                return job
            job["state"] = "failed"; job["error"] = "Rollback wurde unterbrochen"   # manual rollback: leave to the user
            self.store.save_job(job)
            return job
        finally:
            self._mutex.release()
