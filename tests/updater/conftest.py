"""Harness: synthetic releases, a mock GitHub API on localhost, and a fake system (services + health)."""
import hashlib
import http.server
import json
import os
import sqlite3
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from pios_updater import crypto, package                       # noqa: E402
from pios_updater.engine import Env, Paths, Updater            # noqa: E402
from pios_updater.source import GitHubSource                   # noqa: E402


def make_tree(base: Path, version: str, schema=1, extra=None, broken_py=False):
    for f, content in {"pios/__init__.py": f'__version__ = "{version}"\n', "pios/main.py": "def app(): pass\n" if not broken_py else "def (:\n",
                       "web/index.html": "<title>PiOS NOVA</title>", "web/js/main.js": "//", "apps/x/manifest.json": "{}"}.items():
        p = base / f
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    (base / "image/overlay/opt/pios/bin").mkdir(parents=True, exist_ok=True)
    (base / "image/overlay/opt/pios/bin/pios-wait-ready").write_text("#!/bin/sh\n")
    for f, content in (extra or {}).items():
        p = base / f; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(content)


class FakeEnv(Env):
    """Pretends to be systemd + the backend. `behaviour` decides what a freshly started version does."""
    def __init__(self, paths: Paths):
        self.paths, self.bad_versions, self.crash_versions, self.free = paths, set(), set(), 10 ** 12
        self.restarts, self.running, self.migrate_to = [], True, {}
        self.codename, self._arch = "trixie", "arm64"
        self.fail_restart = False
        self.booted = "0.1.0"

    def _cur(self):
        return json.loads((self.paths.current / "release.json").read_text())

    def _boot(self):
        """Simulate the backend starting: new versions may migrate the DB schema."""
        v = self._cur()["version"]
        self.restarts.append(v)
        self.booted = v
        target = self.migrate_to.get(v)
        if target and self.paths.db.exists():
            c = sqlite3.connect(self.paths.db); c.execute(f"PRAGMA user_version={target}"); c.commit(); c.close()
        # backend refuses to start with a newer DB schema than it knows (as pios.db does)
        have = sqlite3.connect(self.paths.db).execute("PRAGMA user_version").fetchone()[0] if self.paths.db.exists() else 0
        self.running = v not in self.crash_versions and have <= self._cur()["db_schema"]

    def restart_backend(self):
        if self.fail_restart:
            raise RuntimeError("systemctl failed")
        self._boot()

    def stop_backend(self): self.running = False
    def start_backend(self): self._boot()

    def health(self, target_version, db_path):
        v = self._cur()["version"]
        d = {"service_active": self.running, "health_api": self.running, "version_active": self.running and self.booted == target_version and v not in self.bad_versions,
             "database": True, "assets": self.running}
        return all(d.values()), d

    def os_codename(self): return self.codename
    def arch(self): return self._arch
    def free_bytes(self, path): return self.free


class MockGitHub:
    """Serves /repos/<r>/releases and release assets, with Range support and optional connection drops."""
    def __init__(self):
        self.releases, self.files, self.drop_after, self.fail_status, self.hits, self.drop_name = [], {}, None, None, 0, ".tar.zst"
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def do_GET(self):
                outer.hits += 1
                if outer.fail_status:
                    self.send_response(outer.fail_status); self.send_header("Content-Length", "0")
                    if outer.fail_status == 403:
                        self.send_header("x-ratelimit-reset", str(int(__import__("time").time()) + 600))
                    self.end_headers(); return
                if self.path.startswith("/repos/"):
                    body = json.dumps(outer.releases).encode()
                    etag = '"' + hashlib.md5(body).hexdigest() + '"'
                    if self.headers.get("If-None-Match") == etag:
                        self.send_response(304); self.end_headers(); return
                    self.send_response(200); self.send_header("ETag", etag); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body); return
                name = self.path.rsplit("/", 1)[-1]
                data = outer.files.get(name)
                if data is None:
                    self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers(); return
                start = 0
                if self.headers.get("Range"):
                    start = int(self.headers["Range"].split("=")[1].split("-")[0]); self.send_response(206)
                else:
                    self.send_response(200)
                chunk = data[start:]
                self.send_header("Content-Length", str(len(chunk))); self.end_headers()
                if outer.drop_after is not None and name.endswith(outer.drop_name) and len(chunk) > outer.drop_after:
                    self.wfile.write(chunk[:outer.drop_after]); self.wfile.flush(); outer.drop_after = None
                    self.connection.shutdown(2); return
                self.wfile.write(chunk)

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.base = f"http://127.0.0.1:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def publish(self, key_seed, version, channel="stable", schema=1, min_version="0.1.0", codename="trixie", tmp: Path = None,
                tamper=None, sign=True, prerelease=None, broken_py=False, notes="- Neu", extra=None):
        src = tmp / f"src-{version}"
        make_tree(src, version, schema, extra, broken_py)
        out = tmp / f"PiOS-NOVA-update-{version}.tar.zst"
        info = package.build(src, out, {"version": version, "db_schema": schema, "api": 1})
        manifest = {"format": 1, "version": version, "channel": channel, "released": "2026-10-26T10:00:00Z", "min_version": min_version,
                    "db_schema": schema, "api": 1, "os_codename": codename, "arch": "arm64", "notes": notes, "highlights": ["x"],
                    "package": {"file": out.name, "size": info["size"], "sha256": info["sha256"], "unpacked_size": info["unpacked_size"]}}
        raw = json.dumps(manifest, sort_keys=True).encode()
        sig = crypto.sign(raw, key_seed) if sign else "AAAA"
        pkg = out.read_bytes()
        if tamper == "package":
            pkg = pkg[:-5] + b"XXXXX"
        if tamper == "manifest":
            raw = raw.replace(b'"stable"', b'"beta"') if channel == "stable" else raw.replace(b'"beta"', b'"stable"')
        tag = "v" + version
        names = {out.name: pkg, f"PiOS-NOVA-update-{version}.manifest.json": raw, f"PiOS-NOVA-update-{version}.manifest.json.sig": sig.encode()}
        self.files.update(names)
        self.releases.insert(0, {"tag_name": tag, "draft": False, "prerelease": version_is_pre(version) if prerelease is None else prerelease,
                                 "published_at": "2026-10-26T10:00:00Z",
                                 "assets": [{"name": n, "size": len(b), "state": "uploaded", "browser_download_url": f"{self.base}/dl/{tag}/{n}"} for n, b in names.items()]})
        return manifest


def version_is_pre(v): return "-" in v


@pytest.fixture()
def keypair():
    seed, pub = crypto.generate_keypair()
    return seed, pub


@pytest.fixture()
def gh():
    g = MockGitHub()
    yield g
    g.srv.shutdown()


class Sys:
    pass


@pytest.fixture()
def system(tmp_path, keypair, gh):
    """An installed 0.1.0 system layout plus an Updater wired to the mock GitHub."""
    seed, pub = keypair
    root, state, data, keys = tmp_path / "opt", tmp_path / "state", tmp_path / "data", tmp_path / "keys"
    for d in (root / "releases", data, keys):
        d.mkdir(parents=True)
    (keys / "release.pub").write_text(pub + "\n")
    rel = root / "releases" / "0.1.0"
    make_tree(rel, "0.1.0")
    (rel / "release.json").write_text(json.dumps({"version": "0.1.0", "db_schema": 1, "api": 1}))
    os.symlink("releases/0.1.0", root / "current")
    c = sqlite3.connect(data / "pios.db"); c.execute("CREATE TABLE notes(id INTEGER PRIMARY KEY, body TEXT)")
    c.execute("INSERT INTO notes(body) VALUES('wichtig')"); c.execute("PRAGMA user_version=1"); c.commit(); c.close()
    (data / "secret.key").write_bytes(b"k" * 32)
    (data / "files" / "1").mkdir(parents=True); (data / "files" / "1" / "foto.jpg").write_bytes(b"JPEGDATA")
    paths = Paths(root=root, state=state, data=data, keys=keys, conf=tmp_path / "etc")
    env = FakeEnv(paths)
    u = Updater(paths, GitHubSource("x/y", api_base=gh.base, allow_insecure=True), env, health_timeout=2, health_interval=0.05, async_jobs=False)
    s = Sys(); s.u, s.env, s.paths, s.seed, s.gh, s.tmp = u, env, paths, seed, gh, tmp_path
    s.publish = lambda version, **kw: gh.publish(seed, version, tmp=tmp_path, **kw)
    return s
