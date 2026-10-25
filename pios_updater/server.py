"""Unix-socket service: `python3 -m pios_updater.server`. Only the pios backend (and root) may talk to it."""
import json
import logging
import os
import pwd
import random
import socket
import socketserver
import struct
import threading
import time
from pathlib import Path

from .engine import Paths, UpdateError, Updater
from .source import GitHubSource
from .system import SystemEnv

log = logging.getLogger("pios-updater")
MAX_REQ = 64 * 1024
CHECK_INTERVAL = 24 * 3600


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        srv = self.server
        creds = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", creds)
        if uid not in srv.allowed_uids:
            return self._send({"ok": False, "error": "Zugriff verweigert", "code": "forbidden"})
        line = self.rfile.readline(MAX_REQ + 1)
        try:
            req = json.loads(line)
            method, args = req["method"], req.get("args", {})
            assert isinstance(args, dict)
        except (ValueError, KeyError, AssertionError):
            return self._send({"ok": False, "error": "Ungültige Anfrage", "code": "bad_request"})
        try:
            self._send({"ok": True, "result": srv.dispatch(method, args)})
        except UpdateError as e:
            self._send({"ok": False, "error": str(e), "code": e.code})
        except Exception as e:                                                   # noqa: BLE001
            log.exception("request %s failed", method)
            self._send({"ok": False, "error": f"Interner Fehler: {e}", "code": "internal"})

    def _send(self, obj):
        self.wfile.write((json.dumps(obj) + "\n").encode())


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, path, updater: Updater, allowed_uids):
        self.updater, self.allowed_uids = updater, set(allowed_uids)
        Path(path).unlink(missing_ok=True)
        super().__init__(str(path), Handler)

    def dispatch(self, method, a):
        u = self.updater
        if method == "status":
            return u.status()
        if method == "check":
            return u.check(force=bool(a.get("force")))
        if method == "install":
            return u.install(str(a.get("version", "")))
        if method == "cancel":
            return {"cancelled": u.cancel()}
        if method == "rollback":
            return u.rollback(restore_backup=bool(a.get("restore_backup")))
        if method == "config":
            return u.set_config(channel=a.get("channel"), auto_check=a.get("auto_check"))
        if method == "snooze":
            u.snooze(str(a["version"]), float(a.get("hours", 24)))
            return u.status()
        raise UpdateError("Unbekannte Methode", "bad_request")


def scheduler(updater: Updater, stop: threading.Event):
    """Daily check (with jitter), backing off after errors; never blocks or breaks normal operation."""
    stop.wait(random.uniform(120, 300))
    while not stop.is_set():
        try:
            cfg, cache = updater.store.config(), updater.store.cache()
            now = time.time()
            due = now - cache.get("success_at", 0) >= CHECK_INTERVAL and now - cache.get("checked_at", 0) >= 3600
            if cfg["auto_check"] and due and not updater._mutex.locked():
                updater.check()
        except Exception:                                                        # noqa: BLE001
            log.exception("scheduled check failed")
        stop.wait(600)


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    paths = Paths(root=Path(os.getenv("PIOS_ROOT", "/opt/pios")), state=Path(os.getenv("PIOS_UPDATER_STATE", "/var/lib/pios-updater")),
                  data=Path(os.getenv("PIOS_DATA", "/var/lib/pios")), keys=Path(os.getenv("PIOS_UPDATE_KEYS", "/usr/share/pios/update-keys")))
    sock = Path(os.getenv("PIOS_UPDATER_SOCKET", "/run/pios-updater/updater.sock"))
    updater = Updater(paths, GitHubSource(os.getenv("PIOS_UPDATE_REPO", "pquandel2-alt/PI-OS")), SystemEnv())
    uids = {0}
    try:
        uids.add(pwd.getpwnam("pios").pw_uid)
    except KeyError:
        log.warning("user 'pios' not found")
    log.info("PiOS updater started; installed=%s keys=%d", updater.installed()["version"], len(updater.keys))
    srv = Server(sock, updater, uids)
    os.chmod(sock, 0o660)
    stop = threading.Event()
    threading.Thread(target=lambda: (updater.recover(), scheduler(updater, stop)), daemon=True, name="recover+scheduler").start()
    try:
        srv.serve_forever()
    finally:
        stop.set()


if __name__ == "__main__":
    main()
