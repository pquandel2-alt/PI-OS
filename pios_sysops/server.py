"""Unix-socket service. Verbs map to fixed systemd units; nothing the client sends is ever passed to a shell or used as a unit name."""
import json
import logging
import os
import pwd
import socket
import socketserver
import struct
import subprocess
from pathlib import Path

from . import osstatus

log = logging.getLogger("pios-sysops")
CLAMD = "clamav-daemon.service"
SIG_UPDATE = "pios-clam-update.service"
OS_CHECK = "pios-os-check.service"
OS_UPGRADE = "pios-os-upgrade.service"
OS_TIMER = "pios-os-upgrade.timer"
OS_CONF = Path(os.getenv("PIOS_OS_CONF", "/etc/pios/os-updates.conf"))


class OpError(Exception):
    def __init__(self, msg, code="error"):
        super().__init__(msg)
        self.code = code


class Systemctl:
    def __init__(self, binary="systemctl"):
        self.binary = binary

    def run(self, *args, timeout=30):
        r = subprocess.run([self.binary, *args], capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()

    def start(self, unit):
        rc, _o, e = self.run("start", "--no-block", unit)
        if rc != 0:
            raise OpError(f"{unit} konnte nicht gestartet werden: {e[:200]}")

    def stop(self, unit):
        rc, _o, e = self.run("stop", "--no-block", unit)
        if rc != 0:
            raise OpError(f"{unit} konnte nicht gestoppt werden: {e[:200]}")

    def show(self, unit, *props):
        rc, out, _e = self.run("show", unit, *[f"-p{p}" for p in props])
        return dict(l.split("=", 1) for l in out.splitlines() if "=" in l) if rc == 0 else {}


def rss_mb(pid) -> float | None:
    try:
        for line in Path(f"/proc/{int(pid)}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return round(int(line.split()[1]) / 1024, 1)
    except (OSError, ValueError):
        pass
    return None


class Ops:
    def __init__(self, ctl: Systemctl | None = None):
        self.ctl = ctl or Systemctl()

    def ping(self, a): return {"ok": True}

    def clamd_start(self, a):
        self.ctl.start(CLAMD); return {"ok": True}

    def clamd_stop(self, a):
        self.ctl.stop(CLAMD); return {"ok": True}

    def clamd_status(self, a):
        p = self.ctl.show(CLAMD, "ActiveState", "MainPID")
        pid = int(p.get("MainPID", "0") or 0)
        return {"active": p.get("ActiveState") == "active", "state": p.get("ActiveState", "unknown"), "pid": pid, "rss_mb": rss_mb(pid) if pid else None}

    def sig_update(self, a):
        if self.ctl.show(SIG_UPDATE, "ActiveState").get("ActiveState") in ("active", "activating"):
            raise OpError("Ein Signatur-Update läuft bereits", "busy")
        self.ctl.start(SIG_UPDATE); return {"ok": True}

    def sig_status(self, a):
        p = self.ctl.show(SIG_UPDATE, "ActiveState", "Result", "ExecMainExitTimestamp")
        return {"running": p.get("ActiveState") in ("active", "activating"), "result": p.get("Result", "unknown"), "last_exit": p.get("ExecMainExitTimestamp", "")}

    def os_check(self, a):
        self.ctl.start(OS_CHECK); return {"ok": True}

    def os_upgrade(self, a):
        self.ctl.start(OS_UPGRADE); return {"ok": True}

    def os_status(self, a):
        st = osstatus.read("os-status.json")
        up = osstatus.read("os-upgrade.json")
        auto = self.auto_security()
        return {"status": st, "last_upgrade": up, "auto_security": auto,
                "check_running": self.ctl.show(OS_CHECK, "ActiveState").get("ActiveState") in ("active", "activating"),
                "upgrade_running": self.ctl.show(OS_UPGRADE, "ActiveState").get("ActiveState") in ("active", "activating"),
                "reboot_required": os.path.exists("/run/reboot-required")}

    def auto_security(self) -> bool:
        try:
            return "AUTO_SECURITY=1" in OS_CONF.read_text()
        except OSError:
            return True                      # default: automatic Debian security updates on

    def os_config(self, a):
        flag = a.get("auto_security")
        if not isinstance(flag, bool):
            raise OpError("auto_security muss true/false sein", "bad_request")
        OS_CONF.parent.mkdir(parents=True, exist_ok=True)
        OS_CONF.write_text(f"AUTO_SECURITY={'1' if flag else '0'}\n")
        rc, _o, e = self.ctl.run("enable" if flag else "disable", "--now", OS_TIMER)
        if rc != 0:
            raise OpError(f"Timer konnte nicht geändert werden: {e[:200]}")
        return {"auto_security": flag}

    METHODS = {"ping": ping, "clamd.start": clamd_start, "clamd.stop": clamd_stop, "clamd.status": clamd_status, "signatures.update": sig_update,
               "signatures.status": sig_status, "os.check": os_check, "os.upgrade": os_upgrade, "os.status": os_status, "os.config": os_config}

    def dispatch(self, method, args):
        fn = self.METHODS.get(method)
        if not fn:
            raise OpError("Unbekannte Methode", "bad_request")
        return fn(self, args)


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        _pid, uid, _gid = struct.unpack("3i", self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        if uid not in self.server.allowed_uids:
            return self._send({"ok": False, "error": "Zugriff verweigert", "code": "forbidden"})
        try:
            req = json.loads(self.rfile.readline(16385))
            method, args = req["method"], req.get("args", {})
            assert isinstance(args, dict) and isinstance(method, str)
        except (ValueError, KeyError, AssertionError, TypeError):
            return self._send({"ok": False, "error": "Ungültige Anfrage", "code": "bad_request"})
        try:
            self._send({"ok": True, "result": self.server.ops.dispatch(method, args)})
        except OpError as e:
            self._send({"ok": False, "error": str(e), "code": e.code})
        except Exception as e:                                                   # noqa: BLE001
            log.exception("request failed")
            self._send({"ok": False, "error": f"Interner Fehler: {e}", "code": "internal"})

    def _send(self, obj):
        self.wfile.write((json.dumps(obj) + "\n").encode())


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, path, ops, allowed_uids):
        self.ops, self.allowed_uids = ops, set(allowed_uids)
        Path(path).unlink(missing_ok=True)
        super().__init__(str(path), Handler)


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    sock = Path(os.getenv("PIOS_SYSOPS_SOCKET", "/run/pios-sysops/sysops.sock"))
    uids = {0}
    try:
        uids.add(pwd.getpwnam("pios").pw_uid)
    except KeyError:
        pass
    srv = Server(sock, Ops(), uids)
    os.chmod(sock, 0o660)
    srv.serve_forever()


if __name__ == "__main__":
    main()
