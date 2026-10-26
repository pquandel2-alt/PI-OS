"""Protection against locking yourself out: a change that could cut the admin's own connection is applied provisionally and rolled back
automatically unless it is confirmed from the new connection within the time limit. The rollback data is persisted, so a crash or
power cycle during the window also rolls back (on the next start)."""
import ipaddress
import json
import logging
import os
import subprocess
import threading
import time
from pathlib import Path

from . import validate
from .ipc import OpError

log = logging.getLogger("pios-connd.guard")
CONFIRM_SECONDS = 60


def run(cmd, timeout=8):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except FileNotFoundError:
        return 127, ""
    except subprocess.TimeoutExpired:
        return 124, ""


class Guard:
    def __init__(self, nm, state_dir: Path, runner=run, confirm_seconds=CONFIRM_SECONDS, events=None):
        self.nm, self.runner, self.confirm_seconds = nm, runner, confirm_seconds
        self.events = events or (lambda *a, **k: None)
        self.path = Path(state_dir) / "pending.json"
        Path(state_dir).mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = threading.RLock()
        self._pending = None
        self._timer = None

    # ---- which interface carries the admin's session? -----------------------------------------------------------
    def admin_iface(self, client_ip) -> str | None:
        """The interface the kernel would use to answer `client_ip`. None for the local kiosk (loopback) or when unknown."""
        if not client_ip:
            return None
        try:
            ip = ipaddress.ip_address(str(client_ip))
        except ValueError:
            raise validate.InvalidInput("Ungültige Client-Adresse") from None
        if ip.is_loopback:
            return None
        rc, out = self.runner(["ip", "-j", "route", "get", str(ip)])
        if rc != 0:
            return None
        try:
            dev = json.loads(out)[0].get("dev")
        except (ValueError, IndexError, AttributeError):
            return None
        return dev if dev and validate.IFACE.match(dev) else None

    # ---- pending change --------------------------------------------------------------------------------------------
    def pending(self) -> dict | None:
        with self.lock:
            if not self._pending:
                return None
            p = self._pending
            return {"kind": p["kind"], "description": p["description"], "iface": p["iface"], "op": p.get("op"), "seconds_left": max(0, round(p["deadline"] - time.time())),
                    "confirm_seconds": self.confirm_seconds}

    def begin(self, kind: str, description: str, iface: str, undo: dict, op: str | None = None):
        with self.lock:
            if self._pending:
                raise OpError("Eine Netzwerkänderung wartet noch auf Bestätigung. Bestätige oder verwirf sie zuerst.", "pending")
            self._pending = {"kind": kind, "description": description, "iface": iface, "undo": undo, "op": op, "deadline": time.time() + self.confirm_seconds}
            self._save()
            self._timer = threading.Timer(self.confirm_seconds, self._expire)
            self._timer.daemon = True
            self._timer.start()
        self.events("net.change_pending", severity="warning", description=description, iface=iface)

    def _save(self):
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self._pending, f)
        os.replace(tmp, self.path)

    def confirm(self):
        with self.lock:
            if not self._pending:
                raise OpError("Keine Netzwerkänderung zu bestätigen.", "nothing_pending")
            if self._timer:
                self._timer.cancel()
            desc = self._pending["description"]
            self._pending = None
            self.path.unlink(missing_ok=True)
        self.events("net.change_confirmed", description=desc)
        return {"confirmed": True}

    def revert(self, reason="manuell"):
        with self.lock:
            p = self._pending
            if not p:
                raise OpError("Keine Netzwerkänderung zum Zurücksetzen.", "nothing_pending")
            if self._timer:
                self._timer.cancel()
            self._pending = None
            self.path.unlink(missing_ok=True)
        self._undo(p["undo"])
        self.events("net.change_reverted", severity="warning", description=p["description"], reason=reason)
        return {"reverted": True, "reason": reason}

    def _expire(self):
        try:
            if self._pending:
                self.revert("nicht bestätigt (Zeit abgelaufen)")
        except OpError:
            pass

    def revert_if_op(self, op: str, reason: str) -> bool:
        with self.lock:
            if not self._pending or self._pending.get("op") != op:
                return False
        self.revert(reason)
        return True

    def recover(self):
        """After a crash/power cycle during the confirmation window: the change was never confirmed, so undo it now."""
        try:
            p = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return False
        self._undo(p.get("undo", {}))
        self.path.unlink(missing_ok=True)
        self.events("net.change_reverted", severity="warning", description=p.get("description", ""), reason="Neustart während der Bestätigungsfrist")
        return True

    def _undo(self, undo: dict):
        """Best effort, every step independent: a failing step must not stop the others."""
        steps = []
        if undo.get("wifi_enabled") is True:
            steps.append(lambda: self.nm.set_wifi_enabled(True))
        for u in undo.get("delete_uuids", []):
            steps.append(lambda u=u: self.nm.delete_connection(u))
        if undo.get("ipv4"):
            steps.append(lambda: self.nm.restore_ipv4(undo["ipv4"]["uuid"], undo["ipv4"].get("previous")))
        if undo.get("activate"):
            a = undo["activate"]
            steps.append(lambda: self.nm.activate(a["uuid"], a.get("iface")))
        for st in steps:
            try:
                st()
            except Exception as e:                                               # noqa: BLE001
                log.warning("rollback step failed: %s", e)
