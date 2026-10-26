"""Client for the PiOS system-operations helper (pios_sysops): start/stop ClamAV, refresh signatures, OS update checks.
The helper runs as root, but only triggers a fixed whitelist of systemd units and reads status files."""
import json
import os
import socket


class Unavailable(Exception):
    pass


class OpError(Exception):
    def __init__(self, msg, code="error"):
        super().__init__(msg)
        self.code = code


def socket_path() -> str:
    return os.getenv("PIOS_SYSOPS_SOCKET", "/run/pios-sysops/sysops.sock")


def call(method: str, args: dict | None = None, timeout: float = 30.0):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(socket_path())
            s.sendall((json.dumps({"method": method, "args": args or {}}) + "\n").encode())
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > 1_000_000:
                    raise Unavailable("Antwort zu groß")
        resp = json.loads(buf)
    except (OSError, ValueError) as e:
        raise Unavailable(str(e)) from None
    if not resp.get("ok"):
        raise OpError(resp.get("error", "Fehler"), resp.get("code", "error"))
    return resp["result"]


def available() -> bool:
    try:
        call("ping", timeout=3)
        return True
    except (Unavailable, OpError):
        return False
