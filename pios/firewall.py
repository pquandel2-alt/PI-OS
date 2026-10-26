"""Client for the PiOS firewall service (pios_firewall). The backend can only ask it to validate/apply/confirm/revert a
small structured policy; it never sends nftables text and has no capability of its own."""
import json
import os
import socket


class Unavailable(Exception):
    pass


class FwError(Exception):
    def __init__(self, msg, code="error"):
        super().__init__(msg)
        self.code = code


def socket_path() -> str:
    return os.getenv("PIOS_FIREWALL_SOCKET", "/run/pios-firewall/firewall.sock")


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
        raise FwError(resp.get("error", "Fehler"), resp.get("code", "error"))
    return resp["result"]
