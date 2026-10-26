"""Unix-socket service for the firewall. Only root and the `pios` backend user may connect; only five verbs exist."""
import json
import logging
import os
import pwd
import socket
import socketserver
import struct
import threading
from pathlib import Path

from .engine import Firewall, FirewallError, Nft
from .ruleset import ConfigError

log = logging.getLogger("pios-firewall")
MAX_REQ = 16 * 1024


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        srv = self.server
        _pid, uid, _gid = struct.unpack("3i", self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        if uid not in srv.allowed_uids:
            log.warning("refused connection from uid %s", uid)
            return self._send({"ok": False, "error": "Zugriff verweigert", "code": "forbidden"})
        try:
            req = json.loads(self.rfile.readline(MAX_REQ + 1))
            method, args = req["method"], req.get("args", {})
            assert isinstance(args, dict) and method in ("status", "preview", "apply", "confirm", "revert")
        except (ValueError, KeyError, AssertionError, TypeError):
            return self._send({"ok": False, "error": "Ungültige Anfrage", "code": "bad_request"})
        fw = srv.fw
        try:
            if method == "status":
                res = fw.status()
            elif method == "preview":
                res = fw.preview(args.get("config", {}))
            elif method == "apply":
                log.warning("apply requested by uid %s", uid)
                res = fw.apply(args.get("config", {}))
            elif method == "confirm":
                res = fw.confirm()
            else:
                res = fw.revert()
            self._send({"ok": True, "result": res})
        except (ConfigError, FirewallError) as e:
            self._send({"ok": False, "error": str(e), "code": getattr(e, "code", "invalid_config")})
        except Exception as e:                                                   # noqa: BLE001
            log.exception("request failed")
            self._send({"ok": False, "error": f"Interner Fehler: {e}", "code": "internal"})

    def _send(self, obj):
        self.wfile.write((json.dumps(obj) + "\n").encode())


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, path, fw: Firewall, allowed_uids):
        self.fw, self.allowed_uids = fw, set(allowed_uids)
        Path(path).unlink(missing_ok=True)
        super().__init__(str(path), Handler)


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    state = Path(os.getenv("PIOS_FIREWALL_STATE", "/var/lib/pios-firewall"))
    sock = Path(os.getenv("PIOS_FIREWALL_SOCKET", "/run/pios-firewall/firewall.sock"))
    fw = Firewall(Nft(), state)
    try:
        fw.boot()
    except FirewallError as e:                  # keep serving: the UI must be able to show "not protected"
        log.error("boot: %s", e)
    uids = {0}
    try:
        uids.add(pwd.getpwnam("pios").pw_uid)
    except KeyError:
        pass
    srv = Server(sock, fw, uids)
    os.chmod(sock, 0o660)

    def maintenance():
        stop = threading.Event()
        while not stop.wait(120):
            try:
                fw.maintain()
            except Exception:                                                    # noqa: BLE001
                log.exception("maintenance failed")
    threading.Thread(target=maintenance, daemon=True).start()
    srv.serve_forever()


if __name__ == "__main__":
    main()
