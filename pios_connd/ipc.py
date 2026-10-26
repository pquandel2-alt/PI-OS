"""Unix-socket server shared by the connectivity daemon: JSON lines, SO_PEERCRED uid allow-list, fixed verb table."""
import json
import logging
import socket
import socketserver
import struct
from pathlib import Path

log = logging.getLogger("pios-connd")
MAX_REQ = 16 * 1024


class OpError(Exception):
    def __init__(self, msg, code="error"):
        super().__init__(msg)
        self.code = code


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        _pid, uid, _gid = struct.unpack("3i", self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        if uid not in self.server.allowed_uids:
            log.warning("refused connection from uid %s", uid)
            return self._send({"ok": False, "error": "Zugriff verweigert", "code": "forbidden"})
        try:
            req = json.loads(self.rfile.readline(MAX_REQ + 1))
            method, args = req["method"], req.get("args", {})
            assert isinstance(method, str) and isinstance(args, dict)
        except (ValueError, KeyError, AssertionError, TypeError):
            return self._send({"ok": False, "error": "Ungültige Anfrage", "code": "bad_request"})
        fn = self.server.verbs.get(method)
        if not fn:
            return self._send({"ok": False, "error": "Unbekannte Methode", "code": "bad_request"})
        try:
            self._send({"ok": True, "result": fn(args)})
        except OpError as e:
            self._send({"ok": False, "error": str(e), "code": e.code})
        except ValueError as e:                       # validation errors (InvalidInput is a ValueError)
            self._send({"ok": False, "error": str(e), "code": "invalid_input"})
        except Exception as e:                        # noqa: BLE001  (never leak internals or secrets)
            log.exception("verb %s failed", method)
            self._send({"ok": False, "error": "Interner Fehler im Verbindungsdienst", "code": "internal"})

    def _send(self, obj):
        self.wfile.write((json.dumps(obj) + "\n").encode())


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, path, verbs: dict, allowed_uids):
        self.verbs, self.allowed_uids = verbs, set(allowed_uids)
        Path(path).unlink(missing_ok=True)
        super().__init__(str(path), Handler)
