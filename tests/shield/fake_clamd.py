"""A clamd stand-in that speaks the real protocol (zPING, zVERSION, zFILDES with SCM_RIGHTS). Detects the EICAR test string."""
import os
import socket
import threading
from pathlib import Path

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class FakeClamd:
    def __init__(self, path: Path):
        self.path = str(path)
        self.mode = "ok"                 # ok | error | hangup
        self.scans = 0
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        Path(self.path).unlink(missing_ok=True)
        self.sock.bind(self.path)
        self.sock.listen(8)
        self.alive = True
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while self.alive:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        with conn:
            cmd = b""
            while not cmd.endswith(b"\0"):
                c = conn.recv(1)
                if not c:
                    return
                cmd += c
            cmd = cmd.rstrip(b"\0")
            if cmd == b"zPING" or cmd == b"PING":
                conn.sendall(b"PONG\0")
            elif cmd in (b"zVERSION", b"VERSION"):
                conn.sendall(b"ClamAV 1.4.3-fake/27800/Mon Oct 26 05:00:00 2026\0")
            elif cmd in (b"zFILDES", b"FILDES"):
                msg, fds, _f, _a = socket.recv_fds(conn, 1, 1)
                self.scans += 1
                if self.mode == "hangup":
                    return
                if self.mode == "error":
                    conn.sendall(b"fd[%d]: Can't open file or directory ERROR\0" % fds[0]); os.close(fds[0]); return
                with os.fdopen(fds[0], "rb") as f:
                    data = f.read()
                if EICAR in data:
                    conn.sendall(b"fd[%d]: Win.Test.EICAR_HDB-1 FOUND\0" % 7)
                else:
                    conn.sendall(b"fd[7]: OK\0")

    def stop(self):
        self.alive = False
        self.sock.close()
        Path(self.path).unlink(missing_ok=True)
