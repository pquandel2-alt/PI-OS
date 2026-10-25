"""Sessions, password hashing, brute-force protection, request guards."""
import hashlib
import hmac
import ipaddress
import json
import secrets
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request

from . import config
from .db import connect

hasher = PasswordHasher()
# Verified against when a user does not exist, so timing does not leak usernames.
_DUMMY = hasher.hash("pios-dummy-password")
COOKIE = "pios_session"


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def is_loopback(request: Request) -> bool:
    try:
        return ipaddress.ip_address(client_ip(request)).is_loopback
    except ValueError:
        return False


def client_kind(request: Request) -> str:
    """'local' for the HDMI kiosk (loopback), 'remote' for browsers on the LAN."""
    return "local" if is_loopback(request) else "remote"


# ---- passwords -------------------------------------------------------------
def verify_password(stored: str | None, password: str) -> bool:
    try:
        hasher.verify(stored or _DUMMY, password)
        return stored is not None
    except (VerifyMismatchError, VerificationError, ValueError):  # ValueError covers InvalidHash(Error) in all versions
        return False


# ---- brute-force protection -----------------------------------------------
def _keys(request: Request, username: str):
    return (f"ip:{client_ip(request)}", f"user:{username.lower()}")


def check_lock(request: Request, username: str):
    now = int(time.time())
    with connect() as c:
        for k in _keys(request, username):
            r = c.execute("SELECT locked_until FROM login_failures WHERE key=?", (k,)).fetchone()
            if r and r["locked_until"] > now:
                raise HTTPException(429, f"Zu viele Versuche. Bitte in {r['locked_until'] - now} s erneut versuchen.",
                                    headers={"Retry-After": str(r["locked_until"] - now)})


def register_failure(request: Request, username: str):
    now = int(time.time())
    with connect() as c:
        for k in _keys(request, username):
            r = c.execute("SELECT count FROM login_failures WHERE key=?", (k,)).fetchone()
            count = (r["count"] if r else 0) + 1
            over = count - config.LOGIN_MAX_FAILURES
            lock = min(config.LOGIN_LOCK_BASE * 2 ** over, config.LOGIN_LOCK_MAX) if over >= 0 else 0
            c.execute("INSERT INTO login_failures VALUES(?,?,?,?) ON CONFLICT(key) DO UPDATE SET "
                      "count=excluded.count, locked_until=excluded.locked_until, updated=excluded.updated",
                      (k, count, now + lock if lock else 0, now))


def clear_failures(request: Request, username: str):
    with connect() as c:
        c.execute("DELETE FROM login_failures WHERE key IN (?,?)", _keys(request, username))
        c.execute("DELETE FROM login_failures WHERE updated<?", (int(time.time()) - 86400,))


# ---- sessions ---------------------------------------------------------------
def create_session(uid: int, request: Request) -> str:
    token = secrets.token_urlsafe(48)
    now = int(time.time())
    with connect() as c:
        c.execute("DELETE FROM sessions WHERE expires<?", (now,))
        c.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?,?)",
                  (token_hash(token), uid, now, now + config.SESSION_TTL, now, client_kind(request),
                   request.headers.get("user-agent", "")[:200]))
    return token


def _session_row(request: Request):
    token = request.cookies.get(COOKIE, "")
    if not token:
        return None
    now = int(time.time())
    with connect() as c:
        r = c.execute("SELECT u.id,u.username,u.role,s.hash,s.kind FROM sessions s JOIN users u ON u.id=s.uid "
                      "WHERE s.hash=? AND s.expires>?", (token_hash(token), now)).fetchone()
        if r:
            c.execute("UPDATE sessions SET last_seen=? WHERE hash=?", (now, r["hash"]))
    return r


def current_user(request: Request) -> dict:
    r = _session_row(request)
    if not r:
        raise HTTPException(401, "Bitte anmelden")
    return {"id": r["id"], "username": r["username"], "role": r["role"], "session": r["hash"], "kind": r["kind"]}


def admin_user(u: dict = Depends(current_user)) -> dict:
    if u["role"] != "admin":
        raise HTTPException(403, "Administratorrechte erforderlich")
    return u


def csrf_guard(request: Request):
    """State-changing browser requests must carry a custom header and a matching Origin.

    A cross-site page cannot set X-PiOS without a CORS preflight (which we never allow).
    """
    if request.method in ("POST", "PUT", "PATCH", "DELETE") and request.url.path.startswith("/api/"):
        if request.headers.get("x-pios") != "1":
            raise HTTPException(403, "Ungültige Anfrage")
        origin = request.headers.get("origin")
        if origin and origin.split("://", 1)[-1] != request.headers.get("host"):
            raise HTTPException(403, "Origin nicht erlaubt")


# ---- app capability tokens --------------------------------------------------
def _secret() -> bytes:
    p = config.DATA / "secret.key"
    if not p.exists():
        p.write_bytes(secrets.token_bytes(32))
        p.chmod(0o600)
    return p.read_bytes()


def issue_app_token(app_id: str, uid: int, perms: list[str], ttl: int = 3600) -> str:
    body = urlsafe_b64encode(json.dumps({"a": app_id, "u": uid, "p": perms, "e": int(time.time()) + ttl},
                                        separators=(",", ":")).encode()).decode().rstrip("=")
    sig = hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def read_app_token(request: Request) -> dict:
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    try:
        body, sig = token.rsplit(".", 1)
        good = hmac.compare_digest(sig, hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest())
        d = json.loads(urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except Exception:
        raise HTTPException(401, "Ungültiges App-Token") from None
    if not good or d["e"] < time.time():
        raise HTTPException(401, "Ungültiges App-Token")
    return {"app": d["a"], "uid": d["u"], "perms": set(d["p"])}
