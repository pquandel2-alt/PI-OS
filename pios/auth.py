"""Setup wizard, login/logout, account and session management."""
import hmac
import re
import secrets
import shutil
import time

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator

from . import audit, config, db, security
from .security import admin_user, current_user

router = APIRouter(prefix="/api")
USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,39}$")
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def _validate_username(v: str) -> str:
    if not USERNAME.match(v):
        raise ValueError("3–40 Zeichen: Buchstaben, Ziffern, . _ -")
    return v


class Credentials(BaseModel):
    username: str
    password: str = Field(min_length=1, max_length=256)

    _u = field_validator("username")(_validate_username)


class Setup(Credentials):
    password: str = Field(min_length=12, max_length=256)
    setup_code: str = Field(default="", max_length=32)


class NewUser(Credentials):
    password: str = Field(min_length=12, max_length=256)
    role: str = Field(default="user", pattern="^(user|admin)$")


class PasswordChange(BaseModel):
    current: str = Field(max_length=256)
    new: str = Field(min_length=12, max_length=256)


# ---- first-run setup code ----------------------------------------------------
def _code_path():
    return config.DATA / "setup-code"


def _done_path():
    return config.DATA / "setup-complete"


def ensure_setup_code():
    """Create the first-boot setup code unless an admin already exists."""
    with db.connect() as c:
        if c.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            return
    p = _code_path()
    if not p.exists():
        p.write_text("".join(secrets.choice(_ALPHABET) for _ in range(8)) + "\n")
        p.chmod(0o600)
        print(f"[pios] Setup-Code für die Ersteinrichtung: {p.read_text().strip()}", flush=True)


def _code_ok(request: Request, given: str) -> bool:
    if security.is_loopback(request):  # physical access on the HDMI screen
        return True
    try:
        want = _code_path().read_text().strip()
    except OSError:
        return False
    return bool(want) and hmac.compare_digest(want.upper(), given.strip().upper().replace("-", ""))


@router.get("/setup-status")
def setup_status(request: Request):
    with db.connect() as c:
        needs = c.execute("SELECT 1 FROM users LIMIT 1").fetchone() is None
    return {"needs_setup": needs, "needs_code": needs and not security.is_loopback(request)}


@router.post("/setup")
def setup(body: Setup, request: Request):
    security.check_lock(request, "setup")
    if not _code_ok(request, body.setup_code):
        security.register_failure(request, "setup")
        audit.event("auth.setup_code_rejected", "warning", ip=security.client_ip(request))
        raise HTTPException(403, "Setup-Code ungültig. Du findest ihn auf dem HDMI-Bildschirm oder in der Datei "
                                 "PIOS-SETUP.txt auf der Boot-Partition der SD-Karte.")
    with db.tx() as c:
        if c.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            raise HTTPException(409, "Bereits eingerichtet")
        c.execute("INSERT INTO users(username,password,role,created) VALUES(?,?,'admin',?)",
                  (body.username, security.hasher.hash(body.password), int(time.time())))
    _code_path().unlink(missing_ok=True)
    _done_path().write_text("1\n")
    audit.event("auth.setup_complete", "notice", actor=body.username, ip=security.client_ip(request), local=security.is_loopback(request))
    return {"ok": True}


# ---- login / logout -----------------------------------------------------------
@router.post("/login")
def login(body: Credentials, request: Request, response: Response):
    try:
        security.check_lock(request, body.username)
    except HTTPException:
        audit.event("auth.locked_out", "warning", actor=body.username, ip=security.client_ip(request))
        raise
    with db.connect() as c:
        r = c.execute("SELECT * FROM users WHERE username=?", (body.username,)).fetchone()
    if not security.verify_password(r["password"] if r else None, body.password):
        security.register_failure(request, body.username)
        audit.event("auth.login_failed", "warning", actor=body.username, ip=security.client_ip(request))
        raise HTTPException(401, "Anmeldung fehlgeschlagen")
    security.clear_failures(request, body.username)
    audit.event("auth.login", "notice" if r["role"] == "admin" else "info", actor=r["username"], ip=security.client_ip(request),
                role=r["role"], client=security.client_kind(request))
    if security.hasher.check_needs_rehash(r["password"]):
        with db.connect() as c:
            c.execute("UPDATE users SET password=? WHERE id=?", (security.hasher.hash(body.password), r["id"]))
    token = security.create_session(r["id"], request)
    response.set_cookie(security.COOKIE, token, httponly=True, samesite="strict",
                        secure=request.url.scheme == "https", max_age=config.SESSION_TTL, path="/")
    return {"ok": True}


@router.post("/logout")
def logout(response: Response, u=Depends(current_user)):
    with db.connect() as c:
        c.execute("DELETE FROM sessions WHERE hash=?", (u["session"],))
    response.delete_cookie(security.COOKIE, path="/")
    return {"ok": True}


@router.get("/me")
def me(u=Depends(current_user)):
    return {"id": u["id"], "username": u["username"], "role": u["role"], "kind": u["kind"]}


# ---- password & sessions -------------------------------------------------------
@router.put("/me/password")
def change_password(body: PasswordChange, request: Request, u=Depends(current_user)):
    security.check_lock(request, u["username"])
    with db.connect() as c:
        r = c.execute("SELECT password FROM users WHERE id=?", (u["id"],)).fetchone()
    if not security.verify_password(r["password"], body.current):
        security.register_failure(request, u["username"])
        audit.event("auth.password_change_failed", "warning", actor=u["username"], ip=security.client_ip(request))
        raise HTTPException(403, "Aktuelles Passwort ist falsch")
    with db.tx() as c:
        c.execute("UPDATE users SET password=? WHERE id=?", (security.hasher.hash(body.new), u["id"]))
        c.execute("DELETE FROM sessions WHERE uid=? AND hash<>?", (u["id"], u["session"]))
    audit.event("auth.password_changed", "notice", actor=u["username"], ip=security.client_ip(request))
    return {"ok": True}


@router.get("/sessions")
def list_sessions(u=Depends(current_user)):
    with db.connect() as c:
        rows = c.execute("SELECT hash,created,last_seen,kind,agent FROM sessions WHERE uid=? AND expires>? "
                         "ORDER BY last_seen DESC", (u["id"], int(time.time()))).fetchall()
    return [{"id": r["hash"][:16], "created": r["created"], "last_seen": r["last_seen"], "kind": r["kind"],
             "agent": r["agent"], "current": r["hash"] == u["session"]} for r in rows]


@router.delete("/sessions/{sid}")
def revoke_session(sid: str, request: Request, u=Depends(current_user)):
    if not re.fullmatch(r"[0-9a-f]{16}", sid):
        raise HTTPException(400, "Ungültige Sitzung")
    with db.connect() as c:
        c.execute("DELETE FROM sessions WHERE uid=? AND hash LIKE ?", (u["id"], sid + "%"))
    audit.event("auth.session_revoked", "notice", actor=u["username"], ip=security.client_ip(request))
    return {"ok": True}


# ---- user administration (admin only) ---------------------------------------------
@router.get("/users")
def list_users(u=Depends(admin_user)):
    with db.connect() as c:
        return [dict(r) for r in c.execute("SELECT id,username,role,created FROM users ORDER BY id")]


@router.post("/users")
def create_user(body: NewUser, request: Request, u=Depends(admin_user)):
    with db.tx() as c:
        if c.execute("SELECT 1 FROM users WHERE username=?", (body.username,)).fetchone():
            raise HTTPException(409, "Benutzername bereits vergeben")
        cur = c.execute("INSERT INTO users(username,password,role,created) VALUES(?,?,?,?)",
                        (body.username, security.hasher.hash(body.password), body.role, int(time.time())))
    audit.event("user.created", "notice", actor=u["username"], ip=security.client_ip(request), user=body.username, role=body.role)
    return {"id": cur.lastrowid}


@router.delete("/users/{uid}")
def delete_user(uid: int, request: Request, u=Depends(admin_user)):
    if uid == u["id"]:
        raise HTTPException(400, "Das eigene Konto kann nicht gelöscht werden")
    with db.tx() as c:
        if not c.execute("DELETE FROM users WHERE id=?", (uid,)).rowcount:
            raise HTTPException(404, "Benutzer nicht gefunden")
    shutil.rmtree(config.DATA / "files" / str(uid), ignore_errors=True)
    audit.event("user.deleted", "notice", actor=u["username"], ip=security.client_ip(request), user_id=uid)
    return {"ok": True}
