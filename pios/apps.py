"""PiOS App Registry, permissions and the app-facing SDK API.

Apps never run inside the backend. System apps are trusted shell modules; every other
app is static web content that the shell runs in a sandboxed, network-less iframe and
that can only talk to PiOS through the postMessage bridge. The bridge forwards calls to
/api/sdk/* with a signed capability token, and *this module* enforces the permissions.
"""
import json
import re
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field, ValidationError, field_validator

from . import API_VERSION, config, db, events, security, system, vfs
from .security import current_user, read_app_token

router = APIRouter()

PERMISSIONS = {
    "storage": "Eigene App-Daten speichern",
    "files.app": "Eigenen Ordner in NOVA Files nutzen",
    "files.read": "Alle eigenen Dateien lesen",
    "files.write": "Alle eigenen Dateien ändern",
    "system.read": "Systemstatus lesen",
    "notifications": "Benachrichtigungen anzeigen",
}
KV_VALUE_MAX = 256 * 1024
KV_APP_MAX = 4 * 1024 * 1024
FILE_MAX = 10 * 1024 * 1024


class WindowSpec(BaseModel):
    width: int = Field(default=720, ge=240, le=4000)
    height: int = Field(default=480, ge=160, le=4000)


class Manifest(BaseModel):
    id: str
    name: str = Field(min_length=1, max_length=40)
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    api: int = API_VERSION
    kind: Literal["system", "sandboxed"] = "sandboxed"
    entry: str = "index.html"
    icon: str = "app"
    description: str = Field(default="", max_length=300)
    author: str = Field(default="", max_length=80)
    permissions: list[str] = []
    window: WindowSpec = WindowSpec()

    @field_validator("id")
    @classmethod
    def _id(cls, v):
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,47}", v):
            raise ValueError("ungültige App-ID")
        return v

    @field_validator("permissions")
    @classmethod
    def _perms(cls, v):
        bad = [p for p in v if p not in PERMISSIONS]
        if bad:
            raise ValueError(f"unbekannte Berechtigungen: {bad}")
        return sorted(set(v))

    @field_validator("entry")
    @classmethod
    def _entry(cls, v):
        if v.startswith("/") or ".." in v.split("/"):
            raise ValueError("ungültiger Einstiegspunkt")
        return v


SYSTEM_APPS = [
    Manifest(id="files", name="NOVA Files", version="0.1.0", kind="system", icon="files",
             description="Dateien verwalten", permissions=["files.read", "files.write"]),
    Manifest(id="notes", name="NOVA Notes", version="0.1.0", kind="system", icon="notes",
             description="Notizen schreiben", permissions=["storage"]),
    Manifest(id="monitor", name="NOVA Monitor", version="0.1.0", kind="system", icon="monitor",
             description="Systemstatus", permissions=["system.read"]),
    Manifest(id="settings", name="NOVA Settings", version="0.1.0", kind="system", icon="settings",
             description="Einstellungen", permissions=[]),
]


class Registry:
    """Loads manifests from the apps directory; broken apps are skipped, never fatal."""

    def __init__(self, apps_dir: Path):
        self.dir = apps_dir
        self.apps: dict[str, Manifest] = {m.id: m for m in SYSTEM_APPS}
        self.errors: dict[str, str] = {}
        self.reload()

    def reload(self):
        self.apps = {m.id: m for m in SYSTEM_APPS}
        self.errors = {}
        if not self.dir.is_dir():
            return
        for mf in sorted(self.dir.glob("*/manifest.json")):
            try:
                m = Manifest(**json.loads(mf.read_text()))
                if m.id != mf.parent.name:
                    raise ValueError("App-ID muss dem Ordnernamen entsprechen")
                if m.kind != "sandboxed":
                    raise ValueError("Nur sandboxed-Apps dürfen im Apps-Ordner liegen")
                if m.api > API_VERSION:
                    raise ValueError(f"benötigt App-API {m.api}, unterstützt wird {API_VERSION}")
                if not (mf.parent / m.entry).is_file():
                    raise ValueError("Einstiegspunkt fehlt")
                if m.id in self.apps:
                    raise ValueError("ID bereits vergeben")
                self.apps[m.id] = m
            except (ValueError, ValidationError, OSError) as e:
                self.errors[mf.parent.name] = str(e)


registry = Registry(config.APPS_DIR)


# ---- registry API -------------------------------------------------------------
@router.get("/api/apps")
def list_apps(u=Depends(current_user)):
    return {"api": API_VERSION, "apps": [m.model_dump() for m in registry.apps.values()],
            "permissions": PERMISSIONS, "errors": registry.errors}


@router.post("/api/apps/{app_id}/token")
def app_token(app_id: str, u=Depends(current_user)):
    m = registry.apps.get(app_id)
    if not m or m.kind != "sandboxed":
        raise HTTPException(404, "App nicht gefunden")
    return {"token": security.issue_app_token(m.id, u["id"], m.permissions), "ttl": 3600,
            "permissions": m.permissions}


# Sandboxed app assets are public static code: the iframe has an opaque origin and sends no cookies.
@router.get("/apps/{app_id}/{path:path}")
def app_asset(app_id: str, path: str = ""):
    m = registry.apps.get(app_id)
    if not m or m.kind != "sandboxed":
        raise HTTPException(404)
    base = (registry.dir / app_id).resolve()
    f = (base / (path or m.entry)).resolve()
    if not f.is_relative_to(base) or not f.is_file():
        raise HTTPException(404)
    return FileResponse(f, headers={
        "Content-Security-Policy": "sandbox allow-scripts; default-src 'none'; script-src 'self'; "
                                   "style-src 'self'; img-src 'self' data: blob:; font-src 'self'; "
                                   "connect-src 'none'; frame-ancestors 'self'",
        "Access-Control-Allow-Origin": "*", "X-Content-Type-Options": "nosniff", "Cache-Control": "no-cache"})


# ---- SDK API (capability token auth, no cookies) ---------------------------------
def need(perm_options: str):
    """Dependency factory: token must hold at least one of the listed permissions."""
    wanted = perm_options.split("|")

    def dep(tok=Depends(read_app_token)):
        held = [p for p in wanted if p in tok["perms"]]
        if not held:
            raise HTTPException(403, f"Berechtigung fehlt: {wanted[0]}")
        return {**tok, "held": held}
    return dep


sdk = APIRouter(prefix="/api/sdk")


class KvValue(BaseModel):
    value: object = None


@sdk.get("/storage/{key}")
def kv_get(key: str, t=Depends(need("storage"))):
    with db.connect() as c:
        r = c.execute("SELECT value FROM app_kv WHERE app=? AND uid=? AND key=?", (t["app"], t["uid"], key)).fetchone()
    return {"value": json.loads(r["value"]) if r else None}


@sdk.put("/storage/{key}")
def kv_set(key: str, body: KvValue, t=Depends(need("storage"))):
    if not re.fullmatch(r"[\w.:-]{1,100}", key):
        raise HTTPException(400, "Ungültiger Schlüssel")
    raw = json.dumps(body.value)
    if len(raw) > KV_VALUE_MAX:
        raise HTTPException(413, "Wert zu groß")
    with db.tx() as c:
        used = c.execute("SELECT COALESCE(SUM(LENGTH(value)),0) FROM app_kv WHERE app=? AND uid=? AND key<>?",
                         (t["app"], t["uid"], key)).fetchone()[0]
        if used + len(raw) > KV_APP_MAX:
            raise HTTPException(413, "App-Speicherkontingent erschöpft")
        c.execute("INSERT INTO app_kv VALUES(?,?,?,?) ON CONFLICT(app,uid,key) DO UPDATE SET value=excluded.value",
                  (t["app"], t["uid"], key, raw))
    return {"ok": True}


@sdk.delete("/storage/{key}")
def kv_del(key: str, t=Depends(need("storage"))):
    with db.connect() as c:
        c.execute("DELETE FROM app_kv WHERE app=? AND uid=? AND key=?", (t["app"], t["uid"], key))
    return {"ok": True}


def _file_scope(t, path: str, write: bool):
    """Returns (root, relpath). files.app confines to Apps/<id>/, files.read/write open the user tree."""
    root = vfs.user_root(t["uid"])
    if "files.write" in t["perms"] or (not write and "files.read" in t["perms"]):
        return root, path
    if "files.app" in t["perms"]:
        scope = root / "Apps" / t["app"]
        scope.mkdir(parents=True, exist_ok=True)
        return scope, path
    raise HTTPException(403, "Berechtigung fehlt: " + ("files.write" if write else "files.read"))


@sdk.get("/files")
def sdk_list(path: str = Query("", max_length=4096), t=Depends(read_app_token)):
    root, rel = _file_scope(t, path, False)
    return vfs.listing(root, rel)


@sdk.get("/files/content")
def sdk_read(path: str = Query(..., max_length=4096), t=Depends(read_app_token)):
    root, rel = _file_scope(t, path, False)
    p = vfs.resolve(root, rel)
    if not p.is_file():
        raise HTTPException(404, "Datei nicht gefunden")
    if p.stat().st_size > FILE_MAX:
        raise HTTPException(413, "Datei zu groß für die App-API")
    return Response(p.read_bytes(), media_type="application/octet-stream",
                    headers={"X-Content-Type-Options": "nosniff"})


@sdk.put("/files/content")
async def sdk_write(request: Request, path: str = Query(..., max_length=4096), t=Depends(read_app_token)):
    root, rel = _file_scope(t, path, True)
    data = await request.body()
    if len(data) > FILE_MAX:
        raise HTTPException(413, "Datei zu groß für die App-API")
    parts = [x for x in rel.split("/") if x]
    if not parts:
        raise HTTPException(400, "Pfad fehlt")
    parent = vfs.resolve(root, "/".join(parts[:-1]))
    vfs.check_space(len(data))
    (parent / vfs.valid_name(parts[-1])).write_bytes(data)
    return {"ok": True}


@sdk.get("/system")
def sdk_system(t=Depends(need("system.read"))):
    s = system.summary()
    return {k: s[k] for k in ("cpu", "ram", "disk", "temp", "uptime", "version")}


class Notification(BaseModel):
    title: str = Field(max_length=80)
    body: str = Field(default="", max_length=300)
    level: Literal["info", "warn", "error"] = "info"


@sdk.post("/notifications")
def sdk_notify(n: Notification, t=Depends(need("notifications"))):
    events.publish(t["uid"], "notification", app=t["app"], title=n.title, body=n.body, level=n.level)
    return {"ok": True}


router.include_router(sdk)
