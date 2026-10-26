"""NOVA Shield API (admin only): security status, audit log, app permissions, firewall, malware protection, OS updates."""
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from . import apps, audit, db, security
from .security import admin_user

router = APIRouter(prefix="/api/shield")


# ---- audit log (read-only) -----------------------------------------------------------------------------
@router.get("/audit")
def audit_list(limit: int = Query(200, ge=1, le=1000), kind: str | None = Query(None, max_length=40),
               severity: Literal["info", "notice", "warning", "critical"] | None = None, u=Depends(admin_user)):
    return {"entries": audit.recent(limit, kind=kind, severity=severity), "integrity": audit.verify()}


@router.get("/audit/verify")
def audit_verify(u=Depends(admin_user)):
    return audit.verify()


# ---- app permissions -----------------------------------------------------------------------------------
class GrantBody(BaseModel):
    permission: str = Field(max_length=40)
    allow: bool


@router.get("/apps")
def apps_overview(u=Depends(admin_user)):
    return {"apps": apps.app_overview(), "permissions": apps.PERMISSIONS}


@router.put("/apps/{app_id}/grants")
def set_grant(app_id: str, b: GrantBody, request: Request, u=Depends(admin_user)):
    m = apps.registry.apps.get(app_id)
    if not m or m.kind != "sandboxed":
        raise HTTPException(404, "App nicht gefunden")
    if b.permission not in m.permissions:
        raise HTTPException(400, "Die App hat diese Berechtigung nicht angefragt")
    import time
    with db.tx() as c:
        if b.allow:
            c.execute("INSERT INTO app_grants VALUES(?,?,?,?) ON CONFLICT(app,perm) DO UPDATE SET granted_by=excluded.granted_by, time=excluded.time",
                      (app_id, b.permission, u["username"], int(time.time())))
        else:
            c.execute("DELETE FROM app_grants WHERE app=? AND perm=?", (app_id, b.permission))
    audit.event("app.permission_changed", "notice", actor=u["username"], ip=security.client_ip(request),
                app=app_id, permission=b.permission, allowed=b.allow)
    return {"app": next(a for a in apps.app_overview() if a["id"] == app_id)}
