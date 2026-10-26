"""Per-user desktop preferences and per-client window layout."""
import json
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from . import db
from .security import current_user

router = APIRouter(prefix="/api")
MAX_STATE = 64 * 1024


class Prefs(BaseModel):
    accent: Literal["cyan", "violet"] = "cyan"
    animations: bool = True
    orb: bool = True
    density: Literal["comfortable", "compact"] = "comfortable"
    clock24: bool = True
    restore_apps: bool = True


def _get(uid, table, args=()):
    sql = {"prefs": "SELECT data FROM prefs WHERE uid=?", "desktop": "SELECT data FROM desktop WHERE uid=? AND kind=?"}[table]
    with db.connect() as c:
        r = c.execute(sql, (uid, *args)).fetchone()
    return json.loads(r["data"]) if r else None


@router.get("/prefs")
def get_prefs(u=Depends(current_user)):
    return Prefs(**(_get(u["id"], "prefs") or {}))


@router.put("/prefs")
def set_prefs(p: Prefs, u=Depends(current_user)):
    with db.connect() as c:
        c.execute("INSERT INTO prefs VALUES(?,?) ON CONFLICT(uid) DO UPDATE SET data=excluded.data",
                  (u["id"], p.model_dump_json()))
    return p


@router.get("/desktop")
def get_desktop(u=Depends(current_user)):
    # Local (HDMI) and remote (browser) sessions keep independent layouts.
    return _get(u["id"], "desktop", (u["kind"],)) or {"windows": {}, "open": []}


@router.put("/desktop")
async def set_desktop(request: Request, u=Depends(current_user)):
    raw = await request.body()
    if len(raw) > MAX_STATE:
        raise HTTPException(413, "Zustand zu groß")
    try:
        data = json.loads(raw)
        assert isinstance(data, dict)
    except (ValueError, AssertionError):
        raise HTTPException(400, "Ungültiges JSON") from None
    with db.connect() as c:
        c.execute("INSERT INTO desktop VALUES(?,?,?) ON CONFLICT(uid,kind) DO UPDATE SET data=excluded.data",
                  (u["id"], u["kind"], json.dumps(data)))
    return {"ok": True}
