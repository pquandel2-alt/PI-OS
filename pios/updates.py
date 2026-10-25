"""NOVA Update Center API: a thin, admin-only gateway to the separate PiOS Update Manager.

The backend never installs anything and has no root rights. It forwards a handful of requests over a
unix socket (the Update Manager checks the caller's uid, verifies signatures itself and does all
privileged work), and relays progress to the browser as Server-Sent Events.
"""
import asyncio
import hashlib
import json
import logging
import os
import socket
import time
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from . import config, db, events
from .security import admin_user

log = logging.getLogger("pios.updates")
router = APIRouter(prefix="/api/updates")

STATUS_FOR_CODE = {"busy": 409, "not_available": 404, "incompatible": 409, "not_newer": 409, "no_space": 507, "db_incompatible": 409,
                   "no_previous": 404, "no_backup": 404, "bad_request": 400, "forbidden": 502}


def socket_path() -> str:
    return os.getenv("PIOS_UPDATER_SOCKET", "/run/pios-updater/updater.sock")


class Unavailable(Exception):
    pass


def call(method: str, args: dict | None = None, timeout: float = 60.0):
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
                if len(buf) > 2_000_000:
                    raise Unavailable("Antwort zu groß")
        resp = json.loads(buf)
    except (OSError, ValueError) as e:
        raise Unavailable(str(e)) from None
    if not resp.get("ok"):
        raise HTTPException(STATUS_FOR_CODE.get(resp.get("code"), 500), resp.get("error", "Fehler"))
    return resp["result"]


def _call(method, args=None, timeout=60.0):
    try:
        return call(method, args, timeout)
    except Unavailable:
        raise HTTPException(503, "Der Update-Dienst ist nicht erreichbar (nur im PiOS-Image verfügbar).") from None


class InstallBody(BaseModel):
    version: str = Field(max_length=40)


class ConfigBody(BaseModel):
    channel: Literal["stable", "beta"] | None = None
    auto_check: bool | None = None


class SnoozeBody(BaseModel):
    version: str = Field(max_length=40)
    hours: float = Field(default=24, ge=1, le=24 * 30)


class RollbackBody(BaseModel):
    restore_backup: bool = False


@router.get("")
def status(u=Depends(admin_user)):
    return _call("status", timeout=10)


@router.post("/check")
def check(u=Depends(admin_user)):
    return _call("check", {"force": True}, timeout=90)


@router.post("/install")
def install(b: InstallBody, u=Depends(admin_user)):
    return _call("install", {"version": b.version}, timeout=30)


@router.post("/cancel")
def cancel(u=Depends(admin_user)):
    return _call("cancel", timeout=10)


@router.post("/rollback")
def rollback(b: RollbackBody, u=Depends(admin_user)):
    return _call("rollback", {"restore_backup": b.restore_backup}, timeout=300)


@router.put("/config")
def set_config(b: ConfigBody, u=Depends(admin_user)):
    return _call("config", b.model_dump(exclude_none=True), timeout=10)


@router.post("/snooze")
def snooze(b: SnoozeBody, u=Depends(admin_user)):
    return _call("snooze", b.model_dump(), timeout=10)


@router.get("/stream")
async def stream(request: Request, u=Depends(admin_user)):
    """Server-Sent Events: pushes the Update Manager's status whenever it changes (1 s while a job runs)."""
    async def gen():
        last, idle = None, 0.0
        yield "retry: 2000\n\n"
        while not await request.is_disconnected():
            try:
                st = await asyncio.to_thread(call, "status", None, 8.0)
                blob = json.dumps(st, sort_keys=True)
                digest = hashlib.sha1(blob.encode()).hexdigest()
                if digest != last:
                    last = digest
                    yield f"event: status\ndata: {blob}\n\n"
                    idle = 0.0
                running = (st.get("job") or {}).get("state") in ("running", "rolling_back")
            except (Unavailable, HTTPException):
                if last != "unavailable":
                    last = "unavailable"
                    yield 'event: unavailable\ndata: {}\n\n'
                running = False
            idle += 1
            if idle >= 15:
                idle = 0.0
                yield ": keepalive\n\n"
            await asyncio.sleep(1.0 if running else 3.0)
    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


# ---- notifications -------------------------------------------------------------
def _admin_ids() -> list[int]:
    with db.connect() as c:
        return [r["id"] for r in c.execute("SELECT id FROM users WHERE role='admin'")]


def _notified_path() -> Path:
    return config.DATA / "updates-notified.json"


def notify_once(st: dict, now: float | None = None):
    """Publish NOVA notifications for a new version / a finished job, at most once each (persisted)."""
    try:
        seen = json.loads(_notified_path().read_text())
    except (OSError, ValueError):
        seen = {}
    changed = False
    av = st.get("available")
    if av and av.get("compatible") and not st.get("snoozed_until") and av["version"] not in st.get("failed_versions", {}) \
            and seen.get("available") != av["version"]:
        for uid in _admin_ids():
            events.publish(uid, "notification", app="updates", title=f"PiOS NOVA {av['version']} verfügbar",
                           body="Öffne das Update Center, um Details zu sehen.", level="info")
        seen["available"] = av["version"]; changed = True
    job = st.get("job")
    if job and job.get("state") in ("success", "rolled_back", "failed", "failed_critical") and seen.get("job") != job["id"]:
        msgs = {"success": ("Update installiert", f"PiOS NOVA {job['to']} läuft.", "info"),
                "rolled_back": ("Update fehlgeschlagen – zurückgesetzt", f"Version {job['from']} läuft wieder. {job.get('error') or ''}", "warn"),
                "failed": ("Update fehlgeschlagen", job.get("error") or "", "error"),
                "failed_critical": ("Update und Rollback fehlgeschlagen", job.get("error") or "", "error")}
        title, body, level = msgs[job["state"]]
        for uid in _admin_ids():
            events.publish(uid, "notification", app="updates", title=title, body=body[:280], level=level)
        seen["job"] = job["id"]; changed = True
    if changed:
        try:
            _notified_path().write_text(json.dumps(seen))
        except OSError:
            pass


async def notify_loop():
    await asyncio.sleep(20)
    while True:
        try:
            if Path(socket_path()).exists():
                st = await asyncio.to_thread(call, "status", None, 10.0)
                await asyncio.to_thread(notify_once, st)
        except Exception:                                            # noqa: BLE001
            log.debug("update notification poll failed", exc_info=True)
        await asyncio.sleep(300)
