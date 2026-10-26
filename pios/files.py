"""NOVA Files API (per-user storage)."""
import os
import shutil

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from . import config, malware, vfs
from .security import current_user

router = APIRouter(prefix="/api/files")
# Types the browser may render inline. Everything else (HTML, SVG, JS...) is forced to download.
INLINE_OK = ("image/png", "image/jpeg", "image/gif", "image/webp", "image/avif", "image/bmp",
             "audio/mpeg", "audio/ogg", "audio/wav", "audio/flac", "video/mp4", "video/webm", "text/plain")


class PathBody(BaseModel):
    path: str = Field(default="", max_length=4096)


class MkdirBody(PathBody):
    name: str = Field(max_length=255)


class RenameBody(PathBody):
    new_name: str = Field(max_length=255)


class MoveBody(PathBody):
    dest: str = Field(default="", max_length=4096)


@router.get("")
def list_dir(path: str = Query("", max_length=4096), u=Depends(current_user)):
    return vfs.listing(vfs.user_root(u["id"]), path)


@router.get("/usage")
def usage(u=Depends(current_user)):
    du = shutil.disk_usage(config.DATA)
    return {"used": vfs.used_bytes(u["id"]), "quota": config.USER_QUOTA, "disk_total": du.total, "disk_free": du.free}


@router.post("/upload")
async def upload(path: str = Query("", max_length=4096), file: UploadFile = File(...), u=Depends(current_user)):
    root = vfs.user_root(u["id"])
    name = file.filename or ""
    target = vfs.write_stream_target(root, path, name)             # validates folder + name before any byte is stored
    vfs.check_space()
    quota_left = config.USER_QUOTA - vfs.used_bytes(u["id"])
    if quota_left <= 0:
        raise HTTPException(507, "Speicherkontingent erreicht")
    scanning = malware.enabled()
    limit = min(config.MAX_UPLOAD, malware.max_scan_bytes()) if scanning else config.MAX_UPLOAD
    if scanning:
        # Never write into the user's tree before the scan verdict: stream into the private quarantine area.
        qid, dest = malware.new_item_path()
        if malware.quarantine_bytes() > malware.QUARANTINE_CAP:
            raise HTTPException(507, "Der Quarantäne-Bereich ist voll. Bitte warte, bis geprüft wurde, oder lösche Einträge.")
    else:
        qid, dest = None, target
    size = 0
    try:
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as f:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > limit:
                    raise HTTPException(413, "Datei überschreitet das Upload-Limit" if not scanning or limit == config.MAX_UPLOAD
                                        else f"Datei ist zu groß für den Virenscan (max. {limit // (1024 * 1024)} MB)")
                if size > quota_left:
                    raise HTTPException(507, "Speicherkontingent erreicht")
                if size % (64 * 1024 * 1024) < len(chunk):
                    vfs.check_space()
                f.write(chunk)
    except BaseException:
        dest.unlink(missing_ok=True)
        raise
    if not scanning:
        vfs.invalidate_usage(u["id"])
        return {"name": target.name, "size": size, "status": "released_unscanned_disabled"}
    result = await run_in_threadpool(malware.admit, u["id"], path, target.name, qid, dest)
    return {"name": target.name, "size": size, **result}


@router.get("/pending")
def pending(u=Depends(current_user)):
    """The caller's uploads that are not (yet) in the file tree: waiting for the scanner, blocked or infected."""
    return [{k: r[k] for k in ("id", "name", "size", "state", "reason", "detection", "created", "dest_dir")}
            for r in malware.list_items(u["id"], 50) if r["state"] in ("pending", "held", "scanning", "infected", "blocked", "error")]


@router.post("/mkdir")
def mkdir(b: MkdirBody, u=Depends(current_user)):
    vfs.mkdir(vfs.user_root(u["id"]), b.path, b.name)
    return {"ok": True}


@router.post("/rename")
def rename(b: RenameBody, u=Depends(current_user)):
    vfs.rename(vfs.user_root(u["id"]), b.path, b.new_name)
    return {"ok": True}


@router.post("/move")
def move(b: MoveBody, u=Depends(current_user)):
    vfs.move(vfs.user_root(u["id"]), b.path, b.dest)
    return {"ok": True}


@router.delete("")
def delete(path: str = Query(..., max_length=4096), u=Depends(current_user)):
    vfs.remove(vfs.user_root(u["id"]), path)
    vfs.invalidate_usage(u["id"])
    return {"ok": True}


@router.get("/download")
def download(path: str = Query(..., max_length=4096), inline: bool = False, u=Depends(current_user)):
    root = vfs.user_root(u["id"])
    p = vfs.resolve(root, path)
    if not p.is_file():
        raise HTTPException(404, "Datei nicht gefunden")
    mime = vfs.mime_of(p.name)
    show = inline and mime in INLINE_OK
    r = FileResponse(p, media_type=mime if show else "application/octet-stream", filename=p.name,
                     content_disposition_type="inline" if show else "attachment")
    r.headers["Content-Security-Policy"] = "sandbox; default-src 'none'; img-src 'self'; media-src 'self'; style-src 'unsafe-inline'"
    return r
