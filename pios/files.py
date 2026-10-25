"""NOVA Files API (per-user storage)."""
import shutil

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from . import config, vfs
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
    return {"used": vfs.tree_size(vfs.user_root(u["id"])), "disk_total": du.total, "disk_free": du.free}


@router.post("/upload")
async def upload(path: str = Query("", max_length=4096), file: UploadFile = File(...), u=Depends(current_user)):
    root = vfs.user_root(u["id"])
    target = vfs.write_stream_target(root, path, file.filename or "")
    vfs.check_space()
    size = 0
    try:
        with target.open("xb") as f:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > config.MAX_UPLOAD:
                    raise HTTPException(413, "Datei überschreitet das Upload-Limit")
                if size % (64 * 1024 * 1024) < len(chunk):
                    vfs.check_space()
                f.write(chunk)
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return {"name": target.name, "size": size}


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
