"""Confined file-system operations. Every path is relative to a per-user root.

Paths come from untrusted clients. They are split into components, validated, and
the final result is checked to stay inside the root without following symlinks.
"""
import mimetypes
import os
import shutil
import stat
import unicodedata
from pathlib import Path

from fastapi import HTTPException

from . import config


# control, format (bidi overrides, zero-width, BOM), surrogate, private-use, unassigned, line/paragraph separators:
# these enable filename spoofing ("invoice\u202Efdp.exe" displays as "invoiceexe.pdf") and invisible look-alikes.
_BAD_CATEGORIES = {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}


def user_root(uid: int) -> Path:
    p = config.DATA / "files" / str(uid)
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    return p


def valid_name(name: str) -> str:
    if (not name or name in (".", "..") or len(name.encode()) > 255 or "/" in name or "\\" in name
            or any(unicodedata.category(ch) in _BAD_CATEGORIES for ch in name)):
        raise HTTPException(400, "Ungültiger Name")
    return name


def resolve(root: Path, rel: str, *, must_exist: bool = True) -> Path:
    """Map a client path like 'Docs/a.txt' to an absolute path inside root."""
    parts = [p for p in rel.replace("\\", "/").split("/") if p not in ("", ".")]
    cur = root
    for part in parts:
        valid_name(part)
        cur = cur / part
        if cur.is_symlink():
            raise HTTPException(400, "Symbolische Links sind nicht erlaubt")
    if must_exist and not cur.exists():
        raise HTTPException(404, "Nicht gefunden")
    if not cur.resolve().is_relative_to(root.resolve()):
        raise HTTPException(400, "Ungültiger Pfad")
    return cur


def rel_of(root: Path, p: Path) -> str:
    return "/".join(p.relative_to(root).parts)


def mime_of(name: str) -> str:
    return mimetypes.guess_type(name)[0] or "application/octet-stream"


def listing(root: Path, rel: str) -> dict:
    d = resolve(root, rel)
    if not d.is_dir():
        raise HTTPException(400, "Kein Ordner")
    entries = []
    for e in os.scandir(d):
        try:
            st = e.stat(follow_symlinks=False)
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode):
            continue
        is_dir = stat.S_ISDIR(st.st_mode)
        entries.append({"name": e.name, "type": "dir" if is_dir else "file", "size": 0 if is_dir else st.st_size,
                        "mtime": int(st.st_mtime), "mime": "" if is_dir else mime_of(e.name)})
    entries.sort(key=lambda x: (x["type"] != "dir", x["name"].lower()))
    return {"path": rel_of(root, d), "entries": entries}


def mkdir(root: Path, rel: str, name: str):
    parent = resolve(root, rel)
    target = parent / valid_name(name)
    try:
        target.mkdir()
    except FileExistsError:
        raise HTTPException(409, "Existiert bereits") from None


def rename(root: Path, rel: str, new_name: str):
    src = resolve(root, rel)
    if src == root:
        raise HTTPException(400, "Wurzelordner kann nicht umbenannt werden")
    dst = src.with_name(valid_name(new_name))
    if dst.exists():
        raise HTTPException(409, "Existiert bereits")
    src.rename(dst)


def move(root: Path, rel: str, dest_dir: str):
    src = resolve(root, rel)
    dst_dir = resolve(root, dest_dir)
    if src == root or not dst_dir.is_dir():
        raise HTTPException(400, "Ungültiges Ziel")
    if src.is_dir() and (dst_dir == src or dst_dir.is_relative_to(src)):
        raise HTTPException(400, "Ordner kann nicht in sich selbst verschoben werden")
    dst = dst_dir / src.name
    if dst.exists():
        raise HTTPException(409, "Im Zielordner existiert bereits ein Eintrag mit diesem Namen")
    shutil.move(str(src), str(dst))


def remove(root: Path, rel: str):
    p = resolve(root, rel)
    if p == root:
        raise HTTPException(400, "Wurzelordner kann nicht gelöscht werden")
    shutil.rmtree(p) if p.is_dir() else p.unlink()


_usage_cache: dict[int, tuple[float, int]] = {}


def used_bytes(uid: int, ttl: float = 30.0) -> int:
    """Per-user usage with a short cache (a full tree walk on every request would be a DoS vector)."""
    import time
    hit = _usage_cache.get(uid)
    if hit and time.monotonic() - hit[0] < ttl:
        return hit[1]
    size = tree_size(user_root(uid))
    _usage_cache[uid] = (time.monotonic(), size)
    return size


def invalidate_usage(uid: int):
    _usage_cache.pop(uid, None)


def tree_size(p: Path) -> int:
    total = 0
    for dp, _dn, fn in os.walk(p):
        for f in fn:
            try:
                total += os.lstat(os.path.join(dp, f)).st_size
            except OSError:
                pass
    return total


def check_space(size_hint: int = 0):
    free = shutil.disk_usage(config.DATA).free
    if free - size_hint < config.MIN_FREE_BYTES:
        raise HTTPException(507, "Nicht genügend freier Speicherplatz")


def write_stream_target(root: Path, rel_dir: str, filename: str) -> Path:
    d = resolve(root, rel_dir)
    if not d.is_dir():
        raise HTTPException(400, "Zielordner existiert nicht")
    p = d / valid_name(filename)
    if p.exists():
        raise HTTPException(409, "Datei existiert bereits")
    return p
