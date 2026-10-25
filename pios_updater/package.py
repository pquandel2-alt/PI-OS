"""Build and safely unpack OTA packages (.tar.zst). Only plain files/dirs, strictly confined."""
import hashlib
import json
import os
import posixpath
import subprocess
import tarfile
from pathlib import Path

ALLOWED_TOP = {"release.json", "pios", "web", "apps", "bin"}
REQUIRED = ("release.json", "pios/main.py", "pios/__init__.py", "web/index.html")
MAX_FILES = 20000
MAX_FILE_BYTES = 200 * 1024 * 1024
EXEC_DIRS = ("bin",)


class PackageError(Exception):
    pass


# ---------------------------------------------------------------- build (CI side)
def collect(src_root: Path) -> list[tuple[str, Path]]:
    out = []
    for top in ("pios", "web", "apps"):
        base = Path(src_root) / top
        for p in sorted(base.rglob("*")):
            rel = p.relative_to(src_root).as_posix()
            if "__pycache__" in rel.split("/") or rel.endswith(".pyc") or p.is_symlink():
                continue
            if p.is_file():
                out.append((rel, p))
    for p in sorted((Path(src_root) / "image/overlay/opt/pios/bin").glob("*")):
        if p.is_file():
            out.append(("bin/" + p.name, p))
    return out


def build(src_root: Path, out_file: Path, release_json: dict, epoch: int = 0) -> dict:
    """Deterministic package: sorted entries, fixed mtime/owner/modes. Returns {sha256,size,unpacked_size}."""
    files = collect(src_root)
    rj = (json.dumps(release_json, indent=2, sort_keys=True) + "\n").encode()
    unpacked = len(rj)
    proc = subprocess.Popen(["zstd", "-19", "-T0", "-q", "-f", "-o", str(out_file)], stdin=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=proc.stdin, mode="w|", format=tarfile.PAX_FORMAT) as tf:
            def add_bytes(name, data, mode):
                ti = tarfile.TarInfo(name); ti.size = len(data); ti.mode = mode; ti.mtime = epoch
                tf.addfile(ti, __import__("io").BytesIO(data))
            add_bytes("release.json", rj, 0o644)
            dirs = sorted({posixpath.dirname(r) for r, _ in files if posixpath.dirname(r)}
                          | {d for r, _ in files for d in _parents(r)})
            for d in dirs:
                ti = tarfile.TarInfo(d); ti.type = tarfile.DIRTYPE; ti.mode = 0o755; ti.mtime = epoch
                tf.addfile(ti)
            for rel, p in files:
                data = p.read_bytes()
                unpacked += len(data)
                add_bytes(rel, data, 0o755 if rel.split("/")[0] in EXEC_DIRS else 0o644)
        proc.stdin.close()
    finally:
        if proc.wait() != 0:
            raise PackageError("zstd fehlgeschlagen")
    h = hashlib.sha256()
    with open(out_file, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return {"sha256": h.hexdigest(), "size": Path(out_file).stat().st_size, "unpacked_size": unpacked}


def _parents(rel):
    parts = rel.split("/")[:-1]
    return ["/".join(parts[:i]) for i in range(1, len(parts) + 1)]


# ---------------------------------------------------------------- unpack (device side)
def _clean(name: str) -> str:
    if not name or name.startswith("/") or "\\" in name or "\x00" in name:
        raise PackageError(f"Ungültiger Pfad im Paket: {name!r}")
    norm = posixpath.normpath(name)
    if norm.startswith("..") or norm == "." or ".." in norm.split("/"):
        raise PackageError(f"Ungültiger Pfad im Paket: {name!r}")
    if norm.split("/")[0] not in ALLOWED_TOP:
        raise PackageError(f"Nicht erlaubter Pfad im Paket: {name!r}")
    return norm


def unpack(package: Path, dest: Path, unpacked_size: int, progress=None) -> int:
    """Extract into the (empty, newly created) `dest`. Raises PackageError on anything unexpected."""
    dest = Path(dest)
    dest.mkdir(parents=True, mode=0o755)
    budget = int(unpacked_size * 1.02) + 4096
    total = count = 0
    proc = subprocess.Popen(["zstd", "-dc", "-q", str(package)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=proc.stdout, mode="r|") as tf:
            for m in tf:
                count += 1
                if count > MAX_FILES:
                    raise PackageError("Zu viele Dateien im Paket")
                name = _clean(m.name)
                target = dest / name
                if m.isdir():
                    target.mkdir(parents=True, exist_ok=True, mode=0o755)
                    os.chmod(target, 0o755)
                    continue
                if not m.isreg():
                    raise PackageError(f"Nicht erlaubter Eintragstyp in {name!r}")
                if m.size > MAX_FILE_BYTES:
                    raise PackageError(f"Datei zu groß: {name!r}")
                total += m.size
                if total > budget:
                    raise PackageError("Paket entpackt größer als im Manifest angegeben")
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                mode = 0o755 if name.split("/")[0] in EXEC_DIRS else 0o644
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
                with os.fdopen(fd, "wb") as out:
                    src = tf.extractfile(m)
                    for chunk in iter(lambda: src.read(1 << 20), b""):
                        out.write(chunk)
                os.chmod(target, mode)
                if progress:
                    progress(min(1.0, total / max(1, unpacked_size)))
    except tarfile.TarError as e:
        raise PackageError(f"Paket beschädigt: {e}") from None
    finally:
        proc.stdout.close()
        rc = proc.wait()
    if rc != 0:
        raise PackageError("Paket konnte nicht dekomprimiert werden")
    return count


def validate_tree(root: Path, version: str, db_schema: int):
    for rel in REQUIRED:
        if not (Path(root) / rel).is_file():
            raise PackageError(f"Pflichtdatei fehlt: {rel}")
    try:
        rj = json.loads((Path(root) / "release.json").read_text())
    except ValueError:
        raise PackageError("release.json ungültig") from None
    if rj.get("version") != version or rj.get("db_schema") != db_schema:
        raise PackageError("release.json passt nicht zum signierten Manifest")
    for p in Path(root).rglob("*"):
        if p.is_symlink():
            raise PackageError("Symbolischer Link im Paket")
    r = subprocess.run(["python3", "-m", "compileall", "-q", str(Path(root) / "pios")], capture_output=True, text=True)
    if r.returncode != 0:
        raise PackageError("Python-Code enthält Syntaxfehler: " + (r.stdout + r.stderr)[-300:])


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
