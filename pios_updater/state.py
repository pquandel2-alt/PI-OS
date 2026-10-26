"""Durable JSON state with atomic replace (survives power loss: either old or new file, never half)."""
import json
import os
import time
from pathlib import Path


def atomic_write(path: Path, data: dict | bytes):
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    raw = data if isinstance(data, bytes) else json.dumps(data, indent=2, sort_keys=True).encode()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    dfd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def read_json(path: Path, default):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return default


class Store:
    DEFAULT_CONFIG = {"channel": "stable", "auto_check": True, "snoozed": {}}

    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.config_path = self.root / "config.json"
        self.status_path = self.root / "status.json"     # last check result (cache)
        self.job_path = self.root / "job.json"           # in-flight update journal
        self.history_path = self.root / "history.json"

    def config(self) -> dict:
        return {**self.DEFAULT_CONFIG, **read_json(self.config_path, {})}

    def save_config(self, cfg: dict):
        atomic_write(self.config_path, cfg)

    def cache(self) -> dict:
        return read_json(self.status_path, {})

    def save_cache(self, d: dict):
        atomic_write(self.status_path, d)

    def job(self) -> dict | None:
        return read_json(self.job_path, None)

    def save_job(self, j: dict):
        atomic_write(self.job_path, j)

    def clear_job(self):
        self.job_path.unlink(missing_ok=True)

    def history(self) -> list:
        return read_json(self.history_path, [])

    def add_history(self, entry: dict):
        h = self.history()
        h.insert(0, {"time": int(time.time()), **entry})
        atomic_write(self.history_path, h[:50])
