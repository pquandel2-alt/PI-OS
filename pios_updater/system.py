"""Real system integration: systemd, health probes, OS info."""
import json
import platform
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

from .engine import Env, db_quick_check, db_user_version

UNIT = "pios.service"


def _sysctl(*args, timeout=60):
    return subprocess.run(["systemctl", *args], capture_output=True, text=True, timeout=timeout)


class SystemEnv(Env):
    def __init__(self, base="http://127.0.0.1"):
        self.base = base

    def restart_backend(self):
        r = _sysctl("restart", UNIT)
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip() or "systemctl restart fehlgeschlagen")

    def stop_backend(self):
        _sysctl("stop", UNIT)

    def start_backend(self):
        r = _sysctl("start", UNIT)
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip() or "systemctl start fehlgeschlagen")

    def _get(self, path, timeout=5):
        with urllib.request.urlopen(self.base + path, timeout=timeout) as r:
            return r.status, r.read(200_000)

    def health(self, target_version, db_path):
        d = {}
        d["service_active"] = _sysctl("is-active", "--quiet", UNIT).returncode == 0
        try:
            st, body = self._get("/healthz")
            hz = json.loads(body)
            d["health_api"] = st == 200 and hz.get("ok") is True
            d["version_active"] = hz.get("version") == target_version
            d["backend_db"] = hz.get("checks", {}).get("db") is True
            d["backend_apps"] = hz.get("checks", {}).get("apps") is True
        except (urllib.error.URLError, OSError, ValueError):
            d.update(health_api=False, version_active=False, backend_db=False, backend_apps=False)
        d["database"] = (not Path(db_path).exists()) or db_quick_check(db_path)
        try:
            ok = True
            st, body = self._get("/")
            ok &= st == 200 and b"PiOS NOVA" in body
            for asset in ("/js/main.js", "/css/tokens.css", "/sdk/pios-sdk.js"):
                ok &= self._get(asset)[0] == 200
            d["assets"] = bool(ok)
        except (urllib.error.URLError, OSError):
            d["assets"] = False
        return all(v is True for v in d.values()), d

    def os_codename(self):
        for line in Path("/etc/os-release").read_text().splitlines():
            if line.startswith("VERSION_CODENAME="):
                return line.split("=", 1)[1].strip('"')
        return "unknown"

    def arch(self):
        return {"aarch64": "arm64", "x86_64": "amd64"}.get(platform.machine(), platform.machine())
