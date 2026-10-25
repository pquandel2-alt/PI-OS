"""Runtime configuration, read once from the environment."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(os.getenv("PIOS_DATA", ROOT / "data")).resolve()
WEB = Path(os.getenv("PIOS_WEB", ROOT / "web")).resolve()
APPS_DIR = Path(os.getenv("PIOS_APPS", ROOT / "apps")).resolve()
MAX_UPLOAD = int(os.getenv("PIOS_MAX_UPLOAD", 4 * 1024**3))
SESSION_TTL = int(os.getenv("PIOS_SESSION_TTL", 7 * 86400))
# Keep this much disk free when accepting uploads.
MIN_FREE_BYTES = int(os.getenv("PIOS_MIN_FREE", 256 * 1024**2))
LOGIN_MAX_FAILURES = 5
LOGIN_LOCK_BASE = 30
LOGIN_LOCK_MAX = 900
