"""Runtime configuration, read once from the environment."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(os.getenv("PIOS_DATA", ROOT / "data")).resolve()
WEB = Path(os.getenv("PIOS_WEB", ROOT / "web")).resolve()
APPS_DIR = Path(os.getenv("PIOS_APPS", ROOT / "apps")).resolve()
MAX_UPLOAD = int(os.getenv("PIOS_MAX_UPLOAD", 2 * 1024**3))
SESSION_TTL = int(os.getenv("PIOS_SESSION_TTL", 14 * 86400))      # absolute lifetime
IDLE_REMOTE = int(os.getenv("PIOS_IDLE_REMOTE", 12 * 3600))           # browsers on the LAN
IDLE_LOCAL = int(os.getenv("PIOS_IDLE_LOCAL", 14 * 86400))             # HDMI kiosk
USER_QUOTA = int(os.getenv("PIOS_USER_QUOTA", 16 * 1024**3))            # per user, bytes
# Keep this much disk free when accepting uploads.
MIN_FREE_BYTES = int(os.getenv("PIOS_MIN_FREE", 256 * 1024**2))
LOGIN_MAX_FAILURES = 5
LOGIN_LOCK_BASE = 30
LOGIN_LOCK_MAX = 900
