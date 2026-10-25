# PiOS · NOVA

**Private Raspberry Pi 5 web operating system — 0.1-alpha**

A locally hosted futuristic desktop with movable app windows, a dock, administrator setup, sign-in, private notes, a scoped file area and a CPU/RAM/disk monitor. Built on Raspberry Pi OS Lite 64-bit. It is **not** a replacement Linux kernel.

## Start on Raspberry Pi OS (Python 3.11+)

```bash
sudo apt update && sudo apt install -y python3-venv python3-pip
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn pios.main:app --host 0.0.0.0 --port 8080
```

Open `http://<PI-IP>:8080` in a browser on the same trusted local network. Create an administrator using a password of 12+ characters. All persistent data is kept under `data/` (gitignored).

**Security notice:** This is an early prototype without complete authentication hardening, rate limiting or an independent security audit. Do not port-forward or expose it to the Internet. HTTPS and reverse proxy hardening are required before broader deployment.

## Status

- Browser desktop, dock, draggable/minimizable windows
- First-run administrator setup and signed-in session cookies
- Local SQLite notes; user-specific file upload/download/delete with 25 MB maximum
- System monitor and built-in app registry
- Future: robust App SDK with permissions and sandbox, local HDMI kiosk mode, tests, CI and release image

See [Roadmap](docs/ROADMAP.md). The starter source has not yet been end-to-end validated on physical Raspberry Pi hardware.
