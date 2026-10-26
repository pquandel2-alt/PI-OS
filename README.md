# PiOS · NOVA

**Raspberry Pi 5 web operating system — 0.2.0 (alpha, beta channel)**

PiOS NOVA is a self-contained, futuristic desktop that runs as a web service on Raspberry Pi OS (64-bit,
Debian trixie). Open it in any browser on your network (`http://pios.local`) — or plug in an HDMI monitor, mouse and
keyboard and the same desktop appears full screen on the device.

> **Status:** The software is tested (backend, browser UI, Debian-package compatibility). The Raspberry Pi image is built
> and checked by CI, but it has **not yet been booted on real Pi 5 hardware**. See
> [docs/IMAGE_BUILD.md](docs/IMAGE_BUILD.md#hardware-tests-still-open).

## What is inside

| Part | What it does |
|---|---|
| **NOVA Shell** | Desktop with animated orb, dock, launcher/search (`Ctrl+K`), movable/resizable windows, clock + status tray, responsive phone/tablet layout, saved layout per client (HDMI vs. browser) |
| **NOVA Files** | Per-user private storage: folders, upload (progress, drag & drop), download, rename, move, delete, image/text/audio/video preview, free-space display |
| **NOVA Notes** | SQLite notes with autosave and search |
| **NOVA Monitor** | Live CPU, RAM, temperature, disk, uptime, network (no reloads) |
| **NOVA Settings** | Profile, password, sessions, appearance (accent, animations, orb), desktop, users (admin), installed apps, system info |
| **NOVA Updates** | Signed OTA updates from GitHub Releases with live progress, automatic backup, health check and application rollback, Stable/Beta channels — [docs/UPDATES.md](docs/UPDATES.md) |
| **App platform** | Versioned manifests, server-enforced permissions, sandboxed apps + JS SDK — [docs/APP_SDK.md](docs/APP_SDK.md) |
| **Local mode** | `cage` (Wayland kiosk compositor) + Chromium, started automatically while a monitor is connected |

Updates: [docs/UPDATES.md](docs/UPDATES.md). Design and architecture decisions: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Security model:
[docs/SECURITY.md](docs/SECURITY.md).

## Install on a Raspberry Pi (image)

1. Download `PiOS-NOVA-arm64.img.xz` (see [docs/IMAGE_BUILD.md](docs/IMAGE_BUILD.md)) and verify its SHA-256.
2. Raspberry Pi Imager → *Raspberry Pi 5* → *Choose OS* → *Use custom* → select the file → choose your SD card/SSD.
   Use **OS customisation** to set Wi-Fi, locale and (optionally) a user/SSH key — PiOS itself needs no SSH.
3. Power on. The file system expands itself on first boot.
4. Open `http://pios.local` (or the IP address) and create the administrator account. You need the **setup code**: it is
   shown on the HDMI screen console and stored in `PIOS-SETUP.txt` on the SD card's boot partition (read it on another
   computer). With a monitor attached the local desktop needs no code.

## Develop

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
PIOS_DATA=./data uvicorn pios.main:app --reload --port 8080   # the setup code is printed to the log
pytest tests --ignore=tests/e2e                                # backend tests
pip install playwright && playwright install chromium && pytest tests/e2e   # browser tests
scripts/check-js.sh                                            # JS syntax check
```

The frontend is plain ES modules — no bundler, no Node on the device. Data lives in `PIOS_DATA`
(`/var/lib/pios` on the image).

## Do not expose PiOS to the internet

The repository is public, the device is not meant to be. PiOS is designed for a trusted home network. There is no TLS; do not port-forward it. If you need remote access use a
VPN (e.g. WireGuard/Tailscale).

See the [Roadmap](docs/ROADMAP.md).
