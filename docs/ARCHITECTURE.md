# Architecture

```
 Browser (LAN)  ─┐                      ┌───────────────────────────────────────────────┐
                 ├─ HTTP :80 ──────────▶│ PiOS Core  (FastAPI/uvicorn, user `pios`)       │
 Chromium kiosk ─┘  127.0.0.1           │  auth · sessions · rate limit · CSRF guard      │
   (cage/Wayland, user `pios-kiosk`)    │  files(vfs) · notes · prefs · system · events   │
                                        │  App Registry · capability tokens · /api/sdk/*  │
                                        │  SQLite + files in /var/lib/pios                │
                                        └───────────────────────────────────────────────┘
```

* **PiOS Core** (`pios/`): one process, one SQLite database, per-user file trees. Everything is behind a session
  cookie (`HttpOnly`, `SameSite=Strict`) except `/healthz`, `/api/setup-status`, login/setup, static shell assets and
  public sandbox app code.
* **NOVA Shell** (`web/`): ES modules, no build step. `wm.js` window manager, `orb.js` indicator, `shell.js` desktop,
  `ui.js`/`components.css` design system, `apps/*.js` trusted system apps loaded on demand.
* **App Registry/Runtime** (`pios/apps.py`, `web/js/sandbox.js`): manifests → sandboxed iframes → `postMessage` bridge →
  `/api/sdk/*` with signed capability tokens. See [APP_SDK.md](APP_SDK.md).
* **Local vs. remote sessions**: the kiosk reaches the backend over loopback. The server marks such sessions `local`;
  window layouts are stored per `(user, kind)`, so the HDMI desktop and a phone browser keep independent layouts while
  sharing the same data and apps.
* **Image** (`image/`, `scripts/`): Raspberry Pi OS Lite (pi-gen, trixie, arm64) + one extra stage that installs Debian
  packages (no pip, no Node on the device), copies `/opt/pios`, creates the service users and enables the units.

## Decisions

| Decision | Reason |
|---|---|
| No React/Vite migration | The shell is ~2k lines. ES modules keep the image free of Node and the build reproducible; a bundler can be added later without changing the app contract (the SDK is the contract). |
| Debian packages instead of a pip venv in the image | Reproducible, signed, security-updated by apt, no compilers or network access to PyPI during the image build. CI tests the backend against exactly these package versions (`debian:trixie`). |
| SQLite + files | One device, few users; no extra daemon to run or secure. |
| Poll instead of WebSockets/SSE | Works through any proxy; one shared 2.5 s poll feeds tray, orb and Monitor. |
| Third-party apps never run in the backend | They are static web apps in sandboxed, network-less iframes. A future "server component" would need a separate container/user per app; this is deliberately out of scope for 0.1. |
| Setup code for remote first-run | Prevents the first LAN client from taking over an unconfigured device. Physical access (HDMI/SD card) proves ownership. |
| Port 80 with `CAP_NET_BIND_SERVICE` | `http://pios.local` without a port; no root and no reverse proxy needed. |
