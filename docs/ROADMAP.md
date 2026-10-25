# Roadmap

## 0.1 — Web desktop + image (this release)
- [x] Backend: setup wizard (+ setup code), login, sessions, brute-force lock, per-user files/notes, prefs, monitor
- [x] NOVA Shell, orb, window manager, launcher/search, responsive layout, Files/Notes/Monitor/Settings
- [x] App registry, manifests, capability tokens, sandboxed app + SDK v1, example app
- [x] Image pipeline (pi-gen + custom stage), systemd units, HDMI kiosk units, CI verification
- [ ] **Boot and test on a real Raspberry Pi 5** (see docs/IMAGE_BUILD.md → Hardware tests)

## 0.2 — Update Center (this release)
- [x] Signed OTA updates, versioned releases, backup, rollback, Stable/Beta, Update Center UI
- [ ] Validate on real hardware, then record it in `release/hardware-validation.json` to allow `stable`

## 0.3 — Hardening and hybrid polish
- HTTPS option (self-signed/local CA or Caddy), HSTS when enabled
- Backup/restore of `/var/lib/pios`, data export per user
- Kiosk: on-screen keyboard, idle/screen-blank policy, display rotation, multi-monitor
- Notes: Markdown preview, pinned notes; Files: trash, zip download, multi-select
- Optional automatic installation of updates, updater key rotation / "core update"; audit log

## 0.4 — App Engine
- Install/update/uninstall apps from a package (`.piosapp`), signature verification
- Per-install permission prompts and a permission manager in Settings
- Optional server components in isolated systemd units (own user, `ProtectSystem`, cgroup limits) behind a broker API
- Background tasks, scheduled jobs, `pios.ui` components library

## 0.5 — Developer experience
- `pios` CLI (scaffold, validate manifest, pack), SDK typings, hot-reload dev mode, code editor app
