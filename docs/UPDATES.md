# NOVA Update Center and OTA updates

Install the PiOS image once; afterwards update from the NOVA interface (**Update Center**, or Settings → System →
Updates). No SSH, no terminal, no re-flashing. Works the same in the browser and on the HDMI desktop.

> **Verified so far:** image build run 40243716027 (2026-10-26): 62 automated image checks passed, including the Update Manager
> running inside the arm64 root file system under qemu. The emulated systemd boot test still does not work on the CI runner.
>
> **Honest status:** the update system is implemented and tested (≈ 90 automated tests, including power-loss, failed
> health checks, rollback and tampering), but it has **not run on a real Raspberry Pi 5 yet**. Images built before
> 0.2.0 do not contain the Update Manager and cannot update themselves: flash a 0.2.0+ image once (see *Migration*).

## How a new version is detected

The **Update Manager** (`pios-updater.service`, root, separate process) asks the public GitHub Releases API
(`/repos/pquandel2-alt/PI-OS/releases`) once a day (jittered, plus on demand; ETag caching, rate-limit back-off,
last known result is kept when offline). For each newer release it downloads the small signed manifest
`PiOS-NOVA-update-<v>.manifest.json` + `.sig`, **verifies the Ed25519 signature against the public key shipped in the
image** (`/usr/share/pios/update-keys/`), and only then trusts anything in it (version, channel, compatibility,
SHA-256 of the package, release notes). Release metadata from GitHub (tag, prerelease flag, asset list) is never
trusted on its own — a manipulated API response can at most hide an update. Admins get a NOVA notification (and a dot
on the dock icon); nothing is installed without a click.

## Release assets

| Asset | Purpose |
|---|---|
| `PiOS-NOVA-arm64.img.xz` | full image for new installations (Raspberry Pi Imager) |
| `PiOS-NOVA-update-<v>.tar.zst` | OTA package: `release.json`, `pios/`, `web/`, `apps/`, `bin/` (deterministic archive) |
| `PiOS-NOVA-update-<v>.manifest.json` + `.manifest.json.sig` | signed description (channel, `min_version`, `db_schema`, OS/arch, SHA-256, size, notes) |
| `SHA256SUMS` | convenience only; **not** a trust anchor |

## Install process

1. **Download** (resumable `Range` requests) into `/var/lib/pios-updater/downloads`.
2. **Verify**: manifest signature re-checked, package size + SHA-256 must match the signed manifest, else discarded.
3. **Compatibility**: `min_version`, OS codename (trixie), architecture, DB schema, free space.
4. **Backup** to `/var/lib/pios-updater/backups/`: consistent SQLite copy (online backup API), `secret.key`, config, metadata.
   User files under `/var/lib/pios/files` are never copied, modified or deleted by updates or rollbacks.
5. **Install**: the package is unpacked into `/opt/pios/releases/.<v>.partial` with strict rules (regular files and
   directories only, allowed top-level names only, no `..`, no links, size budget), the Python code is byte-compiled
   (syntax errors abort), then renamed to `/opt/pios/releases/<v>`. The running version is untouched until the single
   atomic switch of the `current` symlink (`rename(2)`), so a power loss can never leave a mix of two versions.
   **No code from the package is executed as root.** Database migrations run inside the backend (user `pios`) at start.
6. **Restart** `pios.service`.
7. **Health check by the Update Manager** (independent of the web server): service active, `/healthz` ok, **running
   version equals the target**, database `quick_check`, backend DB/app self-checks, UI assets served; two consecutive
   passes required (catches crash loops).
8. **Commit** (history, prune old releases: current + previous + 1 kept) – or **automatic rollback**.

Progress is streamed to the UI with Server-Sent Events; percentages are shown only for measured steps (download,
unpack). The job lives in the Update Manager, not in the browser, and survives closing the tab or restarting the web
backend; the UI reconnects by itself and reloads when the new version is active.

## Rollback

* **Automatic:** a failed health check switches `current` back, restores the database **only if needed** (its schema
  is newer than the old release supports, or it is corrupt) from the pre-update backup, restarts and re-checks. This
  runs once; a failed version is recorded and never retried automatically, so there is no reinstall loop.
* **Database compatibility:** a release declares `db_schema`. The backend refuses to start on a database with a newer
  schema than it knows, so an old version can never silently run on migrated data. If an update's migration is applied
  and the update then fails, the old version gets the pre-update database back (changes made in the few seconds the new
  version ran are lost; files are not affected).
* **Manual:** Update Center → *Zur vorherigen Version zurück*. If the database was migrated, the UI says so and the
  rollback only proceeds when you explicitly confirm restoring the backup.
* **After power loss:** on start the Update Manager inspects its journal: if the switch had not happened it just
  cleans up; if it had, it health-checks the new version and commits or rolls back.
* **Scope:** this is an **application rollback** (PiOS code + its database). There is **no OS rollback** of Linux,
  kernel or system packages; OTA packages never touch them.

## Channels

* **Stable** – only releases whose *signed* manifest says `stable`.
* **Beta** – stable and beta releases.
* Switching channels never downgrades: only versions newer than the installed one are offered (a beta user who goes
  back to Stable simply waits for a newer stable). The default channel of an image is `beta` until
  `release/hardware-validation.json` records a real-hardware validation; the release tooling refuses to create a
  `stable` package before that — passing CI is explicitly not enough.

## Security model

| Threat | Mitigation |
|---|---|
| Manipulated package or manifest on GitHub / MITM | Ed25519 signature over the manifest with a key pinned in the image; package hash inside the signed manifest; HTTPS only to GitHub hosts (redirect-checked) |
| Replay of an old release | only versions newer than installed are offered |
| Malicious archive (path traversal, links, bombs) | strict unpacker, size/file-count budgets, validation before activation |
| Web UI / compromised backend triggering updates | unix socket `0660 root:pios`, caller uid checked (`SO_PEERCRED`); backend endpoints admin-only; the Update Manager only installs signed releases anyway |
| Private key leakage | signing key lives only in the GitHub secret `PIOS_UPDATE_SIGNING_KEY` (and a local 0600 copy on the maintainer's machine); never in the repo, image, logs or artifacts (masked, only used in the signing step) |
| Concurrent updates | in-process mutex + `flock`; UI disables actions while a job runs |

Not covered: key rotation by OTA (the Update Manager and the trusted keys ship in the image; a new key needs a new
image or a future "core update" mechanism), a compromised GitHub account/secret (revoke by publishing a new image with a new
key), OS-level vulnerabilities.

## Publishing a release (maintainers)

1. Bump `__version__` in `pios/__init__.py` (and `DB_SCHEMA` + a `MIGRATIONS` entry if the schema changes). Write `release/NOTES.md`.
2. `git tag v0.2.1-beta.1 && git push --tags` → workflow `release.yml`: tests, tag/version check, package, sign (masked secret),
   verify with the repo's public key, publish a **pre-release** (`beta`). Plain `vX.Y.Z` is `stable` and is rejected until
   `release/hardware-validation.json` is filled in after a real-device test.
3. Image: run *Build PiOS image* and attach `PiOS-NOVA-arm64.img.xz` to the same release.

The workflows currently live in `ci/workflows/` because the token used for development lacks the `workflow` scope;
copy them to `.github/workflows/` (`gh auth refresh -s workflow`, then `git mv`).

Local dry run: `python scripts/release_tool.py package --channel beta --out dist` / `sign` / `verify`.

## Migration of existing images

Images built before 0.2.0 have no Update Manager and a different directory layout (`/opt/pios/pios`). A one-time
in-place migration would need a privileged step on the device (SSH or console), which these images deliberately do not
provide. **Flash a 0.2.0+ image once**; all later updates are OTA. The data in `/var/lib/pios` of an old install is
compatible (schema 1) if you copy it over, but that is manual and untested.

## Known limits

* `pios-updater.service` runs as root with moderate systemd hardening only; tighter capability sets need hardware tests.
* The Update Manager itself and the trusted keys are not OTA-updatable (by design).
* No delta updates; whole packages are downloaded (~ a few MB).
* Automatic installation of updates is not implemented (only checking and notifying).
