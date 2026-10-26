# NOVA Shield 0.3 — security architecture

NOVA Shield is not a dashboard on top of nothing: every status comes from a real check, every control is wired to an enforcing
component, and a protection that was not verified is never shown as active. Results of the audit: [SECURITY_AUDIT.md](SECURITY_AUDIT.md).

## Components

| Component | Runs as | Privileges | Purpose |
|---|---|---|---|
| `pios.service` (backend) | `pios` | only `CAP_NET_BIND_SERVICE`, seccomp, no W+X, MemoryMax 900 M | web UI, API, quarantine pipeline, audit log |
| `pios-firewall.service` | root, group pios | **only `CAP_NET_ADMIN`**, seccomp, no W+X | the only thing that may change nftables |
| `pios-sysops.service` | root, group pios | **no capabilities** | starts/stops a fixed set of units (clamd, signature update, OS check/upgrade) |
| `pios-updater.service` | root, group pios | moderate sandbox | signed OTA updates ([UPDATES.md](UPDATES.md)) |
| `pios-kiosk.service` | `pios-kiosk` | none, NoNewPrivileges, own profile | cage + Chromium on HDMI |
| `pios-os-check/-upgrade.service` | root (oneshot) | APT | Debian security updates, under the shared package lock |
| `pios-clam-update.service`, `clamav-daemon` | `clamav` | CPU/RAM-limited | signatures / on-demand scanner |

The three helpers talk over unix sockets (`root:pios 0660`), check the caller's uid with `SO_PEERCRED`, accept a handful of verbs, validate
all input strictly and **never** execute client-supplied text (the firewall accepts a structured policy and renders the nftables script
itself; sysops maps verbs to fixed unit names). The web UI cannot run shell commands as root.

Hardening is **proven, not asserted**: `tests/firewall/test_unit_hardening.py`, `tests/shield/test_sysops_hardening.py` and
`tests/test_service_hardening.py` start the real services under real systemd with exactly the sandbox of the unit files (transient
units in throw-away network namespaces) and check `CapEff`, seccomp and functionality (login, upload, psutil, nft apply/confirm, unit start).

## Security status model

`GET /api/shield` evaluates ten checks (firewall, virus protection, app sandbox, service hardening, signed PiOS updates, OS updates,
sign-ins, audit-log integrity, browser hardening, transport). Each returns one of `ok / info / unknown / limited / attention / critical`;
the overall state is the **worst** one:

| State | Meaning |
|---|---|
| **Geschützt** | every check ran and passed |
| Status unbekannt | a required check could not run (helper not reachable, never checked) — never shown as protected |
| Eingeschränkt geschützt | a protection is off/stale/not ready (virus protection disabled, no signatures, SSH open, check older than 3 days …) |
| Aufmerksamkeit erforderlich | action needed (security updates pending, reboot required, threat in quarantine, rejected update signature, failed update, firewall change unconfirmed) |
| Kritisches Problem | core protection broken (firewall not active/tampered, sandbox headers wrong, process runs as root without sandbox, audit log tampered, APT signature failure, unsafe Chromium flags) |

## Firewall

* nftables table `inet pios_fw` (IPv4 + IPv6), only this table is replaced (`add table; delete table; table …` is idempotent and leaves
  Docker/NetworkManager tables alone). Input policy **drop**, forward **drop**, output accept.
* Allowed inbound: loopback, established/related, ICMPv6 neighbour discovery / path-MTU / MLD (IPv6 breaks without them), ICMP errors,
  DHCP/DHCPv6 *replies* (udp 67→68, 547→546 only), tcp/80 from the allowed source set, optional mDNS (`pios.local`), optional rate-limited ping,
  optional SSH. Everything else is dropped (rate-limited log line `pios-fw drop:`).
* "Allowed source set" = private/CGNAT/link-local ranges plus the host's own on-link prefixes (global IPv6 /64s are detected and refreshed every 2 min;
  `web_scope: custom` restricts to explicit CIDRs; `/0` is refused).
* **Lock-out protection:** every change is validated (`nft -c` dry run), applied atomically, and reverts by itself after 60 s unless the admin confirms
  from the new connection. Only a confirmed policy is persisted (`/var/lib/pios-firewall/config.json`); after a reboot the persisted policy (or the
  built-in default) is loaded — an unconfirmed change never survives.
* `verify_live` compares the **kernel's** ruleset with the configuration (policies, open ports) and reports drift, so NOVA Shield detects tampering.
* Tested with real traffic between network namespaces: web reachable over IPv4 and IPv6, nothing else, public source blocked, auto-revert,
  persistence across a simulated reboot, tamper detection (`tests/firewall`).

## Malware protection (ClamAV, on demand)

**Measured** (ClamAV 1.4.3, Debian trixie, x86-64, full signature set 108 MB: main 89 MB, daily 23 MB, 28164 signatures DB version):
clamd takes ~18 s to become ready and holds **≈ 990 MB RSS (peak 1015 MB)** permanently — roughly 10 % of a 8 GB Pi and over 25 % of a 4 GB Pi. Therefore
clamd is **not** resident: `pios-sysops` starts it when files wait for a scan and stops it after 5 idle minutes (`MemoryHigh 1.6 G`, `OOMScoreAdjust 500`,
`CPUQuota 70 %`, `Nice 15`, `ConcurrentDatabaseReload no` to avoid doubling RAM on reload). On a Pi 5 expect a slower start (estimate 30–60 s, **not yet measured**);
a Pi with 2 GB RAM should keep protection off or accept that scans can fail (fail-closed). Disk: signatures ≈ 110 MB; the image ships **no** signatures
(they would be stale) — `pios-clam-update.timer` downloads them 4 min after boot and daily, `ca-certificates` required. Scan speed measured: 64 MB random data 6 s, small files ≈ 20 ms each.

Upload pipeline: stream to `DATA/quarantine/<id>` (dir 0700, files 0600, never executable) → size/name/magic-number check (an ELF/PE/script named `.jpg/.pdf/…`
is **blocked**) → scan (`FILDES`: the open descriptor is passed to clamd, no copy, no size limit beyond `max_scan_mb`) → clean: atomically moved into the user's tree
(name conflicts get a suffix) / infected: stays locked, audited as critical, notification to user + admins / error or scanner unavailable: **held (fail-closed)**.
Policy `allow_unscanned` (explicit, confirmed, audited) releases files but records them as **NICHT geprüft**; with protection switched off the upload response says
`released_unscanned_disabled` — the UI never claims a scan that did not happen. Infected files found by a scan of existing files are *moved* to quarantine (never deleted);
there is deliberately **no** manual release of detected malware in 0.3, only deletion. Limits: `max_scan_mb` (default 1024), quarantine cap 4 GiB, clamd `AlertExceedsMax yes`
(archive bombs are flagged instead of silently passing). Weekly scan: Sunday after 03:30, only if the load average is < 1.5. Verified with the EICAR test file against a **real** clamd,
including EICAR inside ZIP and GZIP (`tests/shield/test_real_clamav.py`, run with `PIOS_REAL_CLAMD=<socket>`) and against a protocol-exact fake in the default test run.

## Apps and permissions

Third-party code never runs in the backend. Web apps run in `sandbox="allow-scripts"` iframes (opaque origin, CSP `connect-src 'none'`), talk to the shell via a validated
`postMessage` bridge (sender window checked, message schema checked, 200 calls/s cap) and reach data only through `/api/sdk/*` with a **session-bound capability token**.
The server re-validates on **every** call: token signature, session alive, app still registered, and the permission currently granted (`app_grants`). Therefore logout,
session revocation, password change, uninstall and permission revocation take effect immediately (tests: `tests/security/test_app_permissions.py`).
Bundled apps receive their requested permissions on first start (`granted_by = system:bundled`); a new version asking for more gets the extra permissions *pending* until an admin grants them
in NOVA Shield → Apps. App data are separate (`app_kv` per app+user, `Apps/<id>/` folder with `files.app`). Not part of 0.3: apps with backend processes (they would need per-app OS users and cgroup limits);
the manifest has no `backend` key and the registry rejects non-sandboxed apps from the apps directory. A future *permission manager* and the planned **NOVA Browser** / **NOVA AI** apps plug into the same grant table
(new permission names, e.g. `network.fetch:<host>`, `ai.chat`), enforced server-side the same way.

## Browser hardening (HDMI kiosk)

Chromium runs as `pios-kiosk` (never root) with its sandbox **enabled** (no `--no-sandbox`), no debugging port, profile directory 0700, `umask 077`, and the managed policy
`/etc/chromium/policies/managed/pios.json`: only `http://127.0.0.1/*` may load, DevTools off, downloads blocked, no extensions, no sync/password manager, no sensors/USB/serial/geolocation.
NOVA Shield flags unsafe flags or a missing policy. A future NOVA Browser must run as a separate unit/user with its own profile and a separate policy — never inside the kiosk session — so web content can never reach PiOS system APIs.
Chromium security updates: Chromium from the Raspberry Pi archive is included in the automatic security origins (see below). **Must be verified on the device**: that the policy is read (`chrome://policy`), that the sandbox starts under the unit, and the exact archive origin string.

## Updates: PiOS vs. operating system

* **PiOS application:** signed releases via the Update Manager (Ed25519, pinned key), application rollback only.
* **Debian/APT:** `pios-os-check` (daily; `apt-get update` verifies repository signatures; failures are classified; insecure source options are flagged) and
  `pios-os-upgrade` (daily, toggle in Shield) using `unattended-upgrades` restricted to Debian-Security + the Pi archive, **blacklisting** kernel, firmware, bootloader, libc, systemd and NetworkManager; never reboots
  (Shield shows "Neustart erforderlich"). Both jobs and the OTA installer take `/run/pios-pkg.lock`, so they never run package operations concurrently (test: `test_ota_install_refuses_while_apt_holds_the_package_lock`).
* A PiOS rollback does not undo OS updates, and the UI says so; there is **no OS rollback**.

## Audit log

SQLite table with a hash chain (each entry hashes its predecessor): removal/modification is detected by `verify()` and shown as *critical* in Shield. Copies go to the journal.
Recorded: sign-in success/failure/lock-out, setup, password changes, user and session changes, permission changes and denied app calls (1/min per app+permission), firewall apply/confirm/revert,
malware detections/blocks/unscanned releases/settings, scan runs, update requests/failures/rejected signatures, OS update requests. Never recorded: passwords, cookies, tokens, file contents (keys containing
password/token/cookie/secret/session/key/code/hash are dropped, values truncated to 400 chars). Retention: 20 000 entries / 365 days (older entries are pruned; an anchor hash keeps the chain verifiable).
Read-only for admins; no API can edit or delete entries. Limit: an attacker with code execution *as the backend user* could rewrite the database; the journald copy and the hash chain make that detectable, not impossible.

## HTTPS decision

Not implemented in 0.3 (open risk F-14). The chosen design for 0.4: a **per-device local CA** created on first boot by a root helper (CA key 0600 root-only, never leaves the device), a server certificate for `pios.local`, hostname and
IP addresses, port 443 with HSTS, the CA certificate downloadable from the setup screen with its fingerprint shown on the HDMI console, so each client installs trust *once* and real certificate validation stays on (the loopback kiosk keeps plain HTTP,
which never leaves the device). Rejected: self-signed certificates that train users to click through warnings, Let's Encrypt (needs a public DNS name, DNS-01 credentials and exposes internal names), `--ignore-certificate-errors`.
Until then: use PiOS only on a trusted LAN, VPN for remote access, never port-forward (the firewall already blocks non-private source addresses).

## Resource usage

Backend 55 MB RSS and ~0.5 % of one core while idle (x86 dev machine); firewall/sysops daemons are small Python processes (< 25 MB each, idle); clamd ≈ 1 GB only while scanning; nftables has no userspace cost;
Shield adds ≈ 0.6 MB source. Boot: three extra small services start in parallel; nothing scans at boot. Numbers for the Pi 5 itself are **not measured yet**.

## What must still be tested on a real Raspberry Pi 5

1. Firewall: kernel has `nf_tables` + `nft_ct`, `nft_limit`, `nft_log`; ruleset loads at boot before the network; mDNS (`pios.local`), DHCP renewals, IPv6 SLAAC/RA, NTP and Wi-Fi keep working; auto-revert works over Wi-Fi.
2. `pios-firewall`, `pios-sysops`, `pios`, `pios-updater` start under their sandbox on Pi OS (seccomp filter on arm64, MDWE with the arm64 Python/Rust wheels, `ProtectProc`).
3. ClamAV on arm64: install size, signature download at first boot, **start time and RAM on 4/8 GB**, scan throughput, behaviour when memory is short (OOM score), `clamav-daemon.service` honours the drop-in and the `AlertExceedsMax` config.
4. APT: Debian-Security + Raspberry Pi archive origin strings match (`apt-cache policy`, `unattended-upgrade --dry-run -v`), kernel/firmware really excluded, lock coordination with an OTA install.
5. Kiosk: the Chromium policy is applied (`chrome://policy`), the Chromium sandbox works under `NoNewPrivileges` + empty capability set, GPU/Wayland still work with the hardened unit, downloads/DevTools blocked, no way to leave `127.0.0.1`.
6. Boot-time and idle CPU/RAM with all services; behaviour with hot-unplugged HDMI.
7. Image security checks (`scripts/verify-image.sh`, 90+ checks) pass on the real image, and a first-boot test: no open port other than 80/5353, no default password, no SSH.
