# Security audit (NOVA Shield 0.3.0)

Scope: PiOS Core (FastAPI), authentication/sessions, files/uploads, app registry + SDK + sandbox, systemd units and Linux
permissions, HDMI kiosk/Chromium, Update Manager, GitHub Actions, image build, dependencies.
Method: code reading, **exploit-style regression tests** (`tests/security/test_audit_findings.py`: 16 tests failed against the
0.2.0 code and pass now), bandit, pip-audit, and running the hardened units under real systemd.

Dependency scan: `pip-audit -r requirements.txt` → no known vulnerabilities (2026-10-26). `bandit -ll` on `pios`, `pios_updater`,
`scripts`: 1 high (SHA-1 used as a change-detection hash in the SSE stream → replaced by SHA-256), 4 medium (string-built SQL with
internal constants → rewritten; `chmod` of the control sockets / unpacked files and `urlopen` of a fixed loopback URL are intentional).
The Debian packages in the image are the distribution's; they are kept current by `pios-os-upgrade` (see SHIELD.md).

| ID | Severity | Finding | Impact | Evidence | Fix |
|---|---|---|---|---|---|
| F-01 | **High** | No `Host` header validation | DNS-rebinding / host-header attacks against the unauthenticated endpoints (setup, health) and cache poisoning behind a proxy | `test_f01_*` | `HostGuard`: only IP literals, `localhost`, `pios.local`, the hostname and `PIOS_ALLOWED_HOSTS` (421 otherwise) |
| F-02 | **High** | Request bodies unbounded; upload limit enforced only *after* the whole multipart body was spooled to `/tmp` | Memory/disk exhaustion by any LAN client **before authentication** (e.g. 10 GB POST to `/api/login`) | `test_f02_*` | `BodyLimit` ASGI middleware: 2 MiB for API calls, `MAX_UPLOAD` (+overhead) for uploads, 12 MiB for SDK; checks `Content-Length` and counts streamed/chunked bytes; default upload limit 4 GiB → 2 GiB |
| F-03 | **High** | Capability tokens survived logout, session revocation, password change, app removal and revocation of a permission (valid for 1 h, permissions frozen at issue time) | A stolen/leaked token or a revoked app kept working | `test_f03_*`, `tests/security/test_app_permissions.py` | Tokens are bound to the session; every SDK call re-checks session, app registration and the **current** grants in the database (`app_grants`); new permissions of an updated app are *not* auto-granted |
| F-04 | Medium | No idle timeout (7-day absolute expiry only) | An unattended logged-in browser stayed valid for a week | `test_f04_*` | Sliding idle timeout (12 h browsers / 14 d HDMI kiosk), 14-day absolute limit |
| F-05 | Medium | Filename spoofing: bidi overrides (U+202E), zero-width and format characters accepted | `invoice‮fdp.exe` displays as `invoiceexe.pdf` | `test_f05_*` | Reject Unicode categories Cc, Cf, Cs, Co, Cn, Zl, Zp in all names |
| F-06 | Low | Missing `Permissions-Policy`, `Cross-Origin-Opener/Resource-Policy` | Weaker isolation of the shell and of API responses | `test_f06_*` | Added; shared public assets (`/apps`, `/sdk`, `/css`) use `CORP: cross-origin` so sandboxed apps can load them |
| F-07 | Low | No per-user disk quota | One user can fill the SD card | `test_f08_*` | Default 16 GiB per user (`PIOS_USER_QUOTA`), checked while streaming; usage cached (no O(n) walk per request) |
| F-08 | Medium | `pios.service` only partially sandboxed (no syscall filter, no W^X, no resource ceilings) | Larger blast radius after a hypothetical RCE | `tests/test_service_hardening.py` | Added `SystemCallFilter`, `MemoryDenyWriteExecute`, `ProtectProc`, `ProtectKernel*`, `CapabilityBoundingSet`, `MemoryMax`, `TasksMax`; **verified by running the unit under real systemd** (CapEff = only `CAP_NET_BIND_SERVICE`, seccomp 2, NoNewPrivs 1) |
| F-09 | Medium | Kiosk Chromium unrestricted (any URL, DevTools, downloads, extensions) | A bug in PiOS or a malicious link could browse the web in a full-screen kiosk | `test_chromium_policy_*` | Managed policy: only `http://127.0.0.1/*`, no DevTools/downloads/extensions/sync, no remote debugging; sandbox never disabled; unit hardened |
| F-10 | Medium | No firewall on the device | Every service on the Pi reachable from the LAN (and, if forwarded, the internet) | `tests/firewall` | nftables default-deny inbound, see SHIELD.md |
| F-11 | Low (design) | No tamper evidence for security events; security events not logged at all | Attacks (brute force, denied app calls) invisible | `tests/security/test_audit_log.py` | Hash-chained audit log + journald copy |
| F-12 | Info | Setup endpoint exempt from the setup code on loopback | Anyone with physical access to the HDMI kiosk can create the admin | by design | documented; code required for every remote client; attempts rate-limited and audited |
| F-13 | Info | `ClamAV` signature download failed without `ca-certificates` | scanner silently stale | observed in the container test | `ca-certificates` is a hard package dependency of the image; status shows stale/missing signatures |
| F-14 | Info (open) | No TLS | Passwords and session cookies cross the LAN in clear text | – | **Not fixed in 0.3.** Design decision in SHIELD.md ("HTTPS"); do not expose PiOS to untrusted networks |
| F-15 | Info (open) | `pios-updater.service` runs as root with moderate sandboxing | Compromise of the updater = root | – | Accepted for 0.3: it only installs signed releases; further tightening needs hardware tests |

Not found / verified OK: SQL injection (all queries parameterised), path traversal in files/SDK/app assets (component-wise
validation, symlinks refused), stored XSS (UI builds DOM with `textContent`; strict CSP without inline code), CSRF (custom header +
Origin check, SameSite=Strict), session fixation (new random token per login), user enumeration timing (dummy hash verified),
brute force (per IP and per user, exponential lock, audited), secrets in repository/history (none; public repo), unsafe workflow
triggers (no `pull_request_target`, no secrets in PR workflows).
