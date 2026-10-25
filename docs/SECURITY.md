# Security model (0.1)

Target: a trusted home LAN. **Not** hardened for the open internet (no TLS).

| Area | Measure |
|---|---|
| Passwords | Argon2id (argon2-cffi defaults), minimum 12 characters, rehash on login, constant-time-ish verification for unknown users |
| Sessions | 48-byte random token, only its SHA-256 stored; `HttpOnly`, `SameSite=Strict`, 7-day expiry; all other sessions revoked on password change; session list + revoke in Settings |
| Brute force | 5 failures per IP *and* per username → exponential lock (30 s … 15 min, HTTP 429), persisted in SQLite; setup code attempts are limited the same way |
| First run | Remote setup needs a random 8-character code only visible on the HDMI console / boot partition; loopback (HDMI kiosk) is exempt |
| CSRF | Every mutating `/api` request needs `X-PiOS: 1` (cannot be sent cross-site without CORS preflight, which is never allowed) and a matching `Origin` if present |
| Authorization | Every `/api` route except setup/login depends on `current_user`; admin routes on `admin_user`; all data queries are scoped `WHERE uid=?` |
| Files | Paths validated component-wise, symlinks refused, result must stay inside the per-user root, 255-byte names, no control characters; uploads streamed with size and free-space limits; inline display only for a safe MIME allow-list (HTML/SVG are always downloads) with `CSP: sandbox` |
| Browser | CSP `script-src 'self'; style-src 'self'` (no inline code), `frame-ancestors 'none'`, `nosniff`, `no-referrer` |
| Apps | Third-party code runs only in `sandbox="allow-scripts"` iframes (opaque origin) with CSP `connect-src 'none'`. Server-side capability tokens (HMAC, 1 h) carry the manifest's permissions; the server enforces them. Per-app storage quota. |
| OS | `pios.service` runs as unprivileged `pios` with `ProtectSystem=strict`, `NoNewPrivileges`, only `CAP_NET_BIND_SERVICE`, private `/tmp` and `/dev`; the kiosk runs as separate `pios-kiosk`; no SSH unless enabled in Imager; no default login password |

## Known limits

* No TLS: credentials and session cookies cross the LAN in clear text. Do not use on untrusted networks.
* An attacker with physical access can read the SD card; data is not encrypted at rest.
* App permission consent is declared in manifests and shown in Settings; there is no per-install prompt yet (only bundled
  apps exist in 0.1).
* The login lock is keyed by IP and username; many different IPs against one username lock that username (denial of
  service is possible by design, it is only temporary).
* No independent security audit has been done.
