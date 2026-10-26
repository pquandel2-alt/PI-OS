# Netzwerk & Geräte — Connectivity & Hardware Manager (0.3)

Settings → **Netzwerk & Geräte** (and the dock app of the same name) manages Wi-Fi, Ethernet, Bluetooth, connected input devices and
hardware/drivers. Everything shown comes from NetworkManager, BlueZ, sysfs, udev, libinput and logind on the device; nothing is simulated.

> **Honest status:** the code is tested against simulated D-Bus daemons (python-dbusmock `networkmanager` / `bluez5`), a fake sysfs/procfs
> tree and a scripted daemon in the browser tests. **None of it has been run against real Wi-Fi, Bluetooth or USB hardware yet.**
> The list of hardware tests that are still open is at the end of this file.

> **Image build:** run 40325784778 (2026-10-26) built the image and passed 112 automated image checks (incl. NetworkManager/BlueZ/firmware, `pios-connd` unit limits, software-cursor setting). The emulated boot test still does not work on the CI runner, so this does not prove that the Pi 5 boots.

## Architecture

```
Browser / HDMI kiosk ── /api/net · /api/bt · /api/hw ──► pios.service (user pios, no privileges)
                                                              │ unix socket, SO_PEERCRED uid check, JSON verbs
                                                              ▼
                                  pios-connd.service (root, CAP_NET_ADMIN + CAP_SYS_PTRACE + CAP_DAC_READ_SEARCH only)
                                   ├─ NetworkManager D-Bus  (devices, scan, connect, profiles, WirelessEnabled)
                                   ├─ BlueZ D-Bus           (adapter, discovery, pairing agent, devices)
                                   ├─ sysfs / procfs / udev db / libinput / loginctl (read-only evidence)
                                   └─ pios-sysops (pkg.install: allow-listed firmware packages, version-pinned)
```

* The backend (`pios/connectivity.py`) is a thin gateway: strict pydantic models (`extra=forbid`, length limits), admin-only for everything that
  changes state or reveals hardware identifiers, CSRF header on every mutation, audit entry per change. Ordinary users get a **read-only summary**
  (online/offline, SSID, signal, connected Bluetooth names, hardware names — no MAC addresses, serial numbers, saved networks or pending details).
* `pios-connd` accepts a fixed verb table, validates every argument (`pios_connd/validate.py`: SSID ≤ 32 bytes without control characters,
  PSK 8–63 printable ASCII or 64 hex, interface and MAC formats, UUIDs, country allow-list), never builds shell strings (commands are argument lists)
  and never returns internal exception text. Unexpected errors are logged without arguments and answered generically.
* **Secrets:** a Wi-Fi password travels browser → backend → connd → NetworkManager D-Bus call as an argument. It is not stored by PiOS, not written to the
  audit log or journal, not part of any URL, and the request-validation error handler never echoes submitted values. In the browser the input is
  removed from the DOM right after sending; no storage is used. NetworkManager stores the PSK in its own root-only profile (`/etc/NetworkManager/system-connections`, 0600).
  Not covered: someone with root on the device or network sniffing the plain-HTTP LAN connection (see SECURITY.md → no TLS).
* **No root for third-party apps:** sandboxed apps have no connectivity permission; the API is admin-session only.

## Wi-Fi

Scan (SSID, signal, band, security), connect (WPA2-PSK, WPA3-SAE, WPA2/WPA3 mixed, OWE, open networks with a warning; hidden SSID),
saved networks (auto-connect toggle, forget), disconnect, IP/gateway/DNS display, understandable errors (wrong password, no response, DHCP failed …).
Unsupported: WEP (refused with explanation) and WPA-Enterprise/802.1X (shown, not connectable yet).

* **Regulatory domain.** Raspberry Pi OS ships with the Wi-Fi radio **off** until a country is set (`WirelessEnabled=false`, `rfkill.default_state=0`).
  On first start `pios-connd` sets the image default country **DE** (overridable with the environment variable `PIOS_WIFI_COUNTRY` of `pios-connd`), persists it
  (`/etc/modprobe.d/pios-regdom.conf` → `cfg80211 ieee80211_regdom=`), applies it (`iw reg set`), unblocks rfkill and enables Wi-Fi — exactly once;
  later the user's choice is respected. The country is changeable in the UI (allow-list of country codes, never `00`).
* A failed connection removes the half-created profile again, so a wrong password does not leave a broken saved network behind.

## Lock-out protection (automatic rollback)

Changing the network over the network can lock you out. `pios_connd/netguard.py`:

1. identifies the **interface the administrator is using** (`ip -j route get <client IP>`; the HDMI kiosk on loopback is exempt),
2. if a change touches that interface (switch Wi-Fi, switch Ethernet to DHCP, Wi-Fi off, disconnect), applies it **provisionally** and keeps an undo record
   (persisted in `/var/lib/pios-connd/pending.json` so it survives a daemon restart),
3. shows a banner in every NOVA window for admins ("Netzwerkänderung bestätigen — wird in 60 s automatisch zurückgenommen"). Open PiOS on the new address
   and press **Bestätigen**; otherwise the undo runs (previous profile re-activated, new profile deleted, Wi-Fi radio restored, previous IPv4 method restored),
4. reverts immediately when the connection attempt itself fails, and on daemon restart while a change is pending,
5. refuses to forget the network that currently carries the administrator.

**Ethernet:** shows link, speed, MAC, IP/gateway/DNS and can switch to **DHCP**. Static IPs are deliberately *not* offered yet; they come only with this
protection proven on hardware.

## Bluetooth (BlueZ)

Controller status and power, scan (limited to 60 s; PiOS is never discoverable), pair, connect/disconnect, trust, remove — mice, keyboards, headphones,
speakers first; classic and LE. Pairing uses a registered BlueZ **agent** that exists only for a pairing the administrator started:

* confirmation (numeric comparison), PIN and passkey requests become a dialog with a countdown (60 s), answered by the admin or rejected on timeout;
* a pairing request nobody started is rejected and logged (`bt.pairing_rejected_unsolicited`), service authorisations for unknown devices are rejected;
* only one pairing at a time; the adapter is `Pairable` only during a pairing; cancel is available.

## Mouse / input diagnosis ("Verbundene Geräte → Diagnose")

`pios_connd/inputdiag.py` checks layer by layer and reports the **first layer that breaks**:
USB enumeration → kernel driver binding (usbhid / hid-generic / btusb / hid_logitech_dj …) → input device (`/proc/bus/input/devices`) → udev classification
(`ID_INPUT_MOUSE`, seat tags) → permissions/ACL for the kiosk user → libinput (`libinput list-devices`) → logind session of the kiosk → compositor
(cage has the `/dev/input/event*` files open, via `/proc/<pid>/fd`) → cursor environment.

Candidate causes for "wireless mouse does not work" on the first Pi 5 test, all handled or made visible:

| Cause | Handling |
|---|---|
| **Invisible cursor** (hardware cursor plane on vc4/Pi 5: the mouse works but no pointer is drawn) | `pios-kiosk.service` now sets `WLR_NO_HARDWARE_CURSORS=1` (software cursor). The old unit forced `=0`. Diagnosis flags it. |
| **Bluetooth mouse not paired** — no Bluetooth UI existed | Bluetooth page. |
| **Bluetooth off / blocked by rfkill** | shown, power toggle, rfkill state. |
| **Unifying/Bolt dongle** needs `hid_logitech_dj` or only the receiver node exists | driver binding stage names the bound driver and lists dongle interfaces without driver. |
| **Dongle without driver / firmware** | USB interface without driver is reported; kernel log hints appear in the diagnosis. |
| **Permissions**: kiosk user cannot read the event node | permission/ACL stage (kiosk user is in `input,video,render`; logind `uaccess` rules also apply); no world-writable workaround is ever applied. |
| **No logind session** for `pios-kiosk` | session stage (`PAMName=login` is set in the unit). |
| **Hot-plug**: device added after cage started | cage keeps watching udev; the stage checks whether the compositor holds the node open. |

The diagnosis reads only; it never changes permissions. If a stage fails the UI shows evidence and a plain-language cause.

## Hardware & drivers

Inventory: Pi model/revision, CPU, RAM, kernel, bootloader build, USB devices (vendor/product, driver per interface), input devices, network
adapters (driver, link), Wi-Fi, Bluetooth controllers, audio, displays (EDID name/mode), storage; problems = USB interfaces / adapters without driver.
Refresh is periodic (5–8 s while the page is open) and `connd` emits hot-plug events (USB add/remove, network and Bluetooth changes) that become notifications.

**Driver/firmware detection** (`pios_connd/drivers.py`): (1) scan the kernel log for `Direct firmware load for X failed`, (2) map the file to candidate
packages with a curated table, (3) ask `apt-cache policy` whether the package exists, which version, and whether **all** candidate origins are official
(Debian / Raspberry Pi archives), (4) only packages in `pios_sysops/packages.py` (`ALLOWED`) are installable. The UI shows package, version and source,
asks for confirmation (a reboot or driver reload is needed afterwards), and the install runs through `pios-sysops` → `pios-pkg-install@.service` under the
shared package lock with the **exact confirmed version** (changed candidate → refused). Unknown devices get an explanation only: no downloads from GitHub,
no scripts from the web, no automatic installation, no kernel modules from outside the distribution.

## NOVA Shield integration

* Audit/security events: `net.wifi_connect`, `net.wifi_radio`, `net.wifi_forget`, `net.ethernet_dhcp`, `net.change_confirmed/reverted`, `bt.pair_started/answered`,
  `bt.trust`, `bt.remove`, `bt.pairing_rejected_unsolicited`, `bt.service_rejected`, `hw.package_install`, `hw.package_refused` (failed privileged action), plus daemon events
  (`net.change_pending`, pairing failures, USB add/remove as notifications). Passwords, PINs and passkeys are never logged.
* Shield check **"WLAN, Bluetooth & Eingabegeräte"**: unreachable helper → *Status unbekannt* (never "geschützt"); NetworkManager/BlueZ not running → *eingeschränkt*;
  findings from real observations: no Wi-Fi country set, auto-connect to an open Wi-Fi, permanently discoverable or unsolicited-pairable Bluetooth adapter, pending
  unconfirmed network change.

## What can be updated how

| Component | Update path |
|---|---|
| `pios/connectivity.py` (API gateway), Shield check, all web UI (`web/js/apps/network.js`, tray, banner), app manifest | **OTA** (Update Center) |
| `pios_connd/*`, `pios-connd.service`, `pios-pkg-install@.service`, `pios_sysops` changes, kiosk unit (`WLR_NO_HARDWARE_CURSORS`) | **new image** — helpers live outside the OTA tree on purpose |
| NetworkManager, wpa_supplicant, BlueZ, firmware, libinput, kernel | **new image or Debian/Raspberry Pi OS package updates** (OS security updates via Shield; firmware packages via the driver manager) — OTA packages never touch OS packages or the kernel |

An existing 0.2 image therefore needs one new image (this release) before the connectivity UI works; its API answers 503 ("pios-connd nicht erreichbar") until then.

## Image changes (kept minimal)

New packages: `network-manager`, `wpasupplicant`, `wireless-regdb`, `iw`, `rfkill`, `bluez`, `pi-bluetooth`, `libinput-tools`, `usbutils`, `python3-dbus`, `python3-gi`,
`firmware-brcm80211`, `firmware-realtek`, `firmware-mediatek` (Pi OS already carries most of these; listing them makes the image checks explicit).
`NetworkManager` and `bluetooth` are enabled, `pios-connd` is enabled. No udev rule, group or permission is widened; `verify-image.sh` checks for world-writable input/rfkill rules.

## Tests

| Layer | How | Where |
|---|---|---|
| Validation, guard, hardware parsing, input diagnosis | unit tests with fake sysfs/procfs/udev trees and recorded command output | `tests/connd/test_*.py` |
| NetworkManager client | python-dbusmock `networkmanager` on a private system bus (real D-Bus) | `tests/connd/test_nm.py` |
| BlueZ client + pairing agent | python-dbusmock `bluez5` | `tests/connd/test_bluez.py` (run by `scripts/test-connd.sh` in its own process) |
| connd daemon verbs, rollback, first run, socket server | mock NM + fake hw | `tests/connd/test_connd.py` |
| Sandbox | real `pios-connd` under real systemd with the unit's properties: `CapEff`, seccomp, D-Bus, hw inventory, input diagnosis | `tests/connd/test_connd_hardening.py` (needs sudo + systemd) |
| Backend gateway | scripted connd on a unix socket: admin-only, redaction, secret handling, error mapping, events | `tests/connectivity/test_gateway.py` |
| Browser UI | Chromium/Playwright against the real backend + scripted connd | `tests/e2e/test_ui.py` (`test_network_*`, `test_bluetooth_*`, …) |

## Still to test on a real Raspberry Pi 5

1. Wi-Fi: onboard radio comes up after first boot (country DE), scan, WPA2/WPA3 connect, hidden SSID, wrong password, saved networks, forget, roaming; **lock-out rollback while connected via Wi-Fi** (change the network from a phone/laptop and don't confirm).
2. Ethernet ↔ Wi-Fi switch of the admin interface, DHCP switch rollback.
3. Bluetooth: onboard controller, pair/connect a **Bluetooth mouse**, keyboard (PIN/passkey flow), headphones; reconnect after reboot; unsolicited pairing request is rejected.
4. **USB wireless mouse/keyboard dongle** (e.g. Logitech Unifying/Bolt, generic 2.4 GHz): works in the HDMI kiosk; the diagnosis result matches reality; the software cursor is visible.
5. `pios-connd` under its sandbox on arm64 (capabilities, seccomp, reading `/proc/<cage>/fd`, `iw reg set`, `journalctl -k`).
6. cage/logind: kiosk session, hot-plug of mouse/keyboard after boot, seat ACLs (`uaccess`).
7. Driver manager: a USB Wi-Fi/Ethernet adapter that needs firmware; `apt-cache policy` origin strings on Pi OS; install + reboot flow.
8. Firewall interplay: mDNS, DHCP and Wi-Fi roaming still pass; auto-revert works over Wi-Fi.
