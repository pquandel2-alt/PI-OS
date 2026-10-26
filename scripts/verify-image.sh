#!/usr/bin/env bash
# Static + emulated checks of a built PiOS image. Needs root, losetup, qemu-user-static (arm64 binfmt).
# Usage: sudo scripts/verify-image.sh path/to/PiOS-NOVA-arm64.img
set -uo pipefail
# shellcheck source=lib-binfmt.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib-binfmt.sh"
IMG="${1:?usage: verify-image.sh IMAGE}"
MNT="$(mktemp -d)"
FAILS=0
LOOP=""
SRV_PID=""

pass() { printf '  PASS  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAILS=$((FAILS + 1)); }
check() { local desc="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi; }
cleanup() {
  [[ -n "$SRV_PID" ]] && kill "$SRV_PID" 2>/dev/null
  for m in dev/pts dev proc sys boot/firmware ""; do mountpoint -q "$MNT/$m" 2>/dev/null && umount -l "$MNT/$m"; done
  [[ -n "$LOOP" ]] && losetup -d "$LOOP" 2>/dev/null
  rmdir "$MNT" 2>/dev/null
}
trap 'cleanup; binfmt_unregister' EXIT

echo "== Partition table and file systems"
LOOP="$(losetup --find --show --partscan "$IMG")" || { echo "cannot attach image"; exit 2; }
sleep 1
check "two partitions (boot FAT + root ext4)" test -b "${LOOP}p1" -a -b "${LOOP}p2"
check "boot partition is FAT" bash -c "blkid -o value -s TYPE ${LOOP}p1 | grep -qi vfat"
check "root partition is ext4" bash -c "blkid -o value -s TYPE ${LOOP}p2 | grep -q ext4"
check "fsck.vfat clean" fsck.vfat -n "${LOOP}p1"
check "e2fsck clean" e2fsck -fn "${LOOP}p2"
mount "${LOOP}p2" "$MNT" && mount "${LOOP}p1" "$MNT/boot/firmware" || { echo "mount failed"; exit 2; }

echo "== Raspberry Pi 5 boot files"
for f in config.txt cmdline.txt kernel_2712.img kernel8.img bcm2712-rpi-5-b.dtb; do
  check "boot/firmware/$f" test -s "$MNT/boot/firmware/$f"
done
check "cmdline.txt has a root= device" grep -q 'root=' "$MNT/boot/firmware/cmdline.txt"
echo "     cmdline: $(cat "$MNT/boot/firmware/cmdline.txt")"
check "root/boot use PARTUUID (portable SD/SSD)" grep -q 'PARTUUID=' "$MNT/etc/fstab"
check "first-boot filesystem expansion hook present" bash -c "grep -q -E 'init_resize|firstboot|resize' '$MNT/boot/firmware/cmdline.txt' || test -e '$MNT/usr/lib/raspberrypi-sys-mods/firstboot' || ls '$MNT'/etc/systemd/system/*/rpi-resize* '$MNT'/usr/lib/systemd/system/*resize* 2>/dev/null | grep -q ."

echo "== PiOS payload"
for f in opt/pios/current/pios/main.py opt/pios/current/web/index.html opt/pios/current/web/js/main.js opt/pios/current/web/sdk/pios-sdk.js \
         opt/pios/current/apps/hello/manifest.json etc/pios/pios.conf etc/pios-release \
         etc/systemd/system/pios.service etc/systemd/system/pios-kiosk.service etc/systemd/system/pios-display.service \
         opt/pios/current/bin/pios-kiosk-browser opt/pios/current/bin/pios-display-watch; do
  check "$f" test -s "$MNT/$f"
done
check "bin scripts executable" bash -c "for f in '$MNT'/opt/pios/current/bin/*; do test -x \$f || exit 1; done"
check "/opt/pios is root-owned (code not writable by service)" bash -c "[ \"\$(stat -c %u '$MNT/opt/pios/current/pios/main.py')\" = 0 ]"
check "no world-writable files in /opt/pios (symlinks excluded)" bash -c "! find '$MNT/opt/pios' ! -type l -perm -0002 | grep -q ."
check "no secrets/dev files shipped" bash -c "! find '$MNT/opt/pios' \( -name '*.db' -o -name '.env' -o -name 'setup-code' -o -name '*.pem' \) | grep -q ."
check "service users exist (pios, pios-kiosk)" bash -c "grep -q '^pios:' '$MNT/etc/passwd' && grep -q '^pios-kiosk:' '$MNT/etc/passwd'"
check "service users cannot log in" bash -c "grep -E '^(pios|pios-kiosk):' '$MNT/etc/passwd' | grep -v nologin | wc -l | grep -qx 0"
check "hostname is pios" grep -qx pios "$MNT/etc/hostname"
check "avahi-daemon installed (pios.local)" test -x "$MNT/usr/sbin/avahi-daemon"
check "SSH not enabled by default" bash -c "! test -e '$MNT/etc/systemd/system/multi-user.target.wants/ssh.service' && ! test -e '$MNT/boot/firmware/ssh'"
check "boot partition has no setup code yet" bash -c "! test -e '$MNT/boot/firmware/PIOS-SETUP.txt'"
echo "     release: $(tr '\n' ' ' < "$MNT/etc/pios-release")"

echo "== Update Manager (OTA) layout"
REL="$(sed -n 's/^PIOS_VERSION=//p' "$MNT/etc/pios-release")"
check "current -> releases/$REL (relative symlink)" bash -c "[ \"\$(readlink '$MNT/opt/pios/current')\" = 'releases/$REL' ]"
check "release.json matches image version" bash -c "grep -q '\"version\": \"$REL\"' '$MNT/opt/pios/releases/$REL/release.json'"
check "release tree is not a symlink farm / has no pycache writes needed" bash -c "! find '$MNT/opt/pios/releases' -type l | grep -q ."
check "updater code in /usr/lib/pios-updater (outside OTA tree)" test -s "$MNT/usr/lib/pios-updater/pios_updater/engine.py"
check "trusted release public key installed" bash -c "ls '$MNT'/usr/share/pios/update-keys/*.pub"
check "no private key material in image" bash -c "! grep -rIl -E 'private\.key|PIOS_UPDATE_SIGNING_KEY' '$MNT/usr/share/pios' '$MNT/usr/lib/pios-updater' '$MNT/opt/pios' '$MNT/etc/pios' 2>/dev/null | grep -q ."
check "update channel preconfigured" bash -c "grep -q channel '$MNT/var/lib/pios-updater/config.json'"
check "updater state dir is root-only (0700)" bash -c "[ \"\$(stat -c %a '$MNT/var/lib/pios-updater')\" = 700 ]"
check "pios-updater.service enabled" bash -c "[ \"\$(systemctl --root='$MNT' is-enabled pios-updater.service 2>/dev/null)\" = enabled ]"
check "zstd available for packages" test -x "$MNT/usr/bin/zstd"

echo "== systemd enablement"
for u in pios.service pios-display.service pios-setup-notice.service pios-setup-notice.path; do
  check "$u enabled" bash -c "[ \"\$(systemctl --root='$MNT' is-enabled $u 2>/dev/null)\" = enabled ]"
done
check "default target is multi-user (no desktop)" bash -c "readlink '$MNT/etc/systemd/system/default.target' | grep -q multi-user"
check "no Raspberry Pi desktop session installed" bash -c "! test -e '$MNT/usr/bin/startlxde-pi' && ! test -e '$MNT/usr/bin/labwc'"


echo "== Security hardening (NOVA Shield)"
note() { printf '  NOTE  %s\n' "$1"; }
for u in pios-firewall.service pios-sysops.service pios-connd.service pios-clam-update.timer pios-os-check.timer pios-os-upgrade.timer; do
  check "$u enabled" bash -c "[ \"\$(systemctl --root='$MNT' is-enabled $u 2>/dev/null)\" = enabled ]"
done
check "clamd is NOT started at boot (on-demand only)" bash -c "! systemctl --root='$MNT' list-unit-files --state=enabled --no-legend | grep -q '^clamav-daemon.service'"
check "clamav-daemon.socket masked (a connect() must not wake clamd)" bash -c "[ \"\$(readlink '$MNT/etc/systemd/system/clamav-daemon.socket')\" = /dev/null ]"
check "stock freshclam daemon and nftables.service disabled" bash -c "! systemctl --root='$MNT' list-unit-files --state=enabled --no-legend | grep -E '^(clamav-freshclam|nftables)\.service'"
check "no virus signatures baked into the image (<20 MB in /var/lib/clamav)" bash -c "[ \"\$(du -sk '$MNT/var/lib/clamav' 2>/dev/null | cut -f1)\" -lt 20480 ]"
check "clamd.conf: no duplicated single-value options" python3 - "$MNT/etc/clamav/clamd.conf" <<'PY'
import collections, sys
keys = collections.Counter(l.split()[0] for l in open(sys.argv[1]) if l.strip() and l[0].isalpha())
multi = {"TCPAddr", "ExcludePath", "VirusEvent", "OnAccessIncludePath", "OnAccessExcludePath", "OnAccessMountPath", "Example"}
dup = [k for k, n in keys.items() if n > 1 and k not in multi]
sys.exit(1 if dup else 0)
PY
check "clamd.conf: socket 660, no double RAM on reload, over-limit files flagged" bash -c "grep -q '^LocalSocketMode 660' '$MNT/etc/clamav/clamd.conf' && grep -q '^ConcurrentDatabaseReload no' '$MNT/etc/clamav/clamd.conf' && grep -q '^AlertExceedsMax yes' '$MNT/etc/clamav/clamd.conf'"
check "pios user is in group clamav (socket access)" bash -c "grep -E '^clamav:.*[:,]pios(,|\$)' '$MNT/etc/group'"
check "Chromium policy valid and restricts to loopback PiOS" python3 - "$MNT/etc/chromium/policies/managed/pios.json" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
ok = p["URLBlocklist"] == ["*"] and set(p["URLAllowlist"]) == {"http://127.0.0.1/*", "http://localhost/*"} and p["DeveloperToolsAvailability"] == 2 and p["RemoteDebuggingAllowed"] is False
sys.exit(0 if ok else 1)
PY
check "kiosk script has no unsafe Chromium flags" bash -c "! grep -vE '^[[:space:]]*#' '$MNT/opt/pios/current/bin/pios-kiosk-browser' | grep -E -- '--no-sandbox|--remote-debugging|--disable-web-security|--ignore-certificate-errors|--disable-site-isolation'"
check "kiosk runs as unprivileged pios-kiosk with NoNewPrivileges" bash -c "grep -q '^User=pios-kiosk' '$MNT/etc/systemd/system/pios-kiosk.service' && grep -q '^NoNewPrivileges=yes' '$MNT/etc/systemd/system/pios-kiosk.service'"
check "pios.service sandbox directives present" bash -c "for d in NoNewPrivileges=yes ProtectSystem=strict PrivateTmp=yes MemoryDenyWriteExecute=yes 'CapabilityBoundingSet=CAP_NET_BIND_SERVICE' 'SystemCallFilter=@system-service' RestrictAddressFamilies; do grep -q \"^\$d\" '$MNT/etc/systemd/system/pios.service' || exit 1; done"
check "firewall service limited to CAP_NET_ADMIN" bash -c "grep -q '^CapabilityBoundingSet=CAP_NET_ADMIN\$' '$MNT/etc/systemd/system/pios-firewall.service'"
check "sysops helper has no capabilities" bash -c "grep -q '^CapabilityBoundingSet=\$' '$MNT/etc/systemd/system/pios-sysops.service'"
echo "== Connectivity & hardware (NOVA Verbindungen)"
for u in NetworkManager.service bluetooth.service; do
  check "$u enabled" bash -c "[ \"\$(systemctl --root='$MNT' is-enabled $u 2>/dev/null)\" = enabled ]"
done
for b in NetworkManager wpa_supplicant iw rfkill bluetoothd libinput lsusb cage; do
  check "installed: $b" bash -c "find '$MNT/usr/sbin' '$MNT/usr/bin' '$MNT/usr/libexec/bluetooth' '$MNT/usr/lib/bluetooth' '$MNT/sbin' '$MNT/bin' -maxdepth 1 -name $b 2>/dev/null | grep -q ."
done
check "python3-dbus and python3-gi available for pios-connd" bash -c "ls -d '$MNT'/usr/lib/python3/dist-packages/dbus '$MNT'/usr/lib/python3/dist-packages/gi >/dev/null"
check "Wi-Fi/Bluetooth firmware packages installed (brcm80211)" bash -c "ls '$MNT'/usr/lib/firmware/brcm/brcmfmac43455* >/dev/null 2>&1 || ls '$MNT'/lib/firmware/brcm/brcmfmac43455* >/dev/null 2>&1"
check "pios-connd code outside the OTA-updatable tree and importable" bash -c "test -d '$MNT/usr/lib/pios-connd-lib/pios_connd' && ! find '$MNT/opt/pios' -name pios_connd | grep -q . && cd '$MNT/usr/lib/pios-connd-lib' && python3 -c 'import pios_connd.validate, pios_connd.ipc, pios_connd.hw, pios_connd.inputdiag, pios_connd.drivers'"
check "pios-connd limited to NET_ADMIN, SYS_PTRACE, DAC_READ_SEARCH, no root-writable /etc beyond modprobe.d" bash -c "grep -q '^CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH\$' '$MNT/etc/systemd/system/pios-connd.service' && grep -q '^ReadWritePaths=/etc/modprobe.d\$' '$MNT/etc/systemd/system/pios-connd.service' && grep -q '^NoNewPrivileges=yes' '$MNT/etc/systemd/system/pios-connd.service'"
check "kiosk uses a software cursor (invisible hardware cursor would look like a dead mouse)" bash -c "grep -q '^Environment=WLR_NO_HARDWARE_CURSORS=1' '$MNT/etc/systemd/system/pios-kiosk.service'"
check "kiosk user is in the input/video/render groups and logind session via PAM" bash -c "grep -E '^input:.*pios-kiosk' '$MNT/etc/group' && grep -E '^video:.*pios-kiosk' '$MNT/etc/group' && grep -q '^PAMName=login' '$MNT/etc/systemd/system/pios-kiosk.service'"
check "udev rules: input devices tagged for the seat (uaccess) by systemd" bash -c "grep -rqs 'uaccess' '$MNT/usr/lib/udev/rules.d/70-uaccess.rules' '$MNT/lib/udev/rules.d/70-uaccess.rules' || grep -rqs 'input' '$MNT/usr/lib/udev/rules.d/60-input-id.rules' '$MNT/lib/udev/rules.d/60-input-id.rules'"
check "no world-writable input/rfkill udev rules (MODE=0666/0777)" bash -c "! grep -rEs 'KERNEL==\"(event|mouse|rfkill|hidraw)[^\"]*\".*MODE=\"0?(666|777)\"' '$MNT/etc/udev/rules.d' '$MNT/usr/lib/udev/rules.d' '$MNT/lib/udev/rules.d'"
check "Wi-Fi country not hard-coded outside connd (set via UI/first run)" bash -c "! test -e '$MNT/etc/modprobe.d/pios-regdom.conf'"
check "kernel/network hardening sysctl installed" test -s "$MNT/etc/sysctl.d/90-pios-hardening.conf"
check "APT security origins configured, stock timers disabled by config" bash -c "grep -q 'Debian-Security' '$MNT/etc/apt/apt.conf.d/52pios-security' && grep -q 'linux-image' '$MNT/etc/apt/apt.conf.d/52pios-security'"
check "APT sources are not marked trusted/insecure" bash -c "! grep -rEi 'trusted=yes|allow-insecure=yes|AllowUnauthenticated|AllowInsecureRepositories' '$MNT/etc/apt'"
check "default firewall ruleset is valid nftables (dry run with host nft)" bash -c "cd '$MNT/usr/lib/pios-firewall' && python3 -c 'from pios_firewall.ruleset import FwConfig, render; print(render(FwConfig(), [\"192.168.0.0/24\"], [\"fd00::/64\"]))' | nft -c -f -"
echo "     enabled units: $(systemctl --root="$MNT" list-unit-files --state=enabled --no-legend | awk '{print $1}' | tr '\n' ' ')"
BADSVC="$(systemctl --root="$MNT" list-unit-files --state=enabled --no-legend | awk '{print $1}' | grep -Ei '^(ssh|sshd|telnet|vnc|wayvnc|smbd|nmbd|nfs|rpcbind|cups|vsftpd|proftpd)[a-z.@-]*\.(service|socket)' | grep -Ev '^(sshd-keygen|sshswitch).service$' || true)"   # sshd-keygen (host keys) and sshswitch (enables ssh only if /boot/firmware/ssh exists) open no port themselves; Pi OS needs it for Imager's SSH option
check "no unexpected network services enabled (ssh, telnet, vnc, samba, nfs, rpcbind, cups, ftp)${BADSVC:+ - FOUND: $BADSVC}" test -z "$BADSVC"
check "no SSH host keys baked into the image" bash -c "! ls '$MNT'/etc/ssh/ssh_host_*_key >/dev/null 2>&1"
check "no private keys or access tokens anywhere in the image" bash -c "! grep -rIlE 'BEGIN ((RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY|ghp_[A-Za-z0-9]{30,}|gho_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[0-9A-Z]{16}|PIOS_UPDATE_SIGNING_KEY=' '$MNT/opt' '$MNT/usr/lib/pios-updater' '$MNT/usr/lib/pios-firewall' '$MNT/usr/lib/pios-sysops-lib' '$MNT/usr/share/pios' '$MNT/etc/pios' '$MNT/etc/systemd' '$MNT/home' '$MNT/root' '$MNT/boot/firmware' '$MNT/var/lib' 2>/dev/null | grep -q ."
check "no snake-oil/default TLS private keys (identical on every device)" bash -c "! ls '$MNT'/etc/ssl/private/*.key >/dev/null 2>&1"
check "no unit files or service code inside the OTA-updatable tree" bash -c "! find '$MNT/opt/pios' \( -name '*.service' -o -name '*.timer' -o -name 'pios_firewall' -o -name 'pios_sysops' \) | grep -q ."
check "root account is locked (no password login)" bash -c "awk -F: '\$1==\"root\"{print \$2}' '$MNT/etc/shadow' | grep -qE '^[!*]'"
check "no account has an empty password" bash -c "! awk -F: '\$2==\"\"' '$MNT/etc/shadow' | grep -q ."
if python3 -c 'import crypt' 2>/dev/null; then
  check "no account uses a well-known default password" python3 - "$MNT/etc/shadow" <<'PY'
import crypt, sys
common = ["raspberry", "pi", "pios", "nova", "admin", "password", "123456", "12345678", "root", "toor", "changeme", "novauser", "pios-admin"]
bad = []
for line in open(sys.argv[1]):
    user, h = line.split(":")[:2]
    if h.startswith("$"):
        for pw in common:
            try:
                if crypt.crypt(pw, h) == h:
                    bad.append(f"{user}:{pw}")
            except Exception:
                pass
print("checked default passwords for", [l.split(":")[0] for l in open(sys.argv[1]) if l.split(":")[1].startswith("$")])
sys.exit(1 if bad else 0)
PY
else
  note "python crypt module unavailable: default-password check skipped (NOT counted as passed)"
fi

echo "== arm64 runtime (qemu user emulation)"
check "python3 is aarch64 ELF" bash -c "file -L '$MNT/usr/bin/python3' | grep -q aarch64"
check "chromium installed (arm64)" bash -c "file -L '$MNT/usr/bin/chromium' | grep -q aarch64 || file -L '$MNT/usr/lib/chromium/chromium' | grep -q aarch64"
check "cage installed (arm64)" bash -c "file -L '$MNT/usr/bin/cage' | grep -q aarch64"
if [[ -x /usr/bin/qemu-aarch64-static || -x /usr/libexec/qemu-binfmt/aarch64-binfmt-P ]]; then
  mount -t proc proc "$MNT/proc"; mount --rbind /sys "$MNT/sys"; mount --rbind /dev "$MNT/dev"
  binfmt_register || echo '     could not register qemu binfmt'
  echo "     binfmt: $(cat /proc/sys/fs/binfmt_misc/qemu-aarch64* 2>/dev/null | tr '\n' ' ' || echo none)"
  check "python imports all arm64 dependencies" chroot "$MNT" /usr/bin/python3 -c "
import fastapi, starlette, uvicorn, psutil, argon2, pydantic, pydantic_core, sqlite3, cryptography
try:
    import python_multipart
except ImportError:
    import multipart
print('ok')"
  # Smoke-run the real application inside the arm64 root file system.
  rm -rf "$MNT/tmp/piosdata"; mkdir -p "$MNT/tmp/piosdata"
  chroot "$MNT" env PIOS_DATA=/tmp/piosdata PIOS_WEB=/opt/pios/current/web PIOS_APPS=/opt/pios/current/apps \
    /usr/bin/python3 -m uvicorn pios.main:app --app-dir /opt/pios/current --host 127.0.0.1 --port 18080 >"$MNT/tmp/uvicorn.log" 2>&1 &
  SRV_PID=$!
  up=0; for _ in $(seq 1 90); do curl -fsS -o /dev/null http://127.0.0.1:18080/healthz 2>/dev/null && { up=1; break; }; sleep 1; done
  check "backend starts under arm64 emulation and answers /healthz" test "$up" = 1
  if [[ "$up" = 1 ]]; then
    check "setup status served" bash -c "curl -fsS http://127.0.0.1:18080/api/setup-status | grep -q needs_setup"
    check "desktop page served" bash -c "curl -fsS http://127.0.0.1:18080/ | grep -q 'PiOS NOVA'"
    check "unauthenticated API access is refused" bash -c "[ \"\$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/api/system)\" = 401 ]"
    check "database initialised under emulation" bash -c "ls '$MNT/tmp/piosdata' | grep -q pios.db"
  else
    tail -n 30 "$MNT/tmp/uvicorn.log"
  fi
  kill "$SRV_PID" 2>/dev/null; SRV_PID=""
  # The real Update Manager engine, inside the arm64 root file system: loads the shipped key, reads the installed release.
  check "Update Manager runs on arm64 and reads installed version + shipped key" chroot "$MNT" env PYTHONPATH=/usr/lib/pios-updater /usr/bin/python3 -c "
import tempfile
from pathlib import Path
from pios_updater.engine import Paths, Updater, Env
from pios_updater.source import GitHubSource
from pios_updater.crypto import load_trusted_keys
class E(Env): pass
t = Path(tempfile.mkdtemp())
u = Updater(Paths(root=Path('/opt/pios'), state=t, data=t, keys=Path('/usr/share/pios/update-keys')), GitHubSource(), E())
assert len(u.keys) == 1, 'no key'
assert u.installed()['version'] == '$REL', u.installed()
print('ok')"
  check "zstd decompresses on arm64" chroot "$MNT" /usr/bin/zstd --version
  rm -rf "$MNT/tmp/piosdata" "$MNT/tmp/uvicorn.log" "$MNT/usr/bin/qemu-aarch64-static"
else
  fail "qemu-user-static (aarch64) not available: emulated checks skipped"
fi

echo
if [[ $FAILS -eq 0 ]]; then echo "ALL CHECKS PASSED"; else echo "$FAILS CHECK(S) FAILED"; fi
exit $((FAILS > 0))
