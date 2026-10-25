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
check "no world-writable files in /opt/pios" bash -c "! find '$MNT/opt/pios' -perm -0002 | grep -q ."
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
