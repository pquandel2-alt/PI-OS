#!/usr/bin/env bash
# Best-effort boot test: boots the image's root file system with systemd (as PID 1) in systemd-nspawn under
# qemu-user arm64 emulation and waits for the PiOS backend to answer. It does NOT test the Pi 5 kernel,
# firmware, GPU or HDMI - those need real hardware (see docs/IMAGE_BUILD.md, "Hardware tests").
# Usage: sudo scripts/boot-test-image.sh IMAGE [timeout_seconds]
set -uo pipefail
# shellcheck source=lib-binfmt.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib-binfmt.sh"
binfmt_register || echo "could not register qemu binfmt"
IMG="${1:?usage: boot-test-image.sh IMAGE [timeout]}"
TIMEOUT="${2:-480}"
MNT="$(mktemp -d)"; LOOP=""; NSPID=""; MACHINE="piosboot$$"
cleanup() {
  machinectl terminate "$MACHINE" 2>/dev/null; sleep 2
  [[ -n "$NSPID" ]] && kill "$NSPID" 2>/dev/null
  for m in boot/firmware ""; do mountpoint -q "$MNT/$m" 2>/dev/null && umount -l "$MNT/$m"; done
  [[ -n "$LOOP" ]] && losetup -d "$LOOP" 2>/dev/null
  rmdir "$MNT" 2>/dev/null
}
trap 'cleanup; binfmt_unregister' EXIT
LOOP="$(losetup --find --show --partscan "$IMG")" || exit 2
sleep 1
mount "${LOOP}p2" "$MNT" && mount "${LOOP}p1" "$MNT/boot/firmware" || exit 2

systemd-nspawn --quiet --directory="$MNT" --machine="$MACHINE" --boot --private-network --register=yes >/tmp/nspawn.log 2>&1 &
NSPID=$!
echo "booting arm64 root file system under emulation (timeout ${TIMEOUT}s) ..."
start=$SECONDS
leader=""
while (( SECONDS - start < TIMEOUT )); do
  leader="$(machinectl show "$MACHINE" -p Leader --value 2>/dev/null)"
  if [[ -n "$leader" ]] && nsenter -t "$leader" -n curl -fsS -m 3 -o /dev/null http://127.0.0.1/healthz 2>/dev/null; then
    echo "BOOT OK after $((SECONDS - start))s: pios.service started by systemd and answers on port 80"
    nsenter -t "$leader" -n curl -fsS -m 3 http://127.0.0.1/api/setup-status; echo
    echo "--- setup code notice (as root of the booted system):"
    machinectl shell "$MACHINE" /bin/cat /etc/issue.d/50-pios.issue 2>/dev/null | head -n 5 || true
    exit 0
  fi
  kill -0 "$NSPID" 2>/dev/null || { echo "container exited early"; break; }
  sleep 5
done
echo "BOOT FAILED / TIMED OUT"; tail -n 40 /tmp/nspawn.log
journalctl -D "$MNT/var/log/journal" -u pios.service --no-pager 2>/dev/null | tail -n 40
exit 1
