# shellcheck shell=bash
# Ensure the kernel runs aarch64 binaries through qemu-user-static ("F" flag: interpreter is opened at
# registration time, so it also works inside chroots/containers). Same registration pi-gen uses.
# Sets PIOS_BINFMT_NAME when we registered it (remove with binfmt_unregister).
binfmt_register() {
  [[ "$(uname -m)" == aarch64 ]] && return 0
  mountpoint -q /proc/sys/fs/binfmt_misc || mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc 2>/dev/null
  # A registration without the F flag does not work inside chroots: replace it with ours.
  for e in /proc/sys/fs/binfmt_misc/qemu-aarch64*; do
    [[ -e "$e" ]] && grep -q '^flags:.*F' "$e" && return 0
  done
  [[ -x /usr/bin/qemu-aarch64-static ]] || return 1
  for e in /proc/sys/fs/binfmt_misc/qemu-aarch64*; do [[ -e "$e" ]] && echo -1 > "$e"; done
  PIOS_BINFMT_NAME=qemu-aarch64-pios
  printf '%s' ':qemu-aarch64-pios:M::\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\xb7\x00:\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff:/usr/bin/qemu-aarch64-static:F' \
    > /proc/sys/fs/binfmt_misc/register
}
binfmt_unregister() {
  [[ -n "${PIOS_BINFMT_NAME:-}" && -e "/proc/sys/fs/binfmt_misc/$PIOS_BINFMT_NAME" ]] && echo -1 > "/proc/sys/fs/binfmt_misc/$PIOS_BINFMT_NAME"
}
