# Building and verifying the PiOS image

Result: `PiOS-NOVA-arm64.img` (compress to `.img.xz` for distribution). It is Raspberry Pi OS Lite 64-bit
(Debian trixie, built with the official `pi-gen`, commit pinned in `scripts/build-image.sh`) plus one extra stage
(`image/stage-pios`) that installs PiOS, so Raspberry Pi Imager can write it via *Use custom*. Raspberry Pi 5 is
supported by the stock kernel/firmware (`kernel_2712.img`, `bcm2712-rpi-5-b.dtb` are checked in CI).

## What the image contains

| Path | Content |
|---|---|
| `/opt/pios/{pios,web,apps,bin}` | application, root-owned, read-only for the service |
| `/var/lib/pios` | data (`pios` user, mode 0700), created by `StateDirectory=` |
| `pios.service` | backend on port 80, hardened, enabled |
| `pios-display.service` | enabled; starts `pios-kiosk.service` (cage + Chromium) while an HDMI monitor is connected |
| `pios-setup-notice.{service,path}` | writes the first-run setup code to the console (`/etc/issue.d`) and `/boot/firmware/PIOS-SETUP.txt`, removes it after setup |
| `/etc/pios/pios.conf` | `KIOSK=auto|off`, keyboard layout. `touch /boot/firmware/pios-kiosk-off` also disables the local desktop |
| hostname `pios`, avahi | `http://pios.local` |

Packages come from Debian (no pip, no Node on the device). No SSH, and the placeholder account `nova` has a random
unknown password; use Imager's *OS customisation* (cloud-init) for Wi-Fi, locale and your own user/SSH key.
First boot expands the root file system (stock Raspberry Pi OS mechanism, `cmdline.txt` `resize`).

## Build

On GitHub (preferred): run the workflow **Build PiOS image** (Actions → Run workflow, branch of your choice). It takes
about 40–50 minutes on an `ubuntu-24.04` runner (stages 0–2 ≈ 20 min under qemu, our stage + export, verification).
The output files are `pi-gen/deploy/PiOS-NOVA-arm64.img(.xz)`, `SHA256SUMS`, `verify.log`, `boot-test.log`.

Locally (x86_64 Linux, Docker with privileged containers, ≥ 30 GB free):

```bash
PIOS_VERIFY=1 scripts/build-image.sh     # build + verification (needs sudo + qemu-user-static)
```

Is GitHub-hosted building reliable? Yes in our runs: no disk problems (cleanup of unused toolchains frees space), no
timeouts. Open risks: the free Actions **artifact storage quota** (500 MB on free plans) is smaller than the compressed
image — download from the run if your plan allows it, or attach the image to a private draft release
(`ci/workflows/build-image.yml`, see below); a self-hosted arm64 runner would cut the build time to ~15 min.

> **Workflow files:** the improved workflows are in `ci/workflows/` (tests + image build with release upload). Pushing to
> `.github/workflows/` requires a token with the `workflow` scope (`gh auth refresh -s workflow`); copy them over then.
> Until then the existing workflow runs `scripts/build-image.sh`, which does the verification itself.

## Automated checks (`scripts/verify-image.sh`, run on every build)

1. Partition table, FAT + ext4 types, `fsck.vfat` / `e2fsck` clean
2. Pi 5 boot files, `root=PARTUUID`, first-boot resize hook
3. All PiOS files present, root-owned, nothing world-writable, no databases/secrets shipped
4. Service users exist and cannot log in; SSH disabled; no desktop session installed; default target `multi-user`
5. systemd units enabled (offline `systemctl --root`)
6. arm64 binaries (Python, Chromium, cage) and **running the real backend inside the arm64 root file system under qemu**:
   imports, `/healthz`, setup status, desktop page, `401` for unauthenticated API access, database creation
7. Best-effort boot test (`scripts/boot-test-image.sh`): boots the root file system with systemd as PID 1 in
   `systemd-nspawn` under emulation and waits for `pios.service`. Informational only.

The latest results are documented in the pull request. A passing verification does **not** prove that the Pi 5 boots.

## Hardware tests (still open)

Not covered by emulation; must be done on a real Raspberry Pi 5 before calling the image "working":

- [ ] Imager writes the image; Pi 5 boots from SD and from SSD (USB/NVMe); file system expands on first boot
- [ ] `pios.local` resolves (mDNS) on the LAN; setup code visible on HDMI console and in `PIOS-SETUP.txt`
- [ ] Wi-Fi via Imager customisation; Ethernet DHCP
- [ ] HDMI kiosk: cage + Chromium start with a monitor, hotplug start/stop, mouse/keyboard, GPU acceleration, German keyboard
- [ ] Temperature sensor and throttling values in NOVA Monitor, orb performance (CPU use with animations on)
- [ ] Reboot persistence of data and sessions; behaviour after hard power loss
- [ ] Idle CPU/RAM footprint, 24 h soak test
