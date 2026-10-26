#!/usr/bin/env bash
# Builds PiOS-NOVA-arm64.img with Raspberry Pi's official pi-gen (Docker, arm64 via qemu on x86 hosts).
# Output: $PIOS_BUILD_DIR/pi-gen/deploy/PiOS-NOVA-arm64.img (+ build-info.json, verify.log)
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${PIOS_BUILD_DIR:-$ROOT/image-build}"
# Pin pi-gen for reproducible builds. Override with PIGEN_REF=<commit|branch> to try a newer one.
PIGEN_REPO="${PIGEN_REPO:-https://github.com/RPi-Distro/pi-gen.git}"
PIGEN_BRANCH="${PIGEN_BRANCH:-arm64}"
PIGEN_REF="${PIGEN_REF:-d346cd5}"

if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
  echo "::group::Prepare GitHub runner"
  df -h /
  sudo rm -rf /usr/share/dotnet /usr/local/lib/android /opt/ghc /opt/hostedtoolcache/CodeQL /usr/local/share/boost
  docker image prune -af >/dev/null 2>&1 || true
  df -h /
  sudo apt-get update -qq
  sudo apt-get install -y -qq qemu-user-static binfmt-support systemd-container dosfstools e2fsprogs file
  echo "::endgroup::"
fi

VERSION="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$ROOT/pios/__init__.py")"
GIT_SHA="$(git -C "$ROOT" rev-parse --short=10 HEAD 2>/dev/null || echo unknown)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# A leftover container from an earlier local run would make build-docker.sh abort.
( docker rm -v pigen_work || sudo docker rm -v pigen_work ) >/dev/null 2>&1 || true
rm -rf "$BUILD_DIR/pi-gen"
git clone --quiet --branch "$PIGEN_BRANCH" "$PIGEN_REPO" "$BUILD_DIR/pi-gen"
git -C "$BUILD_DIR/pi-gen" checkout --quiet "$PIGEN_REF"
PIGEN_COMMIT="$(git -C "$BUILD_DIR/pi-gen" rev-parse HEAD)"
cd "$BUILD_DIR/pi-gen"

# Random password for the placeholder Linux account 'nova' (never shown, never logged). Real accounts come
# from Raspberry Pi Imager's "OS customisation" (cloud-init). SSH stays disabled unless Imager enables it.
FIRST_USER_PASS="$(openssl rand -base64 33)"
cat > config <<CFG
IMG_NAME='PiOS-NOVA-arm64'
PI_GEN_RELEASE='PiOS NOVA ${VERSION}'
RELEASE='trixie'
DEPLOY_COMPRESSION='none'
LOCALE_DEFAULT='de_DE.UTF-8'
KEYBOARD_KEYMAP='de'
KEYBOARD_LAYOUT='German'
TIMEZONE_DEFAULT='Europe/Berlin'
TARGET_HOSTNAME='pios'
FIRST_USER_NAME='nova'
FIRST_USER_PASS='${FIRST_USER_PASS}'
DISABLE_FIRST_BOOT_USER_RENAME=1
ENABLE_SSH=0
STAGE_LIST='stage0 stage1 stage2 stage-pios'
CFG
chmod 600 config

# Only the lite system (stage0-2) plus our stage is built; do not export the plain lite image.
rm -f stage2/EXPORT_IMAGE stage2/EXPORT_NOOBS
cp -a "$ROOT/image/stage-pios" ./stage-pios

# Stage the payload that 01-run.sh copies into the root file system. The release tree is produced by the same
# code that builds OTA packages, so the image and a later OTA update are identical in layout and content.
FILES=stage-pios/00-pios/files
mkdir -p "$FILES"
python3 "$ROOT/scripts/release_tool.py" stage --dest "$FILES/release"
cp -a "$ROOT/pios_updater" "$FILES/pios_updater"
tar -C "$ROOT/image/overlay" --exclude=./opt -cf - . | tar -C "$FILES" -xf -
cp "$ROOT/README.md" "$FILES/README.md"
find "$FILES" -name __pycache__ -type d -prune -exec rm -rf {} +
# Default update channel: "beta" until a real-hardware validation is recorded (release/hardware-validation.json).
CHANNEL="$(python3 -c "import json,sys; g=json.load(open('$ROOT/release/hardware-validation.json')); print('stable' if g.get('validated') is True else 'beta')")"
cat > "$FILES/pios-release" <<REL
PIOS_VERSION=${VERSION}
PIOS_CHANNEL=${CHANNEL}
PIOS_BUILD=${GIT_SHA}
PIOS_BUILD_DATE=${BUILD_DATE}
PIGEN_COMMIT=${PIGEN_COMMIT}
REL

# pi-gen's official container build (needs privileged Docker for loop devices + binfmt).
./build-docker.sh -c config

IMG="$(find deploy -maxdepth 1 -name '*.img' | head -n1)"
[[ -n "$IMG" ]] || { echo "build finished but no .img was produced in deploy/" >&2; ls -la deploy >&2; exit 1; }
OUT="$PWD/deploy"
mv "$IMG" "$OUT/PiOS-NOVA-arm64.img"
cat > "$OUT/build-info.json" <<JSON
{"name":"PiOS NOVA","version":"${VERSION}","git":"${GIT_SHA}","built":"${BUILD_DATE}","pi_gen":"${PIGEN_COMMIT}","release":"trixie","arch":"arm64"}
JSON
echo "Image: $OUT/PiOS-NOVA-arm64.img"

# Verification. A failing check fails the build: no success message for an unverified image.
SUDO=""; [[ $EUID -eq 0 ]] || SUDO="sudo"
if [[ -n "${GITHUB_ACTIONS:-}" || -n "${PIOS_VERIFY:-}" ]]; then
  echo "::group::verify-image"
  $SUDO "$ROOT/scripts/verify-image.sh" "$OUT/PiOS-NOVA-arm64.img" 2>&1 | tee "$OUT/verify.log"
  rc=${PIPESTATUS[0]}
  echo "::endgroup::"
  [[ $rc -eq 0 ]] || { echo "image verification FAILED" >&2; exit 1; }
  echo "::group::boot-test (best effort, emulated)"
  $SUDO "$ROOT/scripts/boot-test-image.sh" "$OUT/PiOS-NOVA-arm64.img" 600 2>&1 | tee "$OUT/boot-test.log" || echo "emulated boot test did not pass (see log); this is informational"
  echo "::endgroup::"
fi
