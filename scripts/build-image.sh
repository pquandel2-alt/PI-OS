#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${PIOS_BUILD_DIR:-$ROOT/image-build}"
mkdir -p "$BUILD_DIR"
if [[ ! -d "$BUILD_DIR/pi-gen/.git" ]]; then
  git clone --depth 1 --branch arm64 https://github.com/RPi-Distro/pi-gen.git "$BUILD_DIR/pi-gen"
fi
cd "$BUILD_DIR/pi-gen"
cat > config <<'CFG'
IMG_NAME='PiOS-NOVA'
RELEASE='trixie'
DEPLOY_ZIP=0
LOCALE_DEFAULT='de_DE.UTF-8'
TARGET_HOSTNAME='pios'
ENABLE_SSH=0
CFG
touch stage3/SKIP stage4/SKIP stage5/SKIP
touch stage2/EXPORT_IMAGE
STAGE=stage2/99-pios
mkdir -p "$STAGE"
cat > "$STAGE/00-run.sh" <<'SCRIPT'
#!/bin/bash -e
install -d "${ROOTFS_DIR}/opt/pios"
cp -a "${STAGE_DIR}/files/pios/." "${ROOTFS_DIR}/opt/pios/"
on_chroot <<'EOF'
apt-get update
apt-get install -y --no-install-recommends python3 python3-venv python3-pip ca-certificates
python3 -m venv /opt/pios/.venv
/opt/pios/.venv/bin/pip install --no-cache-dir -r /opt/pios/requirements.txt
useradd --system --home-dir /opt/pios --shell /usr/sbin/nologin pios || true
install -d -o pios -g pios -m 700 /var/lib/pios
systemctl enable pios.service
EOF
SCRIPT
chmod +x "$STAGE/00-run.sh"
mkdir -p "$STAGE/files/pios"
cp "$ROOT/requirements.txt" "$STAGE/files/pios/"
cp -a "$ROOT/pios" "$ROOT/web" "$STAGE/files/pios/"
cat > "$STAGE/files/pios/pios.service" <<'SERVICE'
[Unit]
Description=PiOS NOVA Web Desktop
After=network.target
[Service]
Type=simple
User=pios
Group=pios
WorkingDirectory=/opt/pios
Environment=PIOS_DATA=/var/lib/pios
ExecStart=/opt/pios/.venv/bin/uvicorn pios.main:app --host 0.0.0.0 --port 8080
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/pios
PrivateTmp=true
[Install]
WantedBy=multi-user.target
SERVICE
cat >> "$STAGE/00-run.sh" <<'SCRIPT'
install -D -m 644 "${ROOTFS_DIR}/opt/pios/pios.service" "${ROOTFS_DIR}/etc/systemd/system/pios.service"
rm "${ROOTFS_DIR}/opt/pios/pios.service"
SCRIPT
# The official pi-gen container build requires privileged Docker access.
./build-docker.sh
printf '\nImages produced in: %s\n' "$PWD/deploy"
