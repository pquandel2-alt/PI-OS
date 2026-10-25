#!/bin/bash -e
# Runs on the build host (cwd = this sub-stage). Payload is staged in ./files by scripts/build-image.sh.

install -d -m 755 "${ROOTFS_DIR}/opt/pios"
cp -a files/opt/pios/. "${ROOTFS_DIR}/opt/pios/"
cp -a files/etc/. "${ROOTFS_DIR}/etc/"
install -m 644 files/pios-release "${ROOTFS_DIR}/etc/pios-release"
chown -R 0:0 "${ROOTFS_DIR}/opt/pios" "${ROOTFS_DIR}/etc/pios" "${ROOTFS_DIR}/etc/pios-release"
find "${ROOTFS_DIR}/opt/pios" -type d -exec chmod 755 {} +
find "${ROOTFS_DIR}/opt/pios" -type f ! -path '*/bin/*' -exec chmod 644 {} +
chmod 755 "${ROOTFS_DIR}"/opt/pios/bin/*
chmod 644 "${ROOTFS_DIR}"/etc/systemd/system/pios*.service "${ROOTFS_DIR}"/etc/systemd/system/pios*.path

on_chroot <<'CHROOT'
set -e
# Service accounts: no shell, no password. 'pios' owns the data, 'pios-kiosk' runs the HDMI browser.
getent group pios >/dev/null || groupadd --system pios
id pios >/dev/null 2>&1 || useradd --system --gid pios --home-dir /var/lib/pios --no-create-home --shell /usr/sbin/nologin pios
id pios-kiosk >/dev/null 2>&1 || useradd --system --create-home --home-dir /var/lib/pios-kiosk --shell /usr/sbin/nologin --groups video,render,input pios-kiosk
chown pios-kiosk:pios-kiosk /var/lib/pios-kiosk
chmod 700 /var/lib/pios-kiosk

# Pre-compile the Python code (the service cannot write to /opt/pios at runtime).
python3 -m compileall -q /opt/pios/pios

# Autostart: backend, setup-code notice, and the HDMI display watcher. The kiosk itself is started by the watcher.
systemctl enable pios.service pios-setup-notice.service pios-setup-notice.path pios-display.service
systemctl set-default multi-user.target
CHROOT
