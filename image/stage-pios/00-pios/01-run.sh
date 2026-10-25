#!/bin/bash -e
# Runs on the build host (cwd = this sub-stage). Payload is staged in ./files by scripts/build-image.sh.

# shellcheck source=/dev/null
. files/pios-release                      # PIOS_VERSION, PIOS_CHANNEL, ...

# Versioned layout: /opt/pios/releases/<version> (identical to what an OTA package unpacks) + `current` symlink.
install -d -m 755 "${ROOTFS_DIR}/opt/pios/releases"
cp -a files/release "${ROOTFS_DIR}/opt/pios/releases/${PIOS_VERSION}"
cp files/README.md "${ROOTFS_DIR}/opt/pios/releases/${PIOS_VERSION}/README.md"
ln -sfn "releases/${PIOS_VERSION}" "${ROOTFS_DIR}/opt/pios/current"
# The Update Manager lives outside the OTA-updatable tree so a bad update can never replace the tool that rolls it back.
install -d -m 755 "${ROOTFS_DIR}/usr/lib/pios-updater"
cp -a files/pios_updater "${ROOTFS_DIR}/usr/lib/pios-updater/"
install -d -m 700 "${ROOTFS_DIR}/var/lib/pios-updater"
printf '{"channel": "%s", "auto_check": true}\n' "${PIOS_CHANNEL}" > "${ROOTFS_DIR}/var/lib/pios-updater/config.json"
chmod 600 "${ROOTFS_DIR}/var/lib/pios-updater/config.json"

cp -a files/etc/. "${ROOTFS_DIR}/etc/"
cp -a files/usr/. "${ROOTFS_DIR}/usr/"
install -m 644 files/pios-release "${ROOTFS_DIR}/etc/pios-release"
chown -R 0:0 "${ROOTFS_DIR}/opt/pios" "${ROOTFS_DIR}/usr/lib/pios-updater" "${ROOTFS_DIR}/usr/share/pios" "${ROOTFS_DIR}/etc/pios" "${ROOTFS_DIR}/etc/pios-release"
find "${ROOTFS_DIR}/usr/lib/pios-updater" "${ROOTFS_DIR}/usr/share/pios" -type d -exec chmod 755 {} +
find "${ROOTFS_DIR}/usr/lib/pios-updater" "${ROOTFS_DIR}/usr/share/pios" -type f -exec chmod 644 {} +
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
python3 -m compileall -q /opt/pios/current/pios /usr/lib/pios-updater

# Autostart: backend, setup-code notice, and the HDMI display watcher. The kiosk itself is started by the watcher.
systemctl enable pios.service pios-updater.service pios-setup-notice.service pios-setup-notice.path pios-display.service
systemctl set-default multi-user.target
CHROOT
