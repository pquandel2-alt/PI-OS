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

# Privileged helpers (root daemons) and their code live outside the OTA-updatable tree, in /usr/lib.
install -d -m 755 "${ROOTFS_DIR}/usr/lib/pios-firewall" "${ROOTFS_DIR}/usr/lib/pios-sysops-lib"
cp -a files/pios_firewall "${ROOTFS_DIR}/usr/lib/pios-firewall/"
cp -a files/pios_sysops "${ROOTFS_DIR}/usr/lib/pios-sysops-lib/"

cp -a files/etc/. "${ROOTFS_DIR}/etc/"
cp -a files/usr/. "${ROOTFS_DIR}/usr/"
install -m 644 files/pios-release "${ROOTFS_DIR}/etc/pios-release"
chown -R 0:0 "${ROOTFS_DIR}/opt/pios" "${ROOTFS_DIR}/usr/lib/pios-firewall" "${ROOTFS_DIR}/usr/lib/pios-sysops-lib" "${ROOTFS_DIR}/usr/lib/pios-updater" "${ROOTFS_DIR}/usr/share/pios" "${ROOTFS_DIR}/etc/pios" "${ROOTFS_DIR}/etc/pios-release"
for d in usr/lib/pios-updater usr/lib/pios-firewall usr/lib/pios-sysops-lib usr/share/pios etc/chromium/policies etc/clamav; do
	[ -d "${ROOTFS_DIR}/$d" ] || continue
	find "${ROOTFS_DIR}/$d" -type d -exec chmod 755 {} +
	find "${ROOTFS_DIR}/$d" -type f -exec chmod 644 {} +
done
chmod 644 "${ROOTFS_DIR}"/etc/systemd/system/*.timer "${ROOTFS_DIR}"/etc/systemd/system/clamav-daemon.service.d/pios.conf "${ROOTFS_DIR}"/etc/sysctl.d/90-pios-hardening.conf "${ROOTFS_DIR}"/etc/apt/apt.conf.d/52pios-security
chmod 644 "${ROOTFS_DIR}"/etc/systemd/system/pios*.service "${ROOTFS_DIR}"/etc/systemd/system/pios*.path

on_chroot <<'CHROOT'
set -e
# Service accounts: no shell, no password. 'pios' owns the data, 'pios-kiosk' runs the HDMI browser.
getent group pios >/dev/null || groupadd --system pios
id pios >/dev/null 2>&1 || useradd --system --gid pios --home-dir /var/lib/pios --no-create-home --shell /usr/sbin/nologin pios
id pios-kiosk >/dev/null 2>&1 || useradd --system --create-home --home-dir /var/lib/pios-kiosk --shell /usr/sbin/nologin --groups video,render,input pios-kiosk
chown pios-kiosk:pios-kiosk /var/lib/pios-kiosk
chmod 700 /var/lib/pios-kiosk

# ClamAV: tuned clamd config, no resident updater daemon, no socket activation (a plain connect() must never wake the 1 GB scanner).
# clamd rejects duplicated single-value options, so remove the Debian defaults for every key we set, then append ours.
grep -E '^[A-Za-z]' /etc/clamav/pios-clamd.conf | cut -d' ' -f1 | while read -r key; do sed -i "/^${key}[[:space:]]/d" /etc/clamav/clamd.conf; done
cat /etc/clamav/pios-clamd.conf >> /etc/clamav/clamd.conf
rm -f /etc/clamav/pios-clamd.conf
usermod -aG clamav pios || true

# Pre-compile the Python code (the service cannot write to /opt/pios at runtime).
python3 -m compileall -q /opt/pios/current/pios /usr/lib/pios-updater /usr/lib/pios-firewall /usr/lib/pios-sysops-lib

# Autostart: backend, setup-code notice, and the HDMI display watcher. The kiosk itself is started by the watcher.
systemctl enable pios.service pios-updater.service pios-firewall.service pios-sysops.service pios-setup-notice.service pios-setup-notice.path pios-display.service \
	pios-clam-update.timer pios-os-check.timer pios-os-upgrade.timer
# never started by default: clamd runs on demand; the stock freshclam daemon and nftables.service (which flushes the ruleset) stay off
systemctl disable clamav-daemon.service clamav-freshclam.service nftables.service apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
systemctl mask clamav-daemon.socket
sysctl -p /etc/sysctl.d/90-pios-hardening.conf >/dev/null 2>&1 || true
systemctl set-default multi-user.target
CHROOT
