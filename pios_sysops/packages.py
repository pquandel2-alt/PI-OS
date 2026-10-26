"""The ONLY packages PiOS may install on a user's behalf (driver/firmware manager). Installing anything else requires a normal image/OTA change
reviewed in this file. All come from the official Debian / Raspberry Pi OS archives, verified by APT's signature checks."""
ALLOWED = {
    "wireless-regdb": "Regulatory-Datenbank (WLAN-Länderregeln)",
    "firmware-brcm80211": "Broadcom/Cypress WLAN- und Bluetooth-Firmware (Raspberry Pi onboard)",
    "bluez-firmware": "Bluetooth-Firmware für Broadcom-Adapter",
    "firmware-realtek": "Realtek WLAN/Ethernet/Bluetooth-Firmware",
    "firmware-mediatek": "MediaTek WLAN/Bluetooth-Firmware",
    "firmware-atheros": "Atheros/Qualcomm WLAN/Bluetooth-Firmware",
    "firmware-iwlwifi": "Intel WLAN-Firmware",
    "firmware-intel-misc": "Intel Bluetooth-Firmware",
    "firmware-libertas": "Marvell Libertas WLAN-Firmware",
    "firmware-misc-nonfree": "Verschiedene proprietäre Firmware (u. a. Marvell)",
    "firmware-amd-graphics": "AMD Grafik-Firmware",
}
