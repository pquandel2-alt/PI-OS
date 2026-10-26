import os
import struct

import pytest

from pios_connd import drivers, hw
from pios_sysops import packages
from tests.connd.fakehw import FakeHW, Runner

KLOG = """[    4.1] brcmfmac: brcmf_fw_alloc_request: using brcm/brcmfmac43455-sdio for chip BCM4345/6
[    4.2] brcmfmac mmc1:0001:1: Direct firmware load for brcm/brcmfmac43455-sdio.raspberrypi,5-model-b.bin failed with error -2
[    9.9] cfg80211: Loading compiled-in X.509 certificates for regulatory database
[    9.9] platform regulatory.0: Direct firmware load for regulatory.db failed with error -2
[   12.0] rtw_8821cu 1-1:1.0: Direct firmware load for rtw88/rtw8821c_fw.bin failed with error -2
[   13.0] foo bar: Direct firmware load for vendor/strange.bin failed with error -2
"""
POLICY_OK = """firmware-realtek:
  Installed: (none)
  Candidate: 20250410-2
  Version table:
     20250410-2 500
        500 http://deb.debian.org/debian trixie/non-free-firmware arm64 Packages
"""
POLICY_FOREIGN = """firmware-realtek:
  Installed: (none)
  Candidate: 9.9
  Version table:
     9.9 500
        500 http://evil.example/debian trixie/main arm64 Packages
"""
POLICY_NONE = "N: Unable to locate package foo\n"
POLICY_INSTALLED = """wireless-regdb:
  Installed: 2025.1-1
  Candidate: 2025.1-1
  Version table:
 *** 2025.1-1 500
        500 http://archive.raspberrypi.com/debian trixie/main arm64 Packages
"""


def test_firmware_failures_are_extracted_and_mapped_to_official_packages():
    fw = {f["file"]: f for f in drivers.missing_firmware(KLOG)}
    assert set(fw) == {"brcm/brcmfmac43455-sdio.raspberrypi,5-model-b.bin", "regulatory.db", "rtw88/rtw8821c_fw.bin", "vendor/strange.bin"}
    assert fw["regulatory.db"]["packages"] == ["wireless-regdb"]
    assert fw["rtw88/rtw8821c_fw.bin"]["packages"] == ["firmware-realtek"] and fw["rtw88/rtw8821c_fw.bin"]["device"].startswith("Realtek")
    assert fw["brcm/brcmfmac43455-sdio.raspberrypi,5-model-b.bin"]["packages"] == ["firmware-brcm80211"]
    assert fw["vendor/strange.bin"]["packages"] == [] and not fw["vendor/strange.bin"]["known"], "unknown files get no guessed package"


def test_every_mapped_package_is_on_the_install_allowlist():
    for _pat, pkgs, _d in drivers.FIRMWARE_PACKAGES:
        for p in pkgs:
            assert p in packages.ALLOWED, p


def test_policy_parsing_and_official_origin_check():
    ok = drivers.parse_policy(POLICY_OK)
    assert ok == {"installed": "", "candidate": "20250410-2", "origins": ["deb.debian.org"], "official": True}
    assert drivers.parse_policy(POLICY_FOREIGN)["official"] is False
    assert drivers.parse_policy(POLICY_INSTALLED)["installed"] == "2025.1-1" and drivers.parse_policy(POLICY_INSTALLED)["official"] is True
    assert drivers.parse_policy(POLICY_NONE)["candidate"] == ""


@pytest.mark.parametrize("bad", ["", "Pkg", "a b", "x;rm -rf /", "../x", "a" * 80, "-oAPT::x=1"])
def test_package_names_are_validated(bad):
    with pytest.raises(ValueError):
        drivers.package_status(bad, Runner())


def test_analysis_offers_only_official_allowlisted_installable_packages():
    r = Runner(**{"apt-cache|policy|firmware-realtek": (0, POLICY_FOREIGN), "apt-cache|policy|wireless-regdb": (0, POLICY_INSTALLED), "apt-cache|policy|firmware-brcm80211": (0, POLICY_OK)})
    res = drivers.analyse({"problems": [], "platform": {"kernel": "6.12.47+rpt-rpi-2712"}}, KLOG, r, set(packages.ALLOWED))
    f = {x["title"]: x for x in res["findings"]}
    realtek = f["Firmware fehlt: rtw88/rtw8821c_fw.bin"]["packages"][0]
    assert realtek["installable"] is False and realtek["official"] is False, "a package from a foreign origin is never offered"
    regdb = f["Firmware fehlt: regulatory.db"]
    assert regdb["state"] == "installed_reload" and "passt nicht" in regdb["advice"]
    assert f["Firmware fehlt: vendor/strange.bin"]["state"] == "unknown_file" and "installiert nichts automatisch" in f["Firmware fehlt: vendor/strange.bin"]["advice"]
    assert res["kernel"].startswith("6.12") and res["summary"]["firmware_missing"] >= 1


def test_driver_problem_without_kernel_module_is_documented_as_unsupported():
    inv = {"problems": [{"device": "Exotic WLAN stick", "where": "USB", "problem": "Kein Treiber gebunden", "kernel_module_available": False, "detail": ""},
                        {"device": "Foo", "where": "USB", "problem": "Kein Treiber gebunden", "kernel_module_available": True, "detail": ""}], "platform": {}}
    res = drivers.analyse(inv, "", Runner(), set())
    a, b = res["findings"]
    assert a["state"] == "no_kernel_module" and "keinen Treiber" in a["advice"] and "lädt keine Treiber aus dem Internet" in a["advice"]
    assert b["state"] == "not_loaded"


def test_modalias_check_uses_the_kernel_not_a_guess():
    r = Runner(**{"modprobe|--resolve-alias|usb:v0BDApC811d0200": (0, "8821cu\n"), "modprobe|--resolve-alias|usb:v1234pABCDd0100": (1, "")})
    assert hw.modalias_has_module("usb:v0BDApC811d0200", r) is True
    assert hw.modalias_has_module("usb:v1234pABCDd0100", r) is False
    assert hw.modalias_has_module("x;reboot", r) is None
    assert hw.modalias_has_module("usb:v1234pABCDd0100", Runner()) is None, "modprobe missing -> unknown, not 'no driver'"


# ----------------------------------------------------------------------------------- inventory
def test_inventory_reads_real_looking_sysfs(tmp_path):
    h = FakeHW(tmp_path)
    h.w("proc/device-tree/model", "Raspberry Pi 5 Model B Rev 1.0\x00"); h.w("proc/cpuinfo", "processor : 0\nModel name : Cortex-A76\nRevision : d04170\n"); h.w("proc/meminfo", "MemTotal:        8190000 kB\n")
    h.w("sys/devices/system/cpu/online", "0-3\n")
    h.usb_hub(); h.usb_hid(); h.drivers()
    for n, kind in (("eth0", "ethernet"), ("wlan0", "wifi")):
        h.w(f"sys/class/net/{n}/address", "2c:cf:67:aa:bb:cc\n"); h.w(f"sys/class/net/{n}/operstate", "up\n"); h.w(f"sys/class/net/{n}/type", "1\n"); h.w(f"sys/class/net/{n}/carrier", "1\n")
    h.w("sys/class/net/eth0/speed", "1000\n"); (tmp_path / "sys/class/net/wlan0/wireless").mkdir()
    h.w("sys/class/rfkill/rfkill0/type", "wlan\n"); h.w("sys/class/rfkill/rfkill0/name", "phy0\n"); h.w("sys/class/rfkill/rfkill0/soft", "1\n"); h.w("sys/class/rfkill/rfkill0/hard", "0\n")
    h.w("proc/asound/cards", " 0 [vc4hdmi0      ]: vc4-hdmi - vc4-hdmi-0\n                      vc4-hdmi-0\n")
    edid = bytearray(128); edid[:8] = b"\x00\xff\xff\xff\xff\xff\xff\x00"; edid[8:10] = bytes([0x10, 0xAC]); edid[21], edid[22] = 52, 29
    edid[54:72] = b"\x00\x00\x00\xfc\x00DELL U2415\n   "; (tmp_path / "sys/class/drm/card1-HDMI-A-1").mkdir(parents=True)
    h.w("sys/class/drm/card1-HDMI-A-1/status", "connected\n"); h.w("sys/class/drm/card1-HDMI-A-1/enabled", "enabled\n"); h.w("sys/class/drm/card1-HDMI-A-1/modes", "1920x1200\n1920x1080\n")
    (tmp_path / "sys/class/drm/card1-HDMI-A-1/edid").write_bytes(bytes(edid))
    h.w("sys/block/mmcblk0/size", str(62333952) + "\n"); h.w("sys/block/mmcblk0/removable", "0\n"); h.w("sys/block/mmcblk0/device/name", "SC64G\n")
    (tmp_path / "sys/block/loop0").mkdir(parents=True)
    inv = hw.inventory(h.r)
    assert inv["platform"]["model"] == "Raspberry Pi 5 Model B Rev 1.0" and inv["platform"]["cores"] == 4 and inv["platform"]["memory_mb"] == 7998 and inv["platform"]["cpu"] == "Cortex-A76"
    recv = [u for u in inv["usb"] if not u["is_hub"]]
    assert [u["product"] for u in recv] == ["USB Receiver"] and recv[0]["interfaces"][0]["driver"] == "usbhid" and recv[0]["vendor_id"] == "046d"
    kinds = {n["iface"]: n for n in inv["network"]}
    assert kinds["eth0"]["kind"] == "ethernet" and kinds["eth0"]["speed_mbps"] == 1000 and kinds["wlan0"]["kind"] == "wifi" and kinds["wlan0"]["mac"] == "2C:CF:67:AA:BB:CC"
    assert inv["rfkill"][0] == {"id": "rfkill0", "type": "wlan", "name": "phy0", "soft_blocked": True, "hard_blocked": False}
    assert inv["audio"][0]["name"] == "vc4-hdmi-0" and inv["displays"][0]["monitor"] == "DELL U2415" and inv["displays"][0]["vendor"] == "DEL" and inv["displays"][0]["mode"] == "1920x1200"
    assert [s["name"] for s in inv["storage"]] == ["mmcblk0"] and inv["storage"][0]["size_gb"] == 31.9 and inv["storage"][0]["transport"] == "sd/mmc"


def test_usb_device_without_driver_is_reported_as_a_problem(tmp_path):
    h = FakeHW(tmp_path); h.drivers()
    h.usb_hid(name="1-2", vendor="0bda", product="c811", prod="Wi-Fi Stick", klass="ff", bound=False)
    r = Runner(**{"modprobe|--resolve-alias|usb:v0BDAPC811d0200ic03isc01ip02in00": (1, "")})
    inv = hw.inventory(h.r, r)
    p = inv["problems"][0]
    assert p["device"] == "Wi-Fi Stick" and p["problem"] == "Kein Treiber gebunden" and p["id"] == "0bda:c811"


def test_missing_sysfs_does_not_crash(tmp_path):
    inv = hw.inventory(hw.Roots(sys=tmp_path / "x", proc=tmp_path / "y", dev=tmp_path / "z", udev=tmp_path / "u"))
    assert inv["usb"] == [] and inv["network"] == [] and inv["problems"] == [] and inv["platform"]["model"] == "unbekannt"


def test_hid_roles():
    assert hw.hid_role({"class": "03", "subclass": "01", "protocol": "02"}) == "mouse"
    assert hw.hid_role({"class": "03", "subclass": "01", "protocol": "01"}) == "keyboard"
    assert hw.hid_role({"class": "03", "subclass": "00", "protocol": "00"}) == "hid"
    assert hw.hid_role({"class": "08", "subclass": "06", "protocol": "50"}) == ""


def test_edid_parser_rejects_garbage():
    assert hw.parse_edid(b"garbage") == {} and hw.parse_edid(b"\x00" * 128) == {}
