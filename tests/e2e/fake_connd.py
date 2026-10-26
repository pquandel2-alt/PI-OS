"""A scripted stand-in for pios-connd on a real unix socket, for browser tests of the connectivity UI. Data is canned (nothing here is a hardware test)."""
import os
import threading

from pios_connd.ipc import OpError, Server

AP = lambda ssid, sig, sec, label, **kw: {"ssid": ssid, "signal": sig, "frequency": 5180, "band": "5 GHz", "bssid": "11:22:33:44:55:66", "security": sec, "label": label, "supported": True,
                                           "needs_password": sec != "open", "known": False, "uuid": "", "in_use": False, **kw}


class FakeConnd:
    def __init__(self, path):
        self.calls = []
        self.s = {"pending": None, "connected": None, "wifi_on": True, "bt_on": True, "answer": None, "paired": False, "op_polls": 0,
                  "request": None}
        v = self.verbs = {}
        v["net.summary"] = lambda a: {"online": True, "nm": True, "pending": self.s["pending"],
                                      "wifi": {"present": True, "enabled": self.s["wifi_on"], "connected": bool(self.s["connected"]), "ssid": self.s["connected"] or "", "signal": 72, "ip": "192.168.1.77"},
                                      "ethernet": {"present": True, "connected": True, "carrier": True, "ip": "192.168.1.20", "speed_mbps": 1000},
                                      "bluetooth": {"present": True, "powered": self.s["bt_on"], "connected": ["Test-Maus"] if self.s["paired"] else []}}
        v["net.status"] = self.net_status
        v["wifi.networks"] = lambda a: {"networks": [AP("Heimnetz", 82, "wpa2", "WPA2", in_use=self.s["connected"] == "Heimnetz", known=self.s["connected"] == "Heimnetz"),
                                                      AP("Gastnetz", 55, "open", "Offen (unverschlüsselt)"), AP("Altnetz", 40, "wep", "WEP (unsicher)", supported=False, reason="WEP ist unsicher und wird nicht unterstützt.")]}
        v["wifi.scan"] = lambda a: {"scanning": True}
        v["wifi.connect"] = self.connect
        v["net.operation"] = self.operation
        v["net.confirm"] = lambda a: self.rec("net.confirm") or self.s.update(pending=None) or {"ok": True}
        v["net.revert"] = lambda a: self.rec("net.revert") or self.s.update(pending=None) or {"ok": True}
        v["wifi.set_enabled"] = lambda a: self.s.update(wifi_on=bool(a["enabled"])) or {"ok": True, "protected": False}
        v["wifi.set_country"] = lambda a: {"ok": True, "country": a["code"]}
        v["wifi.forget"] = lambda a: {"ok": True}
        v["wifi.autoconnect"] = lambda a: {"ok": True}
        v["net.disconnect"] = lambda a: {"ok": True, "protected": False}
        v["bt.status"] = self.bt_status
        v["bt.pairing"] = lambda a: {"sessions": [], "requests": [self.s["request"]] if self.s["request"] else [], "display": []}
        v["bt.set_powered"] = lambda a: self.s.update(bt_on=bool(a["powered"])) or {"ok": True}
        v["bt.scan"] = lambda a: {"ok": True}
        v["bt.scan_stop"] = lambda a: {"ok": True}
        v["bt.pair"] = self.pair
        v["bt.answer"] = self.answer
        v["bt.cancel"] = lambda a: self.s.update(request=None) or {"ok": True}
        v["bt.connect"] = lambda a: {"ok": True}
        v["bt.disconnect"] = lambda a: {"ok": True}
        v["bt.trust"] = lambda a: {"ok": True}
        v["bt.remove"] = lambda a: {"ok": True}
        v["hw.inventory"] = self.inventory
        v["hw.input_diag"] = lambda a: {"verdict": {"state": "warn", "stage": "cursor", "title": "Cursor", "cause": "Das Gerät ist erkannt. Der Cursor ist vermutlich unsichtbar."},
                                        "stages": [{"id": "usb", "title": "USB-Gerät erkannt", "state": "ok", "detail": "1 Gerät", "evidence": {}}, {"id": "cursor", "title": "Cursor", "state": "warn", "detail": "Hardware-Cursor aktiv", "evidence": {}}],
                                        "hints": [], "devices": []}
        v["hw.drivers"] = lambda a: {"findings": [{"type": "firmware", "title": "Firmware fehlt: rtl_nic/rtl8153a-4.fw", "device": "eth1", "detail": "Direct firmware load failed", "state": "missing", "advice": "Eines der folgenden Pakete aus den offiziellen Quellen installieren.",
                                                    "packages": [{"package": "firmware-realtek", "installed": "", "candidate": "20240709-2", "origins": ["deb.debian.org"], "official": True, "available": True, "needs_install": True, "installable": True, "reason": ""}]}],
                                     "kernel": "6.12", "summary": {}}
        v["hw.rescan"] = lambda a: {"ok": True}
        v["net.security"] = lambda a: {"nm": True, "bluez": True, "findings": [], "pending": self.s["pending"]}
        v["events.since"] = lambda a: {"last": 0, "events": []}
        self.srv = Server(path, v, {os.getuid()})
        self.path = str(path)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def rec(self, name, a=None):
        self.calls.append((name, a))

    def net_status(self, a):
        cur = self.s["connected"]
        dev = {"iface": "wlan0", "kind": "wifi", "state": 100 if cur else 30, "state_text": "verbunden" if cur else "getrennt", "dhcp": True, "connection": {"id": cur, "uuid": "u1"} if cur else None,
               "ip4": {"addresses": [{"address": "192.168.1.77", "prefix": 24}], "gateway": "192.168.1.1", "dns": ["192.168.1.1"]} if cur else {}, "active_ap": {"ssid": cur, "signal": 72, "frequency": 5180} if cur else None, "mac": "AA:BB"}
        eth = {"iface": "eth0", "kind": "ethernet", "state": 100, "state_text": "verbunden", "dhcp": True, "carrier": True, "speed_mbps": 1000, "mac": "AA:CC", "connection": {"id": "Kabel", "uuid": "u2"},
               "ip4": {"addresses": [{"address": "192.168.1.20", "prefix": 24}], "gateway": "192.168.1.1", "dns": ["192.168.1.1"]}}
        return {"running": True, "wifi": {"present": True, "enabled": self.s["wifi_on"], "devices": [dev]}, "ethernet": {"devices": [eth]}, "known": [], "pending": self.s["pending"], "country": "DE", "rfkill": []}

    def connect(self, a):
        self.rec("wifi.connect", a)
        if a.get("ssid") == "Heimnetz" and a.get("psk") == "falsches-passwort":
            self.s["fail_next"] = True
        self.s["op_polls"] = 0
        self.s["target"] = a["ssid"]
        if a.get("ssid") == "Heimnetz" and not a.get("psk"):
            raise OpError("Für dieses Netzwerk ist ein Passwort erforderlich.", "password_required")
        return {"op": "op1", "protected": True}

    def operation(self, a):
        self.s["op_polls"] += 1
        if self.s.pop("fail_next", False) or self.s.get("failed"):
            self.s["failed"] = True
            return {"state": "failed", "message": "Das Passwort ist falsch.", "ssid": self.s["target"]}
        if self.s["op_polls"] < 2:
            return {"state": "activating", "message": "Verbinde …"}
        self.s["connected"] = self.s["target"]
        self.s["pending"] = {"seconds_left": 55, "description": f"Verbindung zu {self.s['target']}", "iface": "wlan0"}
        return {"state": "connected", "message": "Verbunden", "ssid": self.s["target"]}

    def bt_status(self, a):
        devs = [{"path": "/d1", "address": "11:22:33:44:55:66", "name": "Test-Maus", "paired": self.s["paired"], "bonded": self.s["paired"], "trusted": self.s["paired"], "blocked": False, "connected": self.s["paired"],
                 "rssi": -52, "type": "mouse", "type_label": "Maus", "adapter": "/hci0", "hid": True}]
        return {"running": True, "adapters": [{"name": "hci0", "path": "/hci0", "address": "AA:BB:CC:00:11:22", "powered": self.s["bt_on"], "discoverable": False, "pairable": False, "discovering": False}],
                "devices": devs, "sessions": [], "requests": [self.s["request"]] if self.s["request"] else [], "display": [], "rfkill": [], "uhid": True}

    def pair(self, a):
        self.rec("bt.pair", a)
        self.s["request"] = {"id": "r1", "session": "s1", "kind": "confirm", "address": a["address"], "name": "Test-Maus", "passkey": 123456, "wants_input": False, "expires_in": 55}
        return {"session": "s1"}

    def answer(self, a):
        self.rec("bt.answer", a)
        self.s["request"] = None
        self.s["paired"] = bool(a.get("accept"))
        return {"ok": True}

    def inventory(self, a):
        return {"platform": {"model": "Raspberry Pi 5 Model B", "revision": "d04170", "cpu": "Cortex-A76", "cores": 4, "memory_mb": 8062, "kernel": "6.12.25+rpt-rpi-2712", "arch": "aarch64", "os": "Debian GNU/Linux 13", "bootloader_build": None, "bootloader_update": None},
                "usb": [{"id": "1-1", "vendor_id": "046d", "product_id": "c52b", "manufacturer": "Logitech", "product": "USB Receiver", "speed_mbps": 12, "class": "00", "driver": "usb", "is_hub": False,
                         "interfaces": [{"name": "1-1:1.0", "class": "03", "subclass": "01", "protocol": "02", "driver": "usbhid", "modalias": "x"}], "bus": "1", "dev": "3"}],
                "input": [{"name": "Logitech USB Receiver Mouse", "mouse": True, "keyboard": False, "transport": "usb", "event": 4, "uniq": "", "phys": "", "sysfs": "/x"}],
                "network": [{"iface": "eth0", "kind": "ethernet", "mac": "AA:CC", "state": "up", "driver": "macb", "modalias": ""}, {"iface": "wlan0", "kind": "wifi", "mac": "AA:BB", "state": "up", "driver": "brcmfmac", "modalias": ""}],
                "rfkill": [], "bluetooth": [{"name": "hci0", "bus": "uart", "driver": "hci_uart_bcm"}], "audio": [{"card": 0, "id": "vc4hdmi0", "driver": "vc4", "name": "vc4-hdmi-0"}],
                "displays": [{"connector": "HDMI-A-1", "status": "connected", "enabled": "enabled", "monitor": "Test Monitor", "vendor": "TST", "mode": "1920x1080", "modes": 12}],
                "storage": [{"name": "mmcblk0", "model": "SD", "vendor": "", "size_gb": 64.0, "removable": False, "rotational": False, "transport": "mmc", "readonly": False}], "problems": []}

    def stop(self):
        self.srv.shutdown(); self.srv.server_close()
