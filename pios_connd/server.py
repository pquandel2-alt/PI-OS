"""pios-connd: connectivity & hardware daemon. `python3 -m pios_connd.server`"""
import logging
import os
import pwd
import re
import threading
import time
from collections import deque
from pathlib import Path

import dbus

from . import drivers, hw, inputdiag, validate
from .ipc import OpError, Server
from .netguard import Guard, run

log = logging.getLogger("pios-connd")
REGDOM_CONF = Path(os.getenv("PIOS_REGDOM_CONF", "/etc/modprobe.d/pios-regdom.conf"))
DEFAULT_COUNTRY = os.getenv("PIOS_WIFI_COUNTRY", "DE")


class Events:
    """Ring buffer polled by the web backend (-> notifications + audit log). Never contains secrets."""
    def __init__(self, size=300):
        self.buf, self.seq, self.lock = deque(maxlen=size), 0, threading.Lock()

    def add(self, name: str, severity: str = "info", **detail):
        with self.lock:
            self.seq += 1
            self.buf.append({"id": self.seq, "time": int(time.time()), "name": name, "severity": severity, "detail": {k: (v if isinstance(v, (int, float, bool)) or v is None else str(v)[:200]) for k, v in detail.items()}})

    def since(self, last: int) -> dict:
        with self.lock:
            return {"last": self.seq, "events": [e for e in self.buf if e["id"] > last]}


class Connd:
    def __init__(self, nm, bt, state_dir: Path, roots: hw.Roots = None, runner=run, events: Events = None, allowed_packages=None, confirm_seconds=60):
        self.nm, self.bt, self.runner = nm, bt, runner
        self.roots = roots or hw.Roots()
        self.events = events or Events()
        self.state = Path(state_dir)
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.guard = Guard(nm, self.state, runner=runner, confirm_seconds=confirm_seconds, events=self.events.add)
        self.allowed = set(allowed_packages) if allowed_packages is not None else _allowed_packages()
        if bt is not None:
            bt.events = self.events.add
        self.verbs = {
            "ping": lambda a: {"ok": True}, "events.since": self.ev_since,
            "net.status": self.net_status, "net.summary": self.net_summary, "net.operation": self.net_operation, "net.confirm": lambda a: self.guard.confirm(), "net.revert": lambda a: self.guard.revert("manuell"),
            "wifi.scan": self.wifi_scan, "wifi.networks": self.wifi_networks, "wifi.connect": self.wifi_connect, "wifi.set_enabled": self.wifi_set_enabled, "wifi.forget": self.wifi_forget,
            "wifi.autoconnect": self.wifi_autoconnect, "wifi.set_country": self.wifi_set_country, "net.disconnect": self.net_disconnect, "eth.set_dhcp": self.eth_set_dhcp,
            "bt.status": self.bt_status, "bt.pairing": lambda a: self._bt().pairing_state(), "bt.set_powered": self.bt_power, "bt.scan": self.bt_scan, "bt.scan_stop": lambda a: self._bt().stop_scan(),
            "bt.pair": lambda a: self._bt().pair(a.get("address")), "bt.answer": self.bt_answer, "bt.cancel": lambda a: self._bt().cancel_pairing(a.get("session")),
            "bt.connect": lambda a: self._bt().connect(a.get("address")), "bt.disconnect": lambda a: self._bt().disconnect(a.get("address")),
            "bt.trust": lambda a: self._bt().set_trusted(a.get("address"), a.get("trusted")) or {"ok": True}, "bt.remove": lambda a: self._bt().remove(a.get("address")) or {"ok": True},
            "net.security": self.net_security, "hw.inventory": self.hw_inventory, "hw.input_diag": self.hw_input_diag, "hw.drivers": self.hw_drivers, "hw.rescan": self.hw_rescan,
        }

    # ------------------------------------------------------------------------------------ plumbing
    def _bt(self):
        if self.bt is None or not self.bt.running():
            raise OpError("Der Bluetooth-Dienst (bluetoothd) läuft nicht.", "bt_unavailable")
        return self.bt

    def ev_since(self, a):
        return self.events.since(int(a.get("since", 0)) if isinstance(a.get("since", 0), int) else 0)

    def _client_risk(self, a):
        return self.guard.admin_iface(a.get("client_ip"))

    # ------------------------------------------------------------------------------------ network
    def country(self) -> str:
        rc, out = self.runner(["iw", "reg", "get"])
        m = re.search(r"country ([A-Z0-9]{2}):", out) if rc == 0 else None
        return m.group(1) if m else ""

    def net_status(self, a):
        st = self.nm.status()
        st["pending"] = self.guard.pending()
        st["country"] = self.country()
        st["rfkill"] = [r for r in hw.rfkill(self.roots) if r["type"] in ("wlan", "bluetooth")]
        st["regdb"] = os.path.exists("/lib/firmware/regulatory.db") or os.path.exists("/usr/lib/firmware/regulatory.db") or None
        return st

    def net_summary(self, a):
        """Compact state for the system tray (shown to every signed-in user): no MAC addresses, no saved networks."""
        if not self.nm.running():
            return {"online": False, "nm": False, "wifi": {"present": False}, "ethernet": {"present": False}, "bluetooth": self._bt_summary(), "pending": None}
        st = self.nm.status()
        w = next(iter(st["wifi"]["devices"]), None)
        e = next((d for d in st["ethernet"]["devices"] if d["state"] == 100), None) or next(iter(st["ethernet"]["devices"]), None)
        wifi = {"present": st["wifi"]["present"], "enabled": st["wifi"]["enabled"], "connected": bool(w and w["state"] == 100), "ssid": (w or {}).get("active_ap", {}).get("ssid", ""),
                "signal": (w or {}).get("active_ap", {}).get("signal"), "ip": ((w or {}).get("ip4", {}).get("addresses") or [{}])[0].get("address", "")}
        eth = {"present": bool(e), "connected": bool(e and e["state"] == 100), "carrier": bool(e and e.get("carrier")), "ip": ((e or {}).get("ip4", {}).get("addresses") or [{}])[0].get("address", ""), "speed_mbps": (e or {}).get("speed_mbps")}
        return {"online": wifi["connected"] or eth["connected"], "nm": True, "wifi": wifi, "ethernet": eth, "bluetooth": self._bt_summary(), "pending": self.guard.pending()}

    def _bt_summary(self):
        try:
            if self.bt is None or not self.bt.running():
                return {"present": False}
            ads = self.bt.adapters()
            return {"present": bool(ads), "powered": any(x["powered"] for x in ads), "connected": [d["name"] for d in self.bt.devices() if d["connected"]][:5]}
        except dbus.DBusException:
            return {"present": False}

    def net_security(self, a):
        """Facts for the NOVA Shield connectivity check. Each finding is a real observation; what could not be read is reported as such."""
        out = {"nm": self.nm.running(), "bluez": bool(self.bt is not None and self.bt.running()), "findings": [], "pending": self.guard.pending()}
        f = out["findings"]
        if out["nm"]:
            st = self.nm.status()
            if st["wifi"]["present"]:
                out["country"] = self.country()
                if not out["country"] or out["country"] == "00":
                    f.append({"id": "wifi_country", "level": "limited", "text": "Kein WLAN-Land (Regulierungsdomäne) gesetzt: Kanäle und Sendeleistung sind nicht an die lokale Regulierung angepasst."})
            open_auto = [c["ssid"] for c in st["known"] if not c["secured"] and c.get("autoconnect")]
            if open_auto:
                f.append({"id": "open_wifi_autoconnect", "level": "attention", "text": "Automatische Verbindung zu unverschlüsseltem WLAN gespeichert: " + ", ".join(open_auto[:3])})
        if out["bluez"]:
            for ad in self.bt.adapters():
                if ad["discoverable"]:
                    f.append({"id": "bt_discoverable", "level": "attention", "text": f"Bluetooth-Adapter {ad['address']} ist dauerhaft sichtbar (Discoverable)."})
                if ad["pairable"] and not any(x["state"] in ("pairing", "awaiting_user") for x in self.bt.pairing_state()["sessions"]):
                    f.append({"id": "bt_pairable", "level": "attention", "text": "Bluetooth nimmt Kopplungsanfragen an, ohne dass eine Kopplung gestartet wurde."})
        if out["pending"]:
            f.append({"id": "net_pending", "level": "attention", "text": f"Eine Netzwerkänderung wartet auf Bestätigung ({out['pending']['seconds_left']} s)."})
        return out

    def net_operation(self, a):
        op = str(a.get("op", ""))
        r = self.nm.operation(op)
        if r["state"] == "failed" and self.guard.revert_if_op(op, r["message"]):
            r["reverted"] = True
            r["message"] += " Die vorherige Verbindung wurde wiederhergestellt."
        if r["state"] == "connected":
            self.events.add("net.wifi_connected", ssid=r.get("ssid"))
        elif r["state"] == "failed":
            self.events.add("net.wifi_failed", severity="warning", ssid=r.get("ssid"), reason=r.get("message"))
        return r

    def wifi_scan(self, a):
        return self.nm.scan(self._opt_iface(a))

    def wifi_networks(self, a):
        return {"networks": self.nm.networks(self._opt_iface(a))}

    @staticmethod
    def _opt_iface(a):
        return validate.iface(a["iface"]) if a.get("iface") else None

    def wifi_connect(self, a):
        ssid = a.get("ssid")
        risk = self._client_risk(a)
        if self.guard.pending():
            raise OpError("Eine Netzwerkänderung wartet noch auf Bestätigung.", "pending")
        r = self.nm.connect_wifi(ssid, a.get("psk") if a.get("psk") else None, validate.boolean(a.get("hidden", False), "hidden"), self._opt_iface(a),
                                 validate.boolean(a.get("autoconnect", True), "autoconnect"))
        iface = self.nm.ops[r["op"]]["iface"]
        protected = bool(risk and risk == iface)
        if protected:
            prev = r["previous"]
            undo = {"delete_uuids": [r["new_uuid"]] if r["new_uuid"] else [], "activate": {"uuid": prev["uuid"], "iface": iface} if prev.get("uuid") else None}
            self.guard.begin("wifi_connect", f"WLAN wechselt zu „{ssid}“", iface, undo, op=r["op"])
        self.events.add("net.wifi_connect_requested", ssid=ssid, protected=protected, hidden=bool(a.get("hidden")))
        return {"op": r["op"], "protected": protected, "hint": "Die IP-Adresse deines Geräts kann sich ändern. Öffne PiOS danach unter der neuen Adresse (pios.local) und bestätige die Änderung."
                if protected else ""}

    def wifi_set_enabled(self, a):
        enabled = validate.boolean(a.get("enabled"), "enabled")
        risk = self._client_risk(a)
        if not enabled and risk:
            dev = next((d for d in self.nm.devices() if d["iface"] == risk and d["kind"] == "wifi"), None)
            if dev:
                prev = (dev.get("connection") or {}).get("uuid")
                self.guard.begin("wifi_off", "WLAN wird ausgeschaltet", risk, {"wifi_enabled": True, "activate": {"uuid": prev, "iface": risk} if prev else None})
        self.nm.set_wifi_enabled(enabled)
        if enabled:
            self.runner(["rfkill", "unblock", "wlan"])
        self.events.add("net.wifi_enabled" if enabled else "net.wifi_disabled")
        return {"enabled": enabled, "protected": bool(self.guard.pending())}

    def wifi_forget(self, a):
        uuid = validate.uuid(a.get("uuid"))
        risk = self._client_risk(a)
        for d in self.nm.devices():
            if (d.get("connection") or {}).get("uuid") == uuid and (risk == d["iface"]):
                raise OpError("Dieses Netzwerk trägt gerade deine Verbindung zu PiOS. Verbinde dich zuerst über einen anderen Weg (Ethernet oder HDMI-Bildschirm) oder wechsle das Netzwerk.", "in_use_by_admin")
        for d in self.nm.devices():
            if (d.get("connection") or {}).get("uuid") == uuid:
                self.nm.disconnect(d["iface"])
        self.nm.delete_connection(uuid)
        self.events.add("net.wifi_forgotten")
        return {"ok": True}

    def wifi_autoconnect(self, a):
        self.nm.set_autoconnect(validate.uuid(a.get("uuid")), validate.boolean(a.get("value"), "value"))
        return {"ok": True}

    def net_disconnect(self, a):
        iface = validate.iface(a.get("iface"))
        risk = self._client_risk(a)
        if risk == iface:
            dev = next((d for d in self.nm.devices() if d["iface"] == iface), None)
            prev = ((dev or {}).get("connection") or {}).get("uuid")
            self.guard.begin("disconnect", f"{iface} wird getrennt", iface, {"activate": {"uuid": prev, "iface": iface} if prev else None})
        done = self.nm.disconnect(iface)
        self.events.add("net.disconnected", iface=iface)
        return {"disconnected": done, "protected": bool(risk == iface)}

    def eth_set_dhcp(self, a):
        iface = validate.iface(a.get("iface"))
        risk = self._client_risk(a)
        if self.guard.pending():
            raise OpError("Eine Netzwerkänderung wartet noch auf Bestätigung.", "pending")
        r = self.nm.set_ethernet_dhcp(iface)
        protected = bool(risk == iface and r.get("previous_ipv4") and r["previous_ipv4"].get("method") not in (None, "auto"))
        if protected:
            self.guard.begin("ethernet_dhcp", f"{iface} wechselt auf DHCP", iface, {"ipv4": {"uuid": r["uuid"], "previous": r["previous_ipv4"]}, "activate": {"uuid": r["uuid"], "iface": iface}})
        self.events.add("net.ethernet_dhcp", iface=iface, protected=protected)
        return {"uuid": r["uuid"], "protected": protected}

    def wifi_set_country(self, a):
        code = validate.country(a.get("code"))
        REGDOM_CONF.parent.mkdir(parents=True, exist_ok=True)
        tmp = REGDOM_CONF.with_suffix(".tmp")
        tmp.write_text(f"# written by PiOS NOVA (Einstellungen -> WLAN): regulatory domain\noptions cfg80211 ieee80211_regdom={code}\n")
        os.replace(tmp, REGDOM_CONF)
        rc, out = self.runner(["iw", "reg", "set", code])
        if rc not in (0, 127):
            raise OpError("Das WLAN-Land konnte nicht gesetzt werden: " + out.strip()[:150], "regdom_failed")
        self.runner(["rfkill", "unblock", "wlan"])
        try:
            self.nm.set_wifi_enabled(True)
        except dbus.DBusException:
            pass
        self.events.add("net.wifi_country", country=code)
        return {"country": code, "active": self.country() or code, "persisted": True}

    def first_run(self):
        """Once, on a fresh image: pi-gen ships Wi-Fi switched off until a regulatory country exists. Apply the image default country and enable Wi-Fi."""
        marker = self.state / "radio-initialised"
        if marker.exists() or not self.nm.running():
            return False
        try:
            if not self.country() or self.country() == "00":
                self.wifi_set_country({"code": DEFAULT_COUNTRY})        # also unblocks the radio and enables Wi-Fi in NetworkManager
            else:
                self.runner(["rfkill", "unblock", "wlan"])
                self.nm.set_wifi_enabled(True)
            marker.write_text("1\n")
            return True
        except Exception as e:                                                       # noqa: BLE001
            log.warning("radio first-run failed: %s", e)
            return False

    # ------------------------------------------------------------------------------------ bluetooth
    def bt_status(self, a):
        st = self._bt().status()
        st["rfkill"] = [r for r in hw.rfkill(self.roots) if r["type"] == "bluetooth"]
        st["uhid"] = (self.roots.dev / "uhid").exists()
        return st

    def bt_power(self, a):
        powered = validate.boolean(a.get("powered"), "powered")
        if powered:
            self.runner(["rfkill", "unblock", "bluetooth"])
        self._bt().set_powered(powered)
        return {"powered": powered}

    def bt_scan(self, a):
        return self._bt().start_scan(a.get("seconds", 30))

    def bt_answer(self, a):
        return self._bt().answer(str(a.get("id", "")), a.get("accept"), a.get("value"))

    # ------------------------------------------------------------------------------------ hardware
    def kernel_log(self) -> str:
        rc, out = self.runner(["journalctl", "-k", "-b", "--no-pager", "-o", "cat", "-n", "1500"])
        return out if rc == 0 else ""

    def hw_inventory(self, a):
        return hw.inventory(self.roots, self.runner)

    def hw_input_diag(self, a):
        return inputdiag.diagnose(self.roots, self.runner)

    def hw_drivers(self, a):
        return drivers.analyse(hw.inventory(self.roots, self.runner), self.kernel_log(), self.runner, self.allowed)

    def hw_rescan(self, a):
        self.runner(["udevadm", "trigger", "--action=add", "--subsystem-match=usb", "--subsystem-match=input", "--subsystem-match=bluetooth"])
        self.runner(["udevadm", "settle", "--timeout=5"])
        self.events.add("hw.rescan")
        return {"ok": True}

    # ------------------------------------------------------------------------------------ watchers
    def watch(self, stop: threading.Event, interval=3.0):
        """Hot-plug detection by diffing sysfs/NetworkManager/BlueZ snapshots (robust, no extra daemons)."""
        prev = {}
        while not stop.wait(interval):
            try:
                usb = {f"{u['vendor_id']}:{u['product_id']}@{u['id']}": (u["product"] or "USB-Gerät") for u in hw.usb_devices(self.roots) if not u["is_hub"]}
                inp = {f"{d['name']}#{d['event']}": d["name"] for d in hw.input_devices(self.roots) if d["event"] is not None}
                for key, snap, label in (("usb", usb, "usb"), ("input", inp, "input")):
                    old = prev.get(key)
                    if old is not None:
                        for k in snap.keys() - old.keys():
                            self.events.add(f"hw.{label}_added", device=snap[k])
                        for k in old.keys() - snap.keys():
                            self.events.add(f"hw.{label}_removed", device=old[k])
                    prev[key] = snap
                if self.nm.running():
                    s = self.net_summary({})
                    sig = (s["wifi"].get("connected"), s["wifi"].get("ssid"), s["wifi"].get("ip"), s["ethernet"].get("connected"), s["ethernet"].get("ip"))
                    old = prev.get("net")
                    if old is not None and old != sig:
                        self.events.add("net.state_changed", wifi=bool(sig[0]), ssid=sig[1], ethernet=bool(sig[3]), ip=sig[2] or sig[4])
                    prev["net"] = sig
                if self.bt is not None and self.bt.running():
                    cur = {d["address"]: d["name"] for d in self.bt.devices() if d["connected"]}
                    old = prev.get("bt")
                    if old is not None:
                        for k in cur.keys() - old.keys():
                            self.events.add("bt.connected", device=cur[k])
                        for k in old.keys() - cur.keys():
                            self.events.add("bt.disconnected", device=old[k])
                    prev["bt"] = cur
            except Exception:                                                        # noqa: BLE001
                log.exception("watcher")


def _allowed_packages():
    try:
        from pios_sysops.packages import ALLOWED
        return set(ALLOWED)
    except ImportError:
        return set()


def main():
    import dbus.mainloop.glib
    from gi.repository import GLib
    from .bluez import BluezClient
    from .nm import NMClient
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    loop = GLib.MainLoop()
    threading.Thread(target=loop.run, daemon=True, name="glib").start()
    bus = dbus.SystemBus(mainloop=dbus.mainloop.glib.DBusGMainLoop())
    bt = BluezClient(bus, glib_call=lambda fn, *a: GLib.idle_add(lambda: (fn(*a), False)[1]))
    d = Connd(NMClient(bus), bt, Path(os.getenv("PIOS_CONND_STATE", "/var/lib/pios-connd")))
    d.guard.recover()
    d.first_run()
    uids = {0}
    try:
        uids.add(pwd.getpwnam("pios").pw_uid)
    except KeyError:
        pass
    sock = Path(os.getenv("PIOS_CONND_SOCKET", "/run/pios-connd/connd.sock"))
    srv = Server(sock, d.verbs, uids)
    os.chmod(sock, 0o660)
    stop = threading.Event()
    threading.Thread(target=d.watch, args=(stop,), daemon=True, name="watch").start()
    log.info("pios-connd ready (nm=%s bluez=%s)", d.nm.running(), bt.running())
    try:
        srv.serve_forever()
    finally:
        stop.set()
        bt.close()


if __name__ == "__main__":
    main()
