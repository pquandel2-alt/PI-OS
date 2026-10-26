"""NetworkManager over D-Bus (system bus). Secrets go straight into D-Bus method arguments: never argv, never logs, never files of ours."""
import ipaddress
import logging
import socket
import struct
import threading
import time
import uuid as uuidlib

import dbus

from . import validate
from .ipc import OpError

log = logging.getLogger("pios-connd.nm")
NM = "org.freedesktop.NetworkManager"
PATH = "/org/freedesktop/NetworkManager"
DEV_TYPE = {1: "ethernet", 2: "wifi", 5: "bluetooth", 13: "bridge", 14: "generic", 16: "tun", 18: "wireguard", 29: "loopback"}
STATE = {0: "unbekannt", 10: "nicht verwaltet", 20: "nicht verfügbar", 30: "getrennt", 40: "wird vorbereitet", 50: "wird konfiguriert", 60: "braucht Anmeldung", 70: "IP-Adresse wird angefordert",
         80: "Prüfung", 90: "Gateway-Prüfung", 100: "verbunden", 110: "wird getrennt", 120: "fehlgeschlagen"}
ACTIVATED, DISCONNECTED, UNAVAILABLE, FAILED = 100, 30, 20, 120
# AP security flags (NM_802_11_AP_SEC_*)
KM_PSK, KM_8021X, KM_SAE, KM_OWE, KM_OWE_TM, KM_SUITE_B = 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000
# NMDeviceStateReason values worth explaining
REASONS = {5: "Keine IP-Adresse vom Router erhalten (DHCP/IP-Konfiguration fehlgeschlagen)", 7: "Passwort fehlt oder wurde abgelehnt", 8: "Verbindung zum Access Point wurde beendet",
           9: "WLAN-Konfiguration ungültig", 10: "Authentifizierung fehlgeschlagen: das Passwort ist wahrscheinlich falsch (oder der Router verlangt ein anderes Verfahren)",
           11: "Zeitüberschreitung bei der WLAN-Anmeldung: Signal zu schwach oder Passwort falsch", 15: "DHCP konnte nicht gestartet werden", 16: "DHCP-Fehler: der Router vergibt keine Adresse",
           40: "Kein Kabel erkannt", 53: "Netzwerk (SSID) nicht gefunden: außer Reichweite oder nur auf einem Band, das dieser Adapter nicht nutzt", 54: "Zusatzverbindung fehlgeschlagen"}


def _str(v):
    return str(v) if v is not None else ""


def _ssid(raw) -> str:
    return bytes(bytearray(int(b) for b in raw)).decode("utf-8", "replace")


def classify(flags: int, wpa: int, rsn: int) -> dict:
    """AP flags -> {security, label, supported, needs_password, reason}"""
    km = wpa | rsn
    if km & (KM_8021X | KM_SUITE_B) and not km & (KM_PSK | KM_SAE):
        return {"security": "enterprise", "label": "WPA-Enterprise (802.1X)", "supported": False, "needs_password": True, "reason": "WPA-Enterprise (802.1X/RADIUS) wird von PiOS noch nicht unterstützt."}
    if rsn & KM_SAE and rsn & KM_PSK:
        return {"security": "wpa2-wpa3", "label": "WPA2/WPA3", "supported": True, "needs_password": True, "key_mgmt": "wpa-psk"}
    if rsn & KM_SAE:
        return {"security": "wpa3", "label": "WPA3", "supported": True, "needs_password": True, "key_mgmt": "sae"}
    if rsn & KM_PSK:
        return {"security": "wpa2", "label": "WPA2", "supported": True, "needs_password": True, "key_mgmt": "wpa-psk"}
    if wpa & KM_PSK:
        return {"security": "wpa", "label": "WPA (veraltet)", "supported": True, "needs_password": True, "key_mgmt": "wpa-psk"}
    if km & (KM_OWE | KM_OWE_TM):
        return {"security": "owe", "label": "Enhanced Open (OWE)", "supported": True, "needs_password": False, "key_mgmt": "owe"}
    if flags & 0x1:
        return {"security": "wep", "label": "WEP (unsicher)", "supported": False, "needs_password": True, "reason": "WEP ist unsicher und wird nicht unterstützt."}
    return {"security": "open", "label": "Offen (unverschlüsselt)", "supported": True, "needs_password": False, "key_mgmt": "none"}


class NMClient:
    def __init__(self, bus):
        self.bus = bus
        self.ops: dict[str, dict] = {}
        self.lock = threading.Lock()

    # ---- low level -------------------------------------------------------------------------------
    def _obj(self, path, iface=None):
        o = self.bus.get_object(NM, str(path))
        return dbus.Interface(o, iface) if iface else o

    def props(self, path, iface) -> dict:
        return dbus.Interface(self.bus.get_object(NM, str(path)), "org.freedesktop.DBus.Properties").GetAll(iface)

    def prop(self, path, iface, name, default=None):
        try:
            return dbus.Interface(self.bus.get_object(NM, str(path)), "org.freedesktop.DBus.Properties").Get(iface, name)
        except dbus.DBusException:
            return default

    def running(self) -> bool:
        try:
            return bool(self.bus.name_has_owner(NM))
        except dbus.DBusException:
            return False

    def mgr(self):
        return self._obj(PATH, NM)

    # ---- snapshot ---------------------------------------------------------------------------------
    def _ip4(self, path) -> dict:
        if not path or str(path) == "/":
            return {}
        p = self.props(path, f"{NM}.IP4Config")
        addrs = []
        for a in p.get("AddressData", []) or []:
            addrs.append({"address": str(a["address"]), "prefix": int(a["prefix"])})
        dns = [str(d["address"]) for d in (p.get("NameserverData") or [])] or [socket.inet_ntoa(struct.pack("<I", int(n))) for n in (p.get("Nameservers") or [])]
        return {"addresses": addrs, "gateway": _str(p.get("Gateway")), "dns": dns, "domains": [str(d) for d in (p.get("Searches") or [])]}

    def _ip6(self, path) -> dict:
        if not path or str(path) == "/":
            return {}
        p = self.props(path, f"{NM}.IP6Config")
        return {"addresses": [{"address": str(a["address"]), "prefix": int(a["prefix"])} for a in (p.get("AddressData") or []) if not str(a["address"]).startswith("fe80")],
                "gateway": _str(p.get("Gateway")), "dns": [str(d["address"]) for d in (p.get("NameserverData") or [])] if p.get("NameserverData") else []}

    def _conn_summary(self, path) -> dict | None:
        try:
            s = self._obj(path, f"{NM}.Settings.Connection").GetSettings()
        except dbus.DBusException:
            return None
        c = s.get("connection", {})
        w = s.get("802-11-wireless", {})
        sec = s.get("802-11-wireless-security", {})
        ip4 = s.get("ipv4", {})
        return {"path": str(path), "uuid": _str(c.get("uuid")), "id": _str(c.get("id")), "type": _str(c.get("type")), "autoconnect": bool(c.get("autoconnect", True)),
                "ssid": _ssid(w["ssid"]) if "ssid" in w else "", "hidden": bool(w.get("hidden", False)), "key_mgmt": _str(sec.get("key-mgmt")) if sec else ("none" if w else ""),
                "ipv4_method": _str(ip4.get("method")), "timestamp": int(c.get("timestamp", 0) or 0), "interface": _str(c.get("interface-name"))}

    def device_info(self, path) -> dict:
        d = self.props(path, f"{NM}.Device")
        kind = DEV_TYPE.get(int(d["DeviceType"]), "other")
        info = {"path": str(path), "iface": _str(d["Interface"]), "kind": kind, "state": int(d["State"]), "state_text": STATE.get(int(d["State"]), str(d["State"])), "driver": _str(d.get("Driver")),
                "managed": bool(d.get("Managed", True)), "autoconnect": bool(d.get("Autoconnect", d.get("AutoConnect", True))), "connection": None, "ip4": {}, "ip6": {}, "dhcp": None}
        try:
            info["reason"] = int(d["StateReason"][1])
        except (KeyError, TypeError, IndexError):
            info["reason"] = 0
        ac = d.get("ActiveConnection")
        if ac and str(ac) != "/":
            acp = self.props(ac, f"{NM}.Connection.Active")
            cs = self._conn_summary(acp.get("Connection")) if acp.get("Connection") and str(acp["Connection"]) != "/" else None
            info["connection"] = {"id": cs["id"] if cs else _str(acp.get("Id")), "uuid": cs["uuid"] if cs else _str(acp.get("Uuid")), "ipv4_method": cs["ipv4_method"] if cs else ""}
            info["dhcp"] = bool(cs and cs["ipv4_method"] == "auto")
            info["ip4"] = self._ip4(acp.get("Ip4Config"))
            info["ip6"] = self._ip6(acp.get("Ip6Config"))
        if kind == "ethernet":
            w = self.props(path, f"{NM}.Device.Wired")
            info.update(mac=_str(w.get("HwAddress")).upper(), speed_mbps=int(w.get("Speed", 0)) or None, carrier=bool(w.get("Carrier", False)))
        elif kind == "wifi":
            w = self.props(path, f"{NM}.Device.Wireless")
            info.update(mac=_str(w.get("HwAddress")).upper(), bitrate_kbps=int(w.get("Bitrate", 0)) or None, last_scan=int(w.get("LastScan", -1)))
            ap = w.get("ActiveAccessPoint")
            if ap and str(ap) != "/":
                a = self.props(ap, f"{NM}.AccessPoint")
                info["active_ap"] = {"ssid": _ssid(a["Ssid"]), "signal": int(a["Strength"]), "frequency": int(a["Frequency"]), "bssid": _str(a.get("HwAddress"))}
        return info

    def devices(self) -> list[dict]:
        out = []
        for p in self.mgr().GetDevices():
            try:
                out.append(self.device_info(p))
            except dbus.DBusException as e:
                log.warning("device %s unreadable: %s", p, e.get_dbus_name())
        return out

    def connections(self) -> list[dict]:
        s = self._obj(PATH + "/Settings", f"{NM}.Settings")
        return [c for c in (self._conn_summary(p) for p in s.ListConnections()) if c]

    def status(self) -> dict:
        if not self.running():
            return {"running": False, "wifi": {"present": False, "devices": []}, "ethernet": {"devices": []}, "known": []}
        m = self.props(PATH, NM)
        devs = self.devices()
        wifi_devs = [d for d in devs if d["kind"] == "wifi"]
        known = []
        active = {d["connection"]["uuid"] for d in devs if d["connection"]}
        for c in self.connections():
            if c["type"] == "802-11-wireless":
                known.append({**c, "active": c["uuid"] in active, "secured": c["key_mgmt"] not in ("none", "")})
        known.sort(key=lambda c: -c["timestamp"])
        return {"running": True, "version": _str(m.get("Version")), "state": int(m.get("State", 0)), "connectivity": int(m.get("Connectivity", 0)), "networking_enabled": bool(m.get("NetworkingEnabled", True)),
                "wifi": {"present": bool(wifi_devs), "enabled": bool(m.get("WirelessEnabled", False)), "hardware_enabled": bool(m.get("WirelessHardwareEnabled", True)), "devices": wifi_devs},
                "ethernet": {"devices": [d for d in devs if d["kind"] == "ethernet"]}, "known": known,
                "other": [d for d in devs if d["kind"] not in ("wifi", "ethernet", "loopback") and d["managed"]]}

    # ---- Wi-Fi networks -----------------------------------------------------------------------------
    def wifi_device(self, iface=None):
        for d in self.devices():
            if d["kind"] == "wifi" and (iface is None or d["iface"] == iface):
                return d
        raise OpError("Kein WLAN-Adapter gefunden" + (f" ({iface})" if iface else ""), "no_adapter")

    def scan(self, iface=None) -> dict:
        d = self.wifi_device(iface)
        if not bool(self.prop(PATH, NM, "WirelessEnabled", True)):
            raise OpError("WLAN ist ausgeschaltet. Schalte es zuerst ein.", "wifi_disabled")
        try:
            self._obj(d["path"], f"{NM}.Device.Wireless").RequestScan({})
        except dbus.DBusException as e:
            if "NotAllowedException" in e.get_dbus_name() or "Scanning not allowed" in str(e):
                return {"scanning": False, "note": "NetworkManager scannt gerade oder erlaubt den Scan nicht sofort; die Liste zeigt den letzten Stand."}
            raise OpError("Die WLAN-Suche konnte nicht gestartet werden.", "scan_failed") from None
        return {"scanning": True}

    def networks(self, iface=None) -> list[dict]:
        d = self.wifi_device(iface)
        known = {c["ssid"]: c for c in self.connections() if c["type"] == "802-11-wireless"}
        active_ssid = (d.get("active_ap") or {}).get("ssid")
        best: dict[str, dict] = {}
        for ap in self._obj(d["path"], f"{NM}.Device.Wireless").GetAllAccessPoints():
            a = self.props(ap, f"{NM}.AccessPoint")
            ssid = _ssid(a["Ssid"])
            if not ssid:                                            # hidden networks announce an empty SSID
                continue
            sec = classify(int(a.get("Flags", 0)), int(a.get("WpaFlags", 0)), int(a.get("RsnFlags", 0)))
            entry = {"ssid": ssid, "signal": int(a["Strength"]), "frequency": int(a["Frequency"]), "band": "5 GHz" if int(a["Frequency"]) > 4000 else "2,4 GHz", "bssid": _str(a.get("HwAddress")),
                     "path": str(ap), **sec, "known": ssid in known, "uuid": known[ssid]["uuid"] if ssid in known else "", "in_use": ssid == active_ssid}
            if ssid not in best or entry["signal"] > best[ssid]["signal"]:
                best[ssid] = entry
        return sorted(best.values(), key=lambda n: (not n["in_use"], -n["signal"]))

    # ---- connect ---------------------------------------------------------------------------------------
    def _known_for(self, ssid: str):
        return next((c for c in self.connections() if c["type"] == "802-11-wireless" and c["ssid"] == ssid), None)

    def connect_wifi(self, ssid_text: str, psk=None, hidden=False, iface=None, autoconnect=True, replace_uuid_on_fail=True) -> dict:
        """Create/update a profile and activate it. Returns {op, new_uuid, previous: {...}} immediately; progress via operation()."""
        raw = validate.ssid(ssid_text)
        if psk is not None:
            psk = validate.psk(psk)
        d = self.wifi_device(iface)
        if not bool(self.prop(PATH, NM, "WirelessEnabled", True)):
            raise OpError("WLAN ist ausgeschaltet. Schalte es zuerst ein.", "wifi_disabled")
        if d["state"] in (UNAVAILABLE, 10):
            raise OpError("Der WLAN-Adapter ist nicht verfügbar (blockiert oder ohne Treiber).", "adapter_unavailable")
        nets = {n["ssid"]: n for n in self.networks(d["iface"])}
        net = nets.get(ssid_text)
        if net is None and not hidden:
            raise OpError("Netzwerk nicht gefunden. Suche erneut oder verbinde dich als verstecktes Netzwerk.", "not_found")
        if net is not None:
            if not net["supported"]:
                raise OpError(net["reason"], "unsupported_security")
            sec = net
        else:                                                      # hidden network: security can only be inferred from the user's input
            sec = {"security": "wpa2" if psk else "open", "needs_password": bool(psk), "key_mgmt": "wpa-psk" if psk else "none"}
        km = sec.get("key_mgmt", "none")
        known = self._known_for(ssid_text)
        if sec["needs_password"] and not psk and not known:
            raise OpError("Für dieses Netzwerk ist ein Passwort erforderlich.", "password_required")
        previous = self._active_summary(d)
        ap = net["path"] if net else "/"
        new_uuid = ""
        if known and not psk:
            self._obj(PATH, NM).ActivateConnection(known["path"], d["path"], ap)           # saved credentials
            used = known["uuid"]
        elif known and psk:                                                                 # new password for a known network: update the profile, keep its UUID
            conn = self._obj(known["path"], f"{NM}.Settings.Connection")
            s = conn.GetSettings()
            s = {k: dict(v) for k, v in s.items()}
            s.setdefault("802-11-wireless-security", {})
            s["802-11-wireless-security"].update({"key-mgmt": km, "psk": psk, "psk-flags": dbus.UInt32(0)})
            s["connection"]["autoconnect"] = bool(autoconnect)
            conn.Update(s)
            self._obj(PATH, NM).ActivateConnection(known["path"], d["path"], ap)
            used = known["uuid"]
        else:
            new_uuid = str(uuidlib.uuid4())
            settings = {"connection": {"id": ssid_text, "uuid": new_uuid, "type": "802-11-wireless", "autoconnect": bool(autoconnect)},
                        "802-11-wireless": {"ssid": dbus.ByteArray(raw), "mode": "infrastructure", "hidden": bool(hidden)},
                        "ipv4": {"method": "auto"}, "ipv6": {"method": "auto"}}
            if km != "none":
                sec_s = {"key-mgmt": km}
                if psk:
                    sec_s.update({"psk": psk, "psk-flags": dbus.UInt32(0)})
                settings["802-11-wireless-security"] = sec_s
            self._obj(PATH, NM).AddAndActivateConnection(settings, d["path"], ap)
            used = new_uuid
        op = uuidlib.uuid4().hex[:12]
        with self.lock:
            self.ops[op] = {"state": "activating", "iface": d["iface"], "ssid": ssid_text, "uuid": used, "new_uuid": new_uuid, "started": time.time(), "message": "", "previous": previous}
            for old in [k for k, v in self.ops.items() if time.time() - v["started"] > 600]:
                del self.ops[old]
        return {"op": op, "new_uuid": new_uuid, "previous": previous}

    def _active_summary(self, d) -> dict:
        return {"iface": d["iface"], "uuid": (d.get("connection") or {}).get("uuid", ""), "ssid": (d.get("active_ap") or {}).get("ssid", "")}

    def operation(self, op: str) -> dict:
        """Poll an activation: connected / failed (with a human reason) / still activating."""
        o = self.ops.get(op)
        if not o:
            raise OpError("Unbekannter Vorgang", "not_found")
        if o["state"] != "activating":
            return self._public(o)
        d = self.wifi_device(o["iface"])
        if d["state"] == ACTIVATED and (d.get("connection") or {}).get("uuid") == o["uuid"]:
            o["state"], o["message"] = "connected", "Verbunden"
        elif d["state"] in (FAILED, DISCONNECTED, UNAVAILABLE) and time.time() - o["started"] > 1.5:
            o["state"] = "failed"
            o["message"] = REASONS.get(d["reason"], f"Verbindung fehlgeschlagen ({d['state_text']})")
            o["reason"] = d["reason"]
            self._drop_new_profile(o)
        elif time.time() - o["started"] > 60:
            o["state"], o["message"] = "failed", "Zeitüberschreitung beim Verbinden"
            self._drop_new_profile(o)
        return self._public(o)

    def _drop_new_profile(self, o):
        """Never leave a half-working profile (typically one with a wrong password) behind; tolerate it being gone already."""
        if o.get("new_uuid"):
            try:
                self.delete_connection(o["new_uuid"])
            except (OpError, dbus.DBusException):
                pass

    @staticmethod
    def _public(o):
        return {k: o[k] for k in ("state", "iface", "ssid", "message") if k in o} | {"reason": o.get("reason", 0), "elapsed": round(time.time() - o["started"], 1)}

    # ---- radio / disconnect / forget ----------------------------------------------------------------------------------
    def set_wifi_enabled(self, enabled: bool):
        dbus.Interface(self.bus.get_object(NM, PATH), "org.freedesktop.DBus.Properties").Set(NM, "WirelessEnabled", dbus.Boolean(enabled))

    def disconnect(self, iface: str):
        iface = validate.iface(iface)
        for d in self.devices():
            if d["iface"] == iface:
                if d["state"] != ACTIVATED and d["state"] < 40:
                    return False
                self._obj(d["path"], f"{NM}.Device").Disconnect()
                return True
        raise OpError("Adapter nicht gefunden", "no_adapter")

    def connection_by_uuid(self, uuid: str):
        validate.uuid(uuid)
        c = next((c for c in self.connections() if c["uuid"] == uuid), None)
        if not c:
            raise OpError("Gespeicherte Verbindung nicht gefunden", "not_found")
        return c

    def delete_connection(self, uuid: str):
        c = self.connection_by_uuid(uuid)
        self._obj(c["path"], f"{NM}.Settings.Connection").Delete()

    def set_autoconnect(self, uuid: str, value: bool):
        c = self.connection_by_uuid(uuid)
        conn = self._obj(c["path"], f"{NM}.Settings.Connection")
        s = {k: dict(v) for k, v in conn.GetSettings().items()}
        s["connection"]["autoconnect"] = bool(value)
        conn.Update(s)

    def activate(self, uuid: str, iface=None):
        c = self.connection_by_uuid(uuid)
        dev = None
        for d in self.devices():
            if (c["type"] == "802-11-wireless" and d["kind"] == "wifi") or (c["type"] == "802-3-ethernet" and d["kind"] == "ethernet"):
                if iface is None or d["iface"] == iface:
                    dev = d; break
        if not dev:
            raise OpError("Kein passender Adapter für diese Verbindung", "no_adapter")
        self._obj(PATH, NM).ActivateConnection(c["path"], dev["path"], "/")

    # ---- ethernet: DHCP --------------------------------------------------------------------------------------------------
    def ethernet_profile(self, iface: str) -> dict | None:
        return next((c for c in self.connections() if c["type"] == "802-3-ethernet" and (c["interface"] in ("", iface))), None)

    def set_ethernet_dhcp(self, iface: str) -> dict:
        """Make the wired profile use DHCP (creates one if the adapter has none). Returns the previous IPv4 settings (for rollback)."""
        iface = validate.iface(iface)
        dev = next((d for d in self.devices() if d["iface"] == iface and d["kind"] == "ethernet"), None)
        if not dev:
            raise OpError("LAN-Adapter nicht gefunden", "no_adapter")
        prof = self.ethernet_profile(iface)
        if prof:
            conn = self._obj(prof["path"], f"{NM}.Settings.Connection")
            s = {k: dict(v) for k, v in conn.GetSettings().items()}
            previous = {k: v for k, v in s.get("ipv4", {}).items()}
            s["ipv4"] = {"method": "auto"}
            conn.Update(s)
            self._obj(PATH, NM).ActivateConnection(prof["path"], dev["path"], "/")
            return {"uuid": prof["uuid"], "previous_ipv4": _plain(previous)}
        settings = {"connection": {"id": f"PiOS LAN {iface}", "uuid": str(uuidlib.uuid4()), "type": "802-3-ethernet", "autoconnect": True, "interface-name": iface},
                    "802-3-ethernet": {}, "ipv4": {"method": "auto"}, "ipv6": {"method": "auto"}}
        self._obj(PATH, NM).AddAndActivateConnection(settings, dev["path"], "/")
        return {"uuid": settings["connection"]["uuid"], "previous_ipv4": None, "created": True}

    def restore_ipv4(self, uuid: str, previous: dict | None):
        c = self.connection_by_uuid(uuid)
        conn = self._obj(c["path"], f"{NM}.Settings.Connection")
        s = {k: dict(v) for k, v in conn.GetSettings().items()}
        s["ipv4"] = _from_plain(previous) if previous else {"method": "auto"}
        conn.Update(s)


def _plain(v):
    if isinstance(v, dict):
        return {str(k): _plain(x) for k, x in v.items()}
    if isinstance(v, (list, tuple, dbus.Array)):
        return [_plain(x) for x in v]
    if isinstance(v, dbus.Boolean):
        return bool(v)
    if isinstance(v, (dbus.Int16, dbus.Int32, dbus.Int64, dbus.UInt16, dbus.UInt32, dbus.UInt64, dbus.Byte)):
        return int(v)
    return str(v) if isinstance(v, (dbus.String, dbus.ObjectPath)) else v


def _from_plain(v):
    return {k: dbus.Array([dbus.Dictionary(a, signature="sv") for a in x], signature="a{sv}") if k == "address-data" and isinstance(x, list) else x for k, x in v.items()}
