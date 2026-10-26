"""BlueZ over D-Bus: adapters, discovery, pairing with a user-bound agent, connect/trust/remove.

Pairing security: a pairing request from a remote device is answered ONLY while a pairing session that an administrator started for exactly
that device is open. Everything else (including numeric-comparison confirmations, PIN and passkey prompts) is queued for the user with a
60 s timeout and rejected afterwards. Unsolicited requests are rejected at once and logged."""
import logging
import threading
import time
import uuid as uuidlib

import dbus
import dbus.service

from . import validate
from .ipc import OpError

log = logging.getLogger("pios-connd.bt")
BLUEZ = "org.bluez"
AGENT_PATH = "/org/pios/bluetooth/agent"
REQUEST_TIMEOUT = 60
PAIR_TIMEOUT = 90
SCAN_MAX = 60

ERRORS = {"org.bluez.Error.AuthenticationFailed": "Pairing fehlgeschlagen: falsche PIN oder das Gerät hat abgelehnt.",
          "org.bluez.Error.AuthenticationCanceled": "Pairing abgebrochen.", "org.bluez.Error.AuthenticationRejected": "Das Gerät hat das Pairing abgelehnt.",
          "org.bluez.Error.AuthenticationTimeout": "Zeitüberschreitung beim Pairing: Gerät in den Kopplungsmodus versetzen und erneut versuchen.",
          "org.bluez.Error.ConnectionAttemptFailed": "Verbindung nicht möglich: Gerät außer Reichweite, ausgeschaltet oder nicht im Kopplungsmodus.",
          "org.bluez.Error.AlreadyExists": "Das Gerät ist bereits gekoppelt.", "org.bluez.Error.AlreadyConnected": "Das Gerät ist bereits verbunden.",
          "org.bluez.Error.NotReady": "Der Bluetooth-Adapter ist nicht bereit (ausgeschaltet?).", "org.bluez.Error.NotAvailable": "Nicht verfügbar.",
          "org.bluez.Error.InProgress": "Ein Vorgang läuft bereits.", "org.bluez.Error.Failed": "Der Vorgang ist fehlgeschlagen.", "org.bluez.Error.DoesNotExist": "Gerät nicht gefunden.",
          "org.bluez.Error.Rejected": "Abgelehnt.", "org.bluez.Error.NotConnected": "Das Gerät ist nicht verbunden.", "org.bluez.Error.NotSupported": "Wird vom Gerät/Adapter nicht unterstützt.",
          "org.freedesktop.DBus.Error.NoReply": "Keine Antwort vom Bluetooth-Dienst (Zeitüberschreitung)."}
HID_UUID = "00001124"
A2DP_SINK = "0000110b"


def explain(e: dbus.DBusException) -> str:
    name = e.get_dbus_name() or ""
    return ERRORS.get(name, f"Bluetooth-Fehler ({name.rsplit('.', 1)[-1] or 'unbekannt'})")


def device_type(icon: str, cod: int, appearance: int, uuids) -> tuple[str, str]:
    """-> (type, German label). Classic: icon/class-of-device; LE: GAP appearance."""
    u = " ".join(str(x).lower() for x in (uuids or []))
    if icon == "input-mouse" or (cod >> 8) & 0x1F == 5 and (cod >> 6) & 3 == 2 or appearance == 0x03C2:
        return "mouse", "Maus"
    if icon == "input-keyboard" or (cod >> 8) & 0x1F == 5 and (cod >> 6) & 3 == 1 or appearance == 0x03C1:
        return "keyboard", "Tastatur"
    if icon in ("input-gaming",) or (cod >> 8) & 0x1F == 5 and (cod >> 2) & 0xF in (1, 2):
        return "gamepad", "Controller"
    if icon in ("audio-headset", "audio-headphones") or (cod >> 8) & 0x1F == 4 and (cod >> 2) & 0x3F in (1, 6):
        return "headphones", "Kopfhörer/Headset"
    if icon == "audio-speakers" or (cod >> 8) & 0x1F == 4 and (cod >> 2) & 0x3F in (5, 7, 8) or (A2DP_SINK in u and not icon):
        return "speaker", "Lautsprecher"
    if icon == "audio-card" or (cod >> 8) & 0x1F == 4:
        return "audio", "Audiogerät"
    if icon == "phone" or (cod >> 8) & 0x1F == 2:
        return "phone", "Telefon"
    if icon == "computer" or (cod >> 8) & 0x1F == 1:
        return "computer", "Computer"
    if HID_UUID in u:
        return "hid", "Eingabegerät"
    return "other", "Gerät"


PRIORITY = {"mouse": 0, "keyboard": 1, "headphones": 2, "speaker": 3, "gamepad": 4, "hid": 5, "audio": 6}


class Agent(dbus.service.Object):
    """org.bluez.Agent1. Requests are deferred (async replies) until the user answers via the API or the request times out."""

    def __init__(self, bus, owner: "BluezClient"):
        super().__init__(bus, AGENT_PATH)
        self.owner = owner

    def _ask(self, kind, device, reply, error, passkey=None, wants_input=False):
        self.owner.on_request(kind, str(device), reply, error, passkey, wants_input)

    @dbus.service.method("org.bluez.Agent1", in_signature="", out_signature="")
    def Release(self):
        log.info("agent released by bluez")

    @dbus.service.method("org.bluez.Agent1", in_signature="o", out_signature="s", async_callbacks=("reply", "error"))
    def RequestPinCode(self, device, reply, error):
        self._ask("pin", device, reply, error, wants_input=True)

    @dbus.service.method("org.bluez.Agent1", in_signature="os", out_signature="")
    def DisplayPinCode(self, device, pincode):
        self.owner.on_display(str(device), "pin", str(pincode))

    @dbus.service.method("org.bluez.Agent1", in_signature="o", out_signature="u", async_callbacks=("reply", "error"))
    def RequestPasskey(self, device, reply, error):
        self._ask("passkey", device, reply, error, wants_input=True)

    @dbus.service.method("org.bluez.Agent1", in_signature="ouq", out_signature="")
    def DisplayPasskey(self, device, passkey, entered):
        self.owner.on_display(str(device), "passkey", f"{int(passkey):06d}", int(entered))

    @dbus.service.method("org.bluez.Agent1", in_signature="ou", out_signature="", async_callbacks=("reply", "error"))
    def RequestConfirmation(self, device, passkey, reply, error):
        self._ask("confirm", device, reply, error, passkey=f"{int(passkey):06d}")

    @dbus.service.method("org.bluez.Agent1", in_signature="o", out_signature="", async_callbacks=("reply", "error"))
    def RequestAuthorization(self, device, reply, error):
        self._ask("authorize", device, reply, error)

    @dbus.service.method("org.bluez.Agent1", in_signature="os", out_signature="", async_callbacks=("reply", "error"))
    def AuthorizeService(self, device, uuid, reply, error):
        # service authorisation for an already paired device: only allowed for devices the user trusted
        self.owner.on_service_authorization(str(device), str(uuid), reply, error)

    @dbus.service.method("org.bluez.Agent1", in_signature="", out_signature="")
    def Cancel(self):
        self.owner.on_cancel()


def rejected():
    return dbus.DBusException("Pairing nicht erlaubt", name="org.bluez.Error.Rejected")


class BluezClient:
    def __init__(self, bus, events=None, glib_call=None):
        self.bus = bus
        self.events = events or (lambda *a, **k: None)
        self.glib_call = glib_call or (lambda fn, *a: fn(*a))      # run on the main-loop thread (GLib.idle_add in the daemon)
        self.lock = threading.RLock()
        self.sessions: dict[str, dict] = {}
        self.requests: dict[str, dict] = {}
        self.display: dict[str, dict] = {}
        self.agent = None
        self.scan_timer = None

    # ---- D-Bus helpers ---------------------------------------------------------------------------
    def _om(self):
        return dbus.Interface(self.bus.get_object(BLUEZ, "/"), "org.freedesktop.DBus.ObjectManager")

    def running(self) -> bool:
        try:
            return bool(self.bus.name_has_owner(BLUEZ))
        except dbus.DBusException:
            return False

    def _managed(self) -> dict:
        return self._om().GetManagedObjects()

    def adapters(self) -> list[dict]:
        out = []
        for path, ifs in self._managed().items():
            a = ifs.get("org.bluez.Adapter1")
            if a is not None:
                out.append({"path": str(path), "name": str(path).rsplit("/", 1)[-1], "address": str(a.get("Address", "")), "alias": str(a.get("Alias", "")), "powered": bool(a.get("Powered", False)),
                            "discoverable": bool(a.get("Discoverable", False)), "pairable": bool(a.get("Pairable", False)), "discovering": bool(a.get("Discovering", False))})
        return sorted(out, key=lambda a: a["name"])

    def devices(self) -> list[dict]:
        out = []
        for path, ifs in self._managed().items():
            d = ifs.get("org.bluez.Device1")
            if d is None:
                continue
            kind, label = device_type(str(d.get("Icon", "")), int(d.get("Class", 0) or 0), int(d.get("Appearance", 0) or 0), d.get("UUIDs", []))
            out.append({"path": str(path), "address": str(d.get("Address", "")).upper(), "name": str(d.get("Alias") or d.get("Name") or d.get("Address", "")), "paired": bool(d.get("Paired", False)),
                        "bonded": bool(d.get("Bonded", False)), "trusted": bool(d.get("Trusted", False)), "blocked": bool(d.get("Blocked", False)), "connected": bool(d.get("Connected", False)),
                        "rssi": int(d["RSSI"]) if "RSSI" in d else None, "type": kind, "type_label": label, "adapter": str(d.get("Adapter", "")),
                        "hid": any(HID_UUID in str(u).lower() for u in d.get("UUIDs", []))})
        out.sort(key=lambda d: (not d["connected"], not d["paired"], PRIORITY.get(d["type"], 9), d["name"].lower()))
        return out

    def _device_path(self, address: str) -> str:
        address = validate.mac(address)
        for d in self.devices():
            if d["address"] == address:
                return d["path"]
        raise OpError("Gerät nicht gefunden. Suche zuerst nach Geräten.", "not_found")

    def _adapter(self, name=None) -> dict:
        ads = self.adapters()
        if not ads:
            raise OpError("Kein Bluetooth-Controller gefunden.", "no_adapter")
        return next((a for a in ads if name in (None, a["name"])), ads[0])

    def _dev(self, path):
        return dbus.Interface(self.bus.get_object(BLUEZ, path), "org.bluez.Device1")

    def _props(self, path, iface="org.bluez.Device1"):
        return dbus.Interface(self.bus.get_object(BLUEZ, path), "org.freedesktop.DBus.Properties")

    # ---- status ------------------------------------------------------------------------------------------
    def status(self) -> dict:
        if not self.running():
            return {"running": False, "adapters": [], "devices": [], "sessions": [], "requests": []}
        with self.lock:
            return {"running": True, "adapters": self.adapters(), "devices": self.devices(), "sessions": [self._pub_session(s) for s in self.sessions.values()],
                    "requests": [self._pub_request(r) for r in self.requests.values() if r["state"] == "waiting"], "display": list(self.display.values())}

    def pairing_state(self) -> dict:
        """In-memory view of pairing sessions/requests (no D-Bus round trip: stays responsive while BlueZ is busy pairing)."""
        with self.lock:
            return {"sessions": [self._pub_session(s) for s in self.sessions.values()], "requests": [self._pub_request(r) for r in self.requests.values() if r["state"] == "waiting"],
                    "display": list(self.display.values())}

    @staticmethod
    def _pub_session(s):
        return {k: s[k] for k in ("id", "address", "state", "message", "started") if k in s}

    @staticmethod
    def _pub_request(r):
        return {"id": r["id"], "session": r["session"], "kind": r["kind"], "address": r["address"], "name": r["name"], "passkey": r.get("passkey"), "wants_input": r["wants_input"],
                "expires_in": max(0, round(r["deadline"] - time.monotonic()))}

    # ---- power / discovery ----------------------------------------------------------------------------------
    def set_powered(self, powered: bool, adapter=None):
        a = self._adapter(adapter)
        self._props(a["path"]).Set("org.bluez.Adapter1", "Powered", dbus.Boolean(validate.boolean(powered, "powered")))

    def start_scan(self, seconds=30, adapter=None):
        seconds = validate.seconds(seconds, 5, SCAN_MAX, "Suchdauer")
        a = self._adapter(adapter)
        if not a["powered"]:
            raise OpError("Bluetooth ist ausgeschaltet. Schalte es zuerst ein.", "powered_off")
        ad = dbus.Interface(self.bus.get_object(BLUEZ, a["path"]), "org.bluez.Adapter1")
        try:
            ad.SetDiscoveryFilter({"Transport": "auto", "DuplicateData": False})
            if not a["discovering"]:
                ad.StartDiscovery()
        except dbus.DBusException as e:
            raise OpError(explain(e), "scan_failed") from None
        if self.scan_timer:
            self.scan_timer.cancel()
        self.scan_timer = threading.Timer(seconds, self.stop_scan, args=(adapter,))
        self.scan_timer.daemon = True
        self.scan_timer.start()
        return {"scanning": True, "seconds": seconds}

    def stop_scan(self, adapter=None):
        try:
            a = self._adapter(adapter)
            if a["discovering"]:
                dbus.Interface(self.bus.get_object(BLUEZ, a["path"]), "org.bluez.Adapter1").StopDiscovery()
        except (OpError, dbus.DBusException):
            pass
        if self.scan_timer:
            self.scan_timer.cancel(); self.scan_timer = None
        return {"scanning": False}

    # ---- agent registration ---------------------------------------------------------------------------------------
    def ensure_agent(self):
        """Register once per bluetoothd instance (re-register after a bluetoothd restart, detected by a changed bus-name owner)."""
        try:
            owner = str(self.bus.get_name_owner(BLUEZ))
        except dbus.DBusException:
            owner = ""
        if self.agent is not None and owner and owner == getattr(self, "_registered_owner", None):
            return
        if self.agent is None:
            self.agent = Agent(self.bus, self)
        self._registered_owner = owner
        mgr = dbus.Interface(self.bus.get_object(BLUEZ, "/org/bluez"), "org.bluez.AgentManager1")
        try:
            mgr.RegisterAgent(AGENT_PATH, "KeyboardDisplay")
        except dbus.DBusException as e:
            if e.get_dbus_name() != "org.bluez.Error.AlreadyExists":
                raise OpError(explain(e), "agent_failed") from None
        try:
            mgr.RequestDefaultAgent(AGENT_PATH)
        except dbus.DBusException:
            pass

    def close(self):
        """Unregister the agent (daemon shutdown / tests)."""
        self.stop_scan()
        if self.agent is not None:
            try:
                dbus.Interface(self.bus.get_object(BLUEZ, "/org/bluez"), "org.bluez.AgentManager1").UnregisterAgent(AGENT_PATH)
            except dbus.DBusException:
                pass
            self.agent.remove_from_connection()
            self.agent = None
            self._registered_owner = None

    # ---- pairing -----------------------------------------------------------------------------------------------------
    def pair(self, address: str) -> dict:
        """Start pairing for exactly this device. The session is the only thing that authorises agent requests."""
        address = validate.mac(address)
        with self.lock:                                           # cheap local check first: no D-Bus round trip while another pairing runs
            if any(x["state"] in ("pairing", "awaiting_user") for x in self.sessions.values()):
                raise OpError("Es läuft bereits ein Pairing-Vorgang.", "busy")
        path = self._device_path(address)
        a = self._adapter()
        if not a["powered"]:
            raise OpError("Bluetooth ist ausgeschaltet. Schalte es zuerst ein.", "powered_off")
        dev = next(d for d in self.devices() if d["address"] == address)
        if dev["paired"]:
            raise OpError("Das Gerät ist bereits gekoppelt." + ("" if dev["connected"] else " Du kannst es jetzt verbinden."), "already_paired")
        with self.lock:
            if any(s["state"] in ("pairing", "awaiting_user") for s in self.sessions.values()):
                raise OpError("Es läuft bereits ein Pairing-Vorgang.", "busy")
            self.ensure_agent()
            sid = uuidlib.uuid4().hex[:12]
            s = {"id": sid, "address": address, "path": path, "name": dev["name"], "state": "pairing", "message": "Pairing läuft …", "started": int(time.time()), "deadline": time.monotonic() + PAIR_TIMEOUT}
            self.sessions[sid] = s
            for old in [k for k, v in self.sessions.items() if v["state"] not in ("pairing", "awaiting_user") and time.time() - v["started"] > 300]:
                del self.sessions[old]
        try:                                                    # allow the remote side to complete bonding for the duration of this session only
            self._props(a["path"]).Set("org.bluez.Adapter1", "Pairable", dbus.Boolean(True))
            self.stop_scan()                                    # discovery disturbs pairing
        except dbus.DBusException:
            pass
        self.events("bt.pairing_started", address=address, device_name=dev["name"])
        self._dev(path).Pair(reply_handler=lambda: self._pair_done(sid), error_handler=lambda e: self._pair_failed(sid, e), timeout=PAIR_TIMEOUT)
        return self._pub_session(s)

    def _pair_done(self, sid):
        s = self.sessions[sid]
        try:
            self._props(s["path"]).Set("org.bluez.Device1", "Trusted", dbus.Boolean(True))     # lets HID devices reconnect by themselves
        except dbus.DBusException:
            pass
        s["state"], s["message"] = "paired", "Gekoppelt und als vertrauenswürdig markiert."
        self._cleanup_session(sid)
        self.events("bt.paired", address=s["address"], device_name=s["name"])
        try:                                                    # connect right away (a mouse/keyboard starts working immediately)
            self._dev(s["path"]).Connect(reply_handler=lambda: self.events("bt.connected", address=s["address"], device_name=s["name"]), error_handler=lambda e: log.info("connect after pairing: %s", explain(e)), timeout=30)
        except dbus.DBusException:
            pass

    def _pair_failed(self, sid, e):
        s = self.sessions[sid]
        s["state"], s["message"] = "failed", explain(e)
        self._cleanup_session(sid)
        self.events("bt.pairing_failed", address=s["address"], device_name=s["name"], reason=e.get_dbus_name())

    def _cleanup_session(self, sid):
        with self.lock:
            for r in self.requests.values():
                if r["session"] == sid and r["state"] == "waiting":
                    r["state"] = "cancelled"
            self.display.pop(self.sessions[sid]["address"], None)
        try:
            a = self._adapter()
            self._props(a["path"]).Set("org.bluez.Adapter1", "Pairable", dbus.Boolean(False))
        except (OpError, dbus.DBusException):
            pass

    def cancel_pairing(self, sid=None):
        with self.lock:
            targets = [s for s in self.sessions.values() if s["state"] in ("pairing", "awaiting_user") and sid in (None, s["id"])]
        for s in targets:
            with self.lock:                                   # unblock bluetoothd: answer waiting agent requests with "rejected" first
                for r in self.requests.values():
                    if r["session"] == s["id"] and r["state"] == "waiting":
                        r["state"] = "cancelled"
                        self.glib_call(r["error"], rejected())
            try:
                self._dev(s["path"]).CancelPairing()
            except dbus.DBusException:
                pass
            s["state"], s["message"] = "cancelled", "Pairing abgebrochen."
            self._cleanup_session(s["id"])
        return {"cancelled": len(targets)}

    # ---- agent callbacks (called on the main-loop thread) -----------------------------------------------------------------
    def _session_for(self, device_path):
        with self.lock:
            for s in self.sessions.values():
                if s["path"] == device_path and s["state"] in ("pairing", "awaiting_user") and time.monotonic() < s["deadline"]:
                    return s
        return None

    def on_request(self, kind, device_path, reply, error, passkey, wants_input):
        s = self._session_for(device_path)
        if s is None:
            self.events("bt.pairing_rejected_unsolicited", severity="warning", device=device_path.rsplit("/", 1)[-1], request=kind)
            log.warning("rejected unsolicited %s request from %s", kind, device_path)
            return error(rejected())
        if kind == "authorize":                                  # a user-started session authorises exactly this device
            return reply()
        rid = uuidlib.uuid4().hex[:12]
        r = {"id": rid, "session": s["id"], "kind": kind, "address": s["address"], "name": s["name"], "passkey": passkey, "wants_input": wants_input, "state": "waiting",
             "reply": reply, "error": error, "deadline": time.monotonic() + REQUEST_TIMEOUT}
        with self.lock:
            self.requests[rid] = r
            s["state"] = "awaiting_user"
            s["message"] = {"confirm": "Bitte den angezeigten Code mit dem Gerät vergleichen.", "pin": "Bitte die PIN des Geräts eingeben.", "passkey": "Bitte den Passkey eingeben."}.get(kind, "Bestätigung erforderlich.")
        self.events("bt.pairing_request", address=s["address"], device_name=s["name"], request=kind)
        t = threading.Timer(REQUEST_TIMEOUT, self._expire, args=(rid,))
        t.daemon = True
        t.start()

    def on_display(self, device_path, kind, value, entered=None):
        s = self._session_for(device_path)
        if s is None:
            return
        self.display[s["address"]] = {"address": s["address"], "kind": kind, "value": value, "entered": entered}
        s["state"], s["message"] = "awaiting_user", f"Gib auf dem Gerät diesen Code ein: {value}"

    def on_service_authorization(self, device_path, uuid, reply, error):
        for d in self.devices():
            if d["path"] == device_path and d["trusted"] and d["paired"]:
                return reply()
        self.events("bt.service_rejected", severity="warning", device=device_path.rsplit("/", 1)[-1], uuid=uuid)
        error(rejected())

    def on_cancel(self):
        with self.lock:
            for r in self.requests.values():
                if r["state"] == "waiting":
                    r["state"] = "cancelled"

    def _expire(self, rid):
        r = self.requests.get(rid)
        if r and r["state"] == "waiting":
            r["state"] = "expired"
            self.glib_call(r["error"], rejected())
            self.events("bt.pairing_request_expired", severity="warning", address=r["address"])

    def answer(self, rid: str, accept: bool, value=None) -> dict:
        r = self.requests.get(rid)
        if not r or r["state"] != "waiting":
            raise OpError("Die Pairing-Anfrage ist abgelaufen oder existiert nicht mehr.", "request_gone")
        validate.boolean(accept, "accept")
        if time.monotonic() > r["deadline"]:
            r["state"] = "expired"
            raise OpError("Die Pairing-Anfrage ist abgelaufen.", "request_gone")
        s = self.sessions.get(r["session"])
        if not s or s["state"] not in ("pairing", "awaiting_user"):
            raise OpError("Der Pairing-Vorgang wurde beendet.", "request_gone")
        if not accept:
            r["state"] = "denied"
            self.glib_call(r["error"], rejected())
            return {"ok": True}
        if r["kind"] == "pin":
            pin = str(value or "")
            if not (1 <= len(pin) <= 16) or not all(32 <= ord(c) < 127 for c in pin):
                raise ValueError("Die PIN muss 1 bis 16 Zeichen lang sein")
            r["state"] = "answered"; s["state"] = "pairing"
            self.glib_call(r["reply"], pin)
        elif r["kind"] == "passkey":
            if not isinstance(value, (int, str)) or not str(value).isdigit() or not 0 <= int(value) <= 999999:
                raise ValueError("Der Passkey muss eine Zahl von 0 bis 999999 sein")
            r["state"] = "answered"; s["state"] = "pairing"
            self.glib_call(r["reply"], dbus.UInt32(int(value)))
        else:                                                     # confirm
            r["state"] = "answered"; s["state"] = "pairing"
            self.glib_call(r["reply"])
        return {"ok": True}

    # ---- connect / trust / remove -------------------------------------------------------------------------------------------
    def connect(self, address: str) -> dict:
        path = self._device_path(address)
        try:
            self._dev(path).Connect(timeout=30)
        except dbus.DBusException as e:
            raise OpError(explain(e), "connect_failed") from None
        return {"connected": True}

    def disconnect(self, address: str) -> dict:
        path = self._device_path(address)
        try:
            self._dev(path).Disconnect()
        except dbus.DBusException as e:
            raise OpError(explain(e), "disconnect_failed") from None
        return {"connected": False}

    def set_trusted(self, address: str, trusted: bool):
        path = self._device_path(address)
        self._props(path).Set("org.bluez.Device1", "Trusted", dbus.Boolean(validate.boolean(trusted, "trusted")))

    def remove(self, address: str):
        path = self._device_path(address)
        a = self._adapter()
        try:
            dbus.Interface(self.bus.get_object(BLUEZ, a["path"]), "org.bluez.Adapter1").RemoveDevice(path)
        except dbus.DBusException as e:
            raise OpError(explain(e), "remove_failed") from None
