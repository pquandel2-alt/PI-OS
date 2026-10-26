"""Network, Bluetooth and hardware management API. The backend is a thin, validated gateway to the privileged helper pios-connd
(unix socket, uid-checked); it never runs commands itself and never stores or logs Wi-Fi/Bluetooth secrets."""
import asyncio
import copy
import json
import logging
import os
import socket
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, SecretStr

from . import audit, db, events, security, sysops
from .security import admin_user, current_user

log = logging.getLogger("pios.connectivity")
router = APIRouter(prefix="/api")

CODE_TO_HTTP = {"pending": 409, "nothing_pending": 409, "not_found": 404, "no_adapter": 404, "wifi_disabled": 409, "powered_off": 409, "powered_off_": 409, "busy": 409, "already_paired": 409,
                "unsupported_security": 422, "password_required": 422, "invalid_input": 422, "in_use_by_admin": 409, "request_gone": 410, "bt_unavailable": 503, "forbidden": 502, "not_allowed": 403,
                "untrusted_source": 409, "version_changed": 409, "already_installed": 409, "unavailable": 409, "adapter_unavailable": 409, "regdom_failed": 500}


class Unavailable(Exception):
    pass


def socket_path() -> str:
    return os.getenv("PIOS_CONND_SOCKET", "/run/pios-connd/connd.sock")


def call(method: str, args: dict | None = None, timeout: float = 30.0):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(socket_path())
            s.sendall((json.dumps({"method": method, "args": args or {}}) + "\n").encode())
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > 4_000_000:
                    raise Unavailable("Antwort zu groß")
        resp = json.loads(buf)
    except (OSError, ValueError) as e:
        raise Unavailable(str(e)) from None
    if not resp.get("ok"):
        raise HTTPException(CODE_TO_HTTP.get(resp.get("code"), 400), resp.get("error", "Fehler"))
    return resp["result"]


def _call(method, args=None, timeout=30.0, request: Request | None = None):
    args = dict(args or {})
    if request is not None:
        args["client_ip"] = security.client_ip(request)
    try:
        return call(method, args, timeout)
    except Unavailable:
        raise HTTPException(503, "Der Verbindungsdienst (pios-connd) ist nicht erreichbar. Er ist nur im PiOS-Image vorhanden.") from None


# ---------------------------------------------------------------------------------------------------- network
class WifiConnect(BaseModel):
    model_config = {"extra": "forbid"}
    ssid: str = Field(min_length=1, max_length=64)
    psk: SecretStr | None = Field(default=None, max_length=128)
    hidden: bool = False
    autoconnect: bool = True
    iface: str | None = Field(default=None, max_length=15)


class Enabled(BaseModel):
    model_config = {"extra": "forbid"}
    enabled: bool


class IfaceBody(BaseModel):
    model_config = {"extra": "forbid"}
    iface: str = Field(min_length=1, max_length=15)


class Autoconnect(BaseModel):
    model_config = {"extra": "forbid"}
    autoconnect: bool


class Country(BaseModel):
    model_config = {"extra": "forbid"}
    code: str = Field(min_length=2, max_length=2)


@router.get("/net/summary")
def net_summary(u=Depends(current_user)):
    s = _call("net.summary", timeout=10)
    if u["role"] != "admin" and s.get("pending"):
        s["pending"] = {"seconds_left": s["pending"]["seconds_left"]}          # users learn that something is pending, not what
    return s


@router.get("/net")
def net_status(u=Depends(admin_user)):
    return _call("net.status", timeout=15)


@router.post("/net/wifi/scan")
def wifi_scan(u=Depends(admin_user)):
    return _call("wifi.scan")


@router.get("/net/wifi/networks")
def wifi_networks(iface: str | None = Query(None, max_length=15), u=Depends(admin_user)):
    return _call("wifi.networks", {"iface": iface} if iface else {})


@router.post("/net/wifi/connect")
def wifi_connect(b: WifiConnect, request: Request, u=Depends(admin_user)):
    args = {"ssid": b.ssid, "hidden": b.hidden, "autoconnect": b.autoconnect, "psk": b.psk.get_secret_value() if b.psk else None, "iface": b.iface}
    r = _call("wifi.connect", args, timeout=30, request=request)
    audit.event("net.wifi_connect", "notice", actor=u["username"], ip=security.client_ip(request), ssid=b.ssid, hidden=b.hidden, protected=r.get("protected"))
    return r


@router.get("/net/operation/{op}")
def net_operation(op: str, u=Depends(admin_user)):
    if not op.isalnum() or len(op) > 32:
        raise HTTPException(400, "Ungültiger Vorgang")
    return _call("net.operation", {"op": op})


@router.post("/net/wifi/enabled")
def wifi_enabled(b: Enabled, request: Request, u=Depends(admin_user)):
    r = _call("wifi.set_enabled", {"enabled": b.enabled}, request=request)
    audit.event("net.wifi_radio", "notice", actor=u["username"], ip=security.client_ip(request), enabled=b.enabled, protected=r.get("protected"))
    return r


@router.delete("/net/wifi/known/{uuid}")
def wifi_forget(uuid: str, request: Request, u=Depends(admin_user)):
    r = _call("wifi.forget", {"uuid": uuid}, request=request)
    audit.event("net.wifi_forget", "notice", actor=u["username"], ip=security.client_ip(request))
    return r


@router.put("/net/wifi/known/{uuid}")
def wifi_autoconnect(uuid: str, b: Autoconnect, u=Depends(admin_user)):
    return _call("wifi.autoconnect", {"uuid": uuid, "value": b.autoconnect})


@router.post("/net/disconnect")
def net_disconnect(b: IfaceBody, request: Request, u=Depends(admin_user)):
    r = _call("net.disconnect", {"iface": b.iface}, request=request)
    audit.event("net.disconnect", "notice", actor=u["username"], ip=security.client_ip(request), iface=b.iface, protected=r.get("protected"))
    return r


@router.post("/net/ethernet/dhcp")
def eth_dhcp(b: IfaceBody, request: Request, u=Depends(admin_user)):
    r = _call("eth.set_dhcp", {"iface": b.iface}, request=request)
    audit.event("net.ethernet_dhcp", "notice", actor=u["username"], ip=security.client_ip(request), iface=b.iface, protected=r.get("protected"))
    return r


@router.put("/net/wifi/country")
def wifi_country(b: Country, request: Request, u=Depends(admin_user)):
    r = _call("wifi.set_country", {"code": b.code})
    audit.event("net.wifi_country", "notice", actor=u["username"], ip=security.client_ip(request), country=b.code.upper())
    return r


@router.post("/net/confirm")
def net_confirm(request: Request, u=Depends(admin_user)):
    r = _call("net.confirm")
    audit.event("net.change_confirmed", "notice", actor=u["username"], ip=security.client_ip(request))
    return r


@router.post("/net/revert")
def net_revert(request: Request, u=Depends(admin_user)):
    r = _call("net.revert")
    audit.event("net.change_reverted", "warning", actor=u["username"], ip=security.client_ip(request), reason="manuell")
    return r


# ---------------------------------------------------------------------------------------------------- bluetooth
class Address(BaseModel):
    model_config = {"extra": "forbid"}
    address: str = Field(min_length=17, max_length=17)


class Powered(BaseModel):
    model_config = {"extra": "forbid"}
    powered: bool


class Scan(BaseModel):
    model_config = {"extra": "forbid"}
    seconds: int = Field(default=30, ge=5, le=60)


class Trust(Address):
    trusted: bool


class Answer(BaseModel):
    model_config = {"extra": "forbid"}
    id: str = Field(max_length=32)
    accept: bool
    value: str | int | None = Field(default=None, max_length=16)


@router.get("/bt")
def bt_status(u=Depends(admin_user)):
    return _call("bt.status", timeout=15)


@router.get("/bt/pairing")
def bt_pairing(u=Depends(admin_user)):
    return _call("bt.pairing", timeout=5)


@router.post("/bt/power")
def bt_power(b: Powered, request: Request, u=Depends(admin_user)):
    r = _call("bt.set_powered", {"powered": b.powered})
    audit.event("bt.power", "notice", actor=u["username"], ip=security.client_ip(request), powered=b.powered)
    return r


@router.post("/bt/scan")
def bt_scan(b: Scan, u=Depends(admin_user)):
    return _call("bt.scan", {"seconds": b.seconds})


@router.post("/bt/scan/stop")
def bt_scan_stop(u=Depends(admin_user)):
    return _call("bt.scan_stop")


@router.post("/bt/pair")
def bt_pair(b: Address, request: Request, u=Depends(admin_user)):
    r = _call("bt.pair", {"address": b.address}, timeout=30)
    audit.event("bt.pair_started", "notice", actor=u["username"], ip=security.client_ip(request), address=b.address.upper())
    return r


@router.post("/bt/pair/answer")
def bt_answer(b: Answer, request: Request, u=Depends(admin_user)):
    r = _call("bt.answer", {"id": b.id, "accept": b.accept, "value": b.value})
    audit.event("bt.pair_answered", "notice", actor=u["username"], ip=security.client_ip(request), accepted=b.accept)
    return r


@router.post("/bt/pair/cancel")
def bt_cancel(u=Depends(admin_user)):
    return _call("bt.cancel")


@router.post("/bt/connect")
def bt_connect(b: Address, u=Depends(admin_user)):
    return _call("bt.connect", {"address": b.address}, timeout=45)


@router.post("/bt/disconnect")
def bt_disconnect(b: Address, u=Depends(admin_user)):
    return _call("bt.disconnect", {"address": b.address})


@router.post("/bt/trust")
def bt_trust(b: Trust, request: Request, u=Depends(admin_user)):
    r = _call("bt.trust", {"address": b.address, "trusted": b.trusted})
    audit.event("bt.trust", "notice", actor=u["username"], ip=security.client_ip(request), address=b.address.upper(), trusted=b.trusted)
    return r


@router.post("/bt/remove")
def bt_remove(b: Address, request: Request, u=Depends(admin_user)):
    r = _call("bt.remove", {"address": b.address})
    audit.event("bt.remove", "notice", actor=u["username"], ip=security.client_ip(request), address=b.address.upper())
    return r


# ---------------------------------------------------------------------------------------------------- hardware
def redact(inv: dict) -> dict:
    """What ordinary users may see: device names and states, but no hardware addresses, serial-like IDs or kernel log excerpts."""
    d = copy.deepcopy(inv)
    for n in d.get("network", []):
        n.pop("mac", None); n.pop("modalias", None)
    for i in d.get("input", []):
        for k in ("uniq", "phys", "sysfs"):
            i.pop(k, None)
    for u in d.get("usb", []):
        u.pop("bus", None); u.pop("dev", None)
        for itf in u.get("interfaces", []):
            itf.pop("modalias", None)
    for p in d.get("problems", []):
        p.pop("id", None)
    d["platform"].pop("revision", None)
    return d


@router.get("/hw")
def hw_overview(u=Depends(current_user)):
    inv = _call("hw.inventory", timeout=20)
    return inv if u["role"] == "admin" else redact(inv)


@router.get("/hw/input-diagnosis")
def hw_input(u=Depends(admin_user)):
    return _call("hw.input_diag", timeout=30)


@router.get("/hw/drivers")
def hw_drivers(u=Depends(admin_user)):
    return _call("hw.drivers", timeout=45)


@router.post("/hw/rescan")
def hw_rescan(request: Request, u=Depends(admin_user)):
    audit.event("hw.rescan", "info", actor=u["username"], ip=security.client_ip(request))
    return _call("hw.rescan", timeout=30)


class PkgInstall(BaseModel):
    model_config = {"extra": "forbid"}
    package: str = Field(min_length=2, max_length=61)
    version: str = Field(min_length=1, max_length=80)


def _ops(method, args):
    try:
        return sysops.call(method, args, 30)
    except sysops.Unavailable:
        raise HTTPException(503, "Der System-Dienst ist nicht erreichbar (nur im PiOS-Image verfügbar).") from None
    except sysops.OpError as e:
        audit.event("hw.package_refused", "warning", package=str(args.get("package"))[:60], code=e.code)
        raise HTTPException(CODE_TO_HTTP.get(e.code, 400), str(e)) from None


@router.get("/hw/packages/{package}")
def hw_package(package: str, u=Depends(admin_user)):
    return _ops("pkg.status", {"package": package})


@router.post("/hw/packages/install")
def hw_install(b: PkgInstall, request: Request, u=Depends(admin_user)):
    """Installs one allow-listed package from the official archives. The caller must send the exact version the user confirmed."""
    r = _ops("pkg.install", {"package": b.package, "version": b.version})
    audit.event("hw.package_install", "notice", actor=u["username"], ip=security.client_ip(request), package=b.package, version=b.version)
    return r


# ---------------------------------------------------------------------------------------------------- events -> notifications + audit
AUDITED = {"net.change_pending": "warning", "net.change_confirmed": "notice", "net.change_reverted": "warning", "net.wifi_failed": "warning", "bt.pairing_started": "notice", "bt.paired": "notice",
           "bt.pairing_failed": "warning", "bt.pairing_rejected_unsolicited": "warning", "bt.service_rejected": "warning", "bt.pairing_request_expired": "warning"}
NOTIFY = {"net.wifi_connected": ("WLAN verbunden", "info"), "net.state_changed": ("Netzwerkstatus geändert", "info"), "net.wifi_failed": ("WLAN-Verbindung fehlgeschlagen", "warn"),
          "net.change_reverted": ("Netzwerkänderung zurückgesetzt", "warn"), "bt.paired": ("Bluetooth-Gerät gekoppelt", "info"), "bt.connected": ("Bluetooth-Gerät verbunden", "info"),
          "bt.disconnected": ("Bluetooth-Gerät getrennt", "info"), "bt.pairing_failed": ("Bluetooth-Pairing fehlgeschlagen", "warn"), "bt.pairing_rejected_unsolicited": ("Unerwartete Bluetooth-Kopplungsanfrage abgelehnt", "warn"),
          "hw.usb_added": ("USB-Gerät angeschlossen", "info"), "hw.usb_removed": ("USB-Gerät entfernt", "info")}
_last = {"id": 0}


def process_events(batch: dict):
    """Forward connd events to NOVA notifications (admins) and the audit log. Idempotent per event id."""
    if batch["last"] < _last["id"]:
        _last["id"] = 0                                         # connd restarted
    with db.connect() as c:
        admins = [r["id"] for r in c.execute("SELECT id FROM users WHERE role='admin'")]
    for e in batch["events"]:
        if e["id"] <= _last["id"]:
            continue
        _last["id"] = e["id"]
        d = {k: v for k, v in e["detail"].items() if k != "severity"}
        if e["name"] in AUDITED:
            audit.event(e["name"], AUDITED[e["name"]], actor="connd", **d)
        if e["name"] in NOTIFY:
            title, level = NOTIFY[e["name"]]
            body = d.get("device") or d.get("device_name") or d.get("ssid") or d.get("description") or d.get("reason") or ""
            if e["name"] == "net.state_changed":
                body = ("WLAN: " + (d.get("ssid") or "verbunden") if d.get("wifi") else "") + (" Ethernet verbunden" if d.get("ethernet") else "") + (f" · {d['ip']}" if d.get("ip") else "") or "Keine Verbindung"
            for uid in admins:
                events.publish(uid, "notification", app="network", title=title, body=str(body)[:200], level=level)


async def events_loop():
    await asyncio.sleep(8)
    while True:
        try:
            if os.path.exists(socket_path()):
                batch = await asyncio.to_thread(call, "events.since", {"since": _last["id"]}, 8.0)
                await asyncio.to_thread(process_events, batch)
        except Exception:                                      # noqa: BLE001
            log.debug("connd event poll failed", exc_info=True)
        await asyncio.sleep(3)
