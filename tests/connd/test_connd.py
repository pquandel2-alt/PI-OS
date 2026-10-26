import json
import os
import socket
import threading
import time

import dbus
import pytest

from pios_connd import nm as nmmod
from pios_connd import server as srv
from pios_connd.ipc import OpError, Server
from tests.connd.dbusenv import recording
from tests.connd.fakehw import FakeHW, Runner

ADMIN_WIFI = "192.168.1.50"
ADMIN_ETH = "10.0.0.2"
LOCAL = "127.0.0.1"


def route(ip, dev):
    return f"ip|-j|route|get|{ip}", (0, json.dumps([{"dst": ip, "dev": dev}]))


@pytest.fixture()
def d(nm_mock, tmp_path, monkeypatch):
    monkeypatch.setattr(srv, "REGDOM_CONF", tmp_path / "regdom.conf")
    h = FakeHW(tmp_path / "hw")
    h.w("sys/class/rfkill/rfkill0/type", "wlan\n"); h.w("sys/class/rfkill/rfkill0/soft", "0\n"); h.w("sys/class/rfkill/rfkill0/hard", "0\n"); h.w("sys/class/rfkill/rfkill0/name", "phy0\n")
    r = Runner(**dict([route(ADMIN_WIFI, "wlan0"), route(ADMIN_ETH, "eth0")], **{"iw|reg|get": (0, "global\ncountry DE: DFS-ETSI\n"), "iw|reg|set|DE": (0, ""), "iw|reg|set|US": (0, ""), "rfkill|unblock|wlan": (0, ""),
                                                                                  "rfkill|unblock|bluetooth": (0, "")}))
    c = srv.Connd(nmmod.NMClient(nm_mock.bus), None, tmp_path / "state", roots=h.r, runner=r, allowed_packages={"firmware-realtek"}, confirm_seconds=60)
    c.m, c.h, c.r = nm_mock, h, r
    return c


def setup_wifi(d, ssid="Heim", psk_ap=True, with_eth=True):
    m = d.m.nm_mock_iface
    dev = m.AddWiFiDevice("mock_wlan0", "wlan0", 30)
    ap = m.AddAccessPoint(dev, "ap1", ssid, "11:22:33:44:55:66", 2, 5180, 300000, 80, 0)
    if psk_ap:
        m.SetProperty(ap, "org.freedesktop.NetworkManager.AccessPoint", "RsnFlags", dbus.UInt32(nmmod.KM_PSK))
        m.SetProperty(ap, "org.freedesktop.NetworkManager.AccessPoint", "Flags", dbus.UInt32(1))
    if with_eth:
        m.AddEthernetDevice("mock_eth0", "eth0", 30)
    return dev, ap


def test_status_and_summary_shape(d):
    setup_wifi(d)
    st = d.verbs["net.status"]({})
    assert st["running"] and st["country"] == "DE" and st["rfkill"][0]["type"] == "wlan" and st["pending"] is None
    s = d.verbs["net.summary"]({})
    assert s["nm"] and s["wifi"]["present"] and s["ethernet"]["present"] and s["online"] is False and s["bluetooth"] == {"present": False}
    flat = json.dumps(s)
    assert "mac" not in flat.lower() and "known" not in s, "the tray summary (all users) leaks neither MAC addresses nor saved networks"


def test_wifi_change_on_the_admins_own_interface_is_protected_and_can_be_reverted(d):
    setup_wifi(d)
    r = d.verbs["wifi.connect"]({"ssid": "Heim", "psk": "12345678", "client_ip": ADMIN_WIFI})
    assert r["protected"] is True and "IP-Adresse" in r["hint"]
    p = d.verbs["net.status"]({})["pending"]
    assert p["kind"] == "wifi_connect" and p["iface"] == "wlan0" and p["seconds_left"] <= 60
    with pytest.raises(OpError) as e:
        d.verbs["wifi.connect"]({"ssid": "Heim", "psk": "12345678", "client_ip": ADMIN_WIFI})
    assert e.value.code == "pending"
    d.verbs["net.revert"]({})
    assert d.verbs["net.status"]({})["pending"] is None


def test_confirming_keeps_the_change(d):
    setup_wifi(d)
    d.verbs["wifi.connect"]({"ssid": "Heim", "psk": "12345678", "client_ip": ADMIN_WIFI})
    d.verbs["net.confirm"]({})
    assert d.verbs["net.status"]({})["pending"] is None and any(c["ssid"] == "Heim" for c in d.verbs["net.status"]({})["known"])


def test_changes_not_touching_the_admin_path_are_not_held_back(d):
    setup_wifi(d)
    assert d.verbs["wifi.connect"]({"ssid": "Heim", "psk": "12345678", "client_ip": ADMIN_ETH})["protected"] is False      # admin uses ethernet
    d.verbs["wifi.set_enabled"]({"enabled": False, "client_ip": ADMIN_ETH})
    assert d.verbs["net.status"]({})["pending"] is None


def test_local_kiosk_is_never_locked_out(d):
    setup_wifi(d)
    assert d.verbs["wifi.connect"]({"ssid": "Heim", "psk": "12345678", "client_ip": LOCAL})["protected"] is False
    assert d.verbs["wifi.set_enabled"]({"enabled": False, "client_ip": LOCAL})["protected"] is False


def test_switching_wifi_off_while_connected_over_wifi_is_provisional(d):
    setup_wifi(d)
    r = d.verbs["wifi.set_enabled"]({"enabled": False, "client_ip": ADMIN_WIFI})
    assert r["protected"] is True and d.verbs["net.status"]({})["pending"]["kind"] == "wifi_off"
    d.verbs["net.revert"]({})
    assert d.verbs["net.status"]({})["wifi"]["enabled"] is True, "rollback re-enables the radio"


def test_failed_connection_is_reverted_immediately(d):
    dev, ap = setup_wifi(d)
    r = d.verbs["wifi.connect"]({"ssid": "Heim", "psk": "falschfalsch", "client_ip": ADMIN_WIFI})
    op = r["op"]
    d.nm.ops[op]["started"] -= 5
    m = d.m.nm_mock_iface
    m.SetProperty(dev, "org.freedesktop.NetworkManager.Device", "State", dbus.UInt32(120))
    m.SetProperty(dev, "org.freedesktop.NetworkManager.Device", "StateReason", dbus.Struct((dbus.UInt32(120), dbus.UInt32(10)), signature="uu"))
    res = d.verbs["net.operation"]({"op": op})
    assert res["state"] == "failed" and res["reverted"] is True and "Passwort" in res["message"] and "wiederhergestellt" in res["message"]
    assert d.verbs["net.status"]({})["pending"] is None
    assert any(e["name"] == "net.wifi_failed" for e in d.events.since(0)["events"])


def test_forgetting_the_network_that_carries_the_admin_is_refused(d):
    dev, ap = setup_wifi(d)
    m = d.m.nm_mock_iface
    conn = m.AddWiFiConnection(dev, "Heim", "Heim", "wpa-psk")
    active = m.AddActiveConnection([dev], conn, ap, "Heim", 2)
    m.SetDeviceActive(dev, active)
    uuid = d.verbs["net.status"]({})["known"][0]["uuid"]
    import dbusmock
    dbus.Interface(d.m.bus.get_object("org.freedesktop.NetworkManager", dev), dbusmock.MOCK_IFACE).AddMethod("org.freedesktop.NetworkManager.Device", "Disconnect", "", "", "pass")   # (stand-in lacks it)
    with pytest.raises(OpError) as e:
        d.verbs["wifi.forget"]({"uuid": uuid, "client_ip": ADMIN_WIFI})
    assert e.value.code == "in_use_by_admin" and "anderen Weg" in str(e.value)
    assert d.verbs["wifi.forget"]({"uuid": uuid, "client_ip": ADMIN_ETH}) == {"ok": True}
    assert d.verbs["net.status"]({})["known"] == []


def test_ethernet_dhcp_switch_from_static_is_protected(d):
    setup_wifi(d)
    m = d.m.nm_mock_iface
    eth = "/org/freedesktop/NetworkManager/Devices/mock_eth0"
    d.nm._obj(nmmod.PATH + "/Settings", nmmod.NM + ".Settings").AddConnection({"connection": {"id": "static", "uuid": "aaaaaaaa-1111-2222-3333-444444444444", "type": "802-3-ethernet", "interface-name": "eth0"},
                                                                              "802-3-ethernet": {}, "ipv4": {"method": "manual", "address-data": dbus.Array([], signature="a{sv}")}})
    log = recording(d.nm)
    r = d.verbs["eth.set_dhcp"]({"iface": "eth0", "client_ip": ADMIN_ETH})
    assert r["protected"] is True and d.verbs["net.status"]({})["pending"]["kind"] == "ethernet_dhcp"
    d.verbs["net.revert"]({})
    c = next(c for c in d.nm.connections() if c["uuid"] == "aaaaaaaa-1111-2222-3333-444444444444")
    assert c["ipv4_method"] == "manual", "the previous (static) setting is restored by the rollback"


def test_wifi_country_validated_persisted_and_applied_without_a_shell(d, tmp_path):
    setup_wifi(d)
    for bad in ("", "D", "DEU", "XX", "00", "de;reboot", "$(id)", None, 5):
        with pytest.raises(ValueError):
            d.verbs["wifi.set_country"]({"code": bad})
    r = d.verbs["wifi.set_country"]({"code": "us"})
    assert r["country"] == "US" and (tmp_path / "regdom.conf").read_text().splitlines()[-1] == "options cfg80211 ieee80211_regdom=US"
    assert ["iw", "reg", "set", "US"] in d.r.calls and ["rfkill", "unblock", "wlan"] in d.r.calls
    assert all(isinstance(c, list) and all(isinstance(x, str) for x in c) for c in d.r.calls), "commands are argument lists, never shell strings"


def test_first_run_enables_wifi_exactly_once(d, tmp_path):
    setup_wifi(d)
    d.nm.set_wifi_enabled(False)
    d.r.cmds[("iw", "reg", "get")] = (0, "global\ncountry 00: DFS-UNSET\n")
    assert d.first_run() is True and d.verbs["net.status"]({})["wifi"]["enabled"] is True
    assert ["iw", "reg", "set", "DE"] in d.r.calls
    d.nm.set_wifi_enabled(False)
    assert d.first_run() is False and d.verbs["net.status"]({})["wifi"]["enabled"] is False, "later runs respect the user's choice"


def test_bluetooth_verbs_report_missing_bluez(d):
    with pytest.raises(OpError) as e:
        d.verbs["bt.status"]({})
    assert e.value.code == "bt_unavailable"
    with pytest.raises(OpError):
        d.verbs["bt.pair"]({"address": "11:22:33:44:55:66"})


def test_hardware_verbs_use_real_data_sources(d):
    d.h.drivers(); d.h.usb_hub(); d.h.usb_hid(); d.h.mouse(); d.h.cage(opens=(4,), env={"WLR_NO_HARDWARE_CURSORS": "1"})
    inv = d.verbs["hw.inventory"]({})
    assert any(u["product"] == "USB Receiver" for u in inv["usb"])
    diag = d.verbs["hw.input_diag"]({})
    assert {s["id"] for s in diag["stages"]} >= {"usb", "kernel", "binding", "input", "udev"} and diag["devices"]["pointers"][0]["transport"] == "usb"
    dr = d.verbs["hw.drivers"]({})
    assert "findings" in dr and dr["summary"]["drivers_missing"] == 0
    d.verbs["hw.rescan"]({})
    assert ["udevadm", "trigger", "--action=add", "--subsystem-match=usb", "--subsystem-match=input", "--subsystem-match=bluetooth"] in d.r.calls


def test_hotplug_watcher_emits_events(d):
    d.h.drivers(); d.h.usb_hub()
    stop = threading.Event()
    t = threading.Thread(target=d.watch, args=(stop, 0.1), daemon=True); t.start()
    time.sleep(0.4)
    d.h.usb_hid(); d.h.mouse()
    time.sleep(0.5)
    import shutil
    shutil.rmtree(d.h.root / "sys/bus/usb/devices/1-1"); (d.h.root / "proc/bus/input/devices").write_text("")
    time.sleep(0.5)
    stop.set()
    names = [e["name"] for e in d.events.since(0)["events"]]
    assert "hw.usb_added" in names and "hw.usb_removed" in names and "hw.input_added" in names and "hw.input_removed" in names


# ------------------------------------------------------------------ socket protocol
def ask(sock, raw: bytes):
    c = socket.socket(socket.AF_UNIX); c.connect(str(sock)); c.sendall(raw); r = c.makefile().readline(); c.close(); return json.loads(r)


def test_socket_server_validates_everything(d, tmp_path):
    setup_wifi(d)
    sock = tmp_path / "c.sock"
    s = Server(sock, d.verbs, {os.getuid()}); threading.Thread(target=s.serve_forever, daemon=True).start()
    try:
        assert ask(sock, b'{"method":"ping"}\n')["ok"]
        assert ask(sock, b"garbage\n")["code"] == "bad_request"
        assert ask(sock, b'{"method":"os.system","args":{"cmd":"id"}}\n')["code"] == "bad_request"
        r = ask(sock, json.dumps({"method": "wifi.connect", "args": {"ssid": "x" * 40, "psk": "12345678", "hidden": True}}).encode() + b"\n")
        assert r["ok"] is False and r["code"] == "invalid_input" and "32 Bytes" in r["error"]
        r = ask(sock, json.dumps({"method": "wifi.connect", "args": {"ssid": "Heim", "psk": "geheim-passwort-123", "client_ip": "1.2.3.4; reboot"}}).encode() + b"\n")
        assert r["ok"] is False and "geheim-passwort-123" not in json.dumps(r), "secrets never come back in error messages"
        s.allowed_uids = {123456}
        assert ask(sock, b'{"method":"ping"}\n')["code"] == "forbidden"
    finally:
        s.shutdown(); s.server_close()


def test_internal_errors_do_not_leak_details(d, tmp_path, monkeypatch):
    sock = tmp_path / "c.sock"
    d.verbs["boom"] = lambda a: (_ for _ in ()).throw(RuntimeError("secret-token-abc /etc/shadow"))
    s = Server(sock, d.verbs, {os.getuid()}); threading.Thread(target=s.serve_forever, daemon=True).start()
    try:
        r = ask(sock, b'{"method":"boom"}\n')
        assert r["code"] == "internal" and "secret-token" not in json.dumps(r) and "shadow" not in json.dumps(r)
    finally:
        s.shutdown(); s.server_close()
