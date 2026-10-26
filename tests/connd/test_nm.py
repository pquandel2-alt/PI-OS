import dbus
import pytest

from pios_connd import nm as nmmod
from pios_connd.ipc import OpError
from tests.connd.dbusenv import nm_mock, recording, system_bus      # noqa: F401  (fixtures)

DEV_ACTIVATED, DEV_DISCONNECTED, DEV_UNAVAILABLE = 100, 30, 20


@pytest.fixture()
def nm(nm_mock):
    return nmmod.NMClient(nm_mock.bus), nm_mock


def mock_iface(nm_mock):
    return nm_mock.nm_mock_iface


def add_wifi(m, ap_security=0x0, ssid="HeimWLAN", strength=70, state=DEV_DISCONNECTED, name="wlan0"):
    dev = mock_iface(m).AddWiFiDevice(f"mock_{name}", name, state)
    ap = mock_iface(m).AddAccessPoint(dev, f"ap_{ssid}", ssid, "11:22:33:44:55:66", 2, 2412, 54000, strength, ap_security)
    return dev, ap


def test_classification_of_ap_security_flags():
    c = nmmod.classify
    assert c(1, 0, nmmod.KM_PSK)["security"] == "wpa2" and c(1, 0, nmmod.KM_PSK)["supported"]
    assert c(1, 0, nmmod.KM_PSK | nmmod.KM_SAE)["security"] == "wpa2-wpa3" and c(1, 0, nmmod.KM_PSK | nmmod.KM_SAE)["key_mgmt"] == "wpa-psk"
    assert c(1, 0, nmmod.KM_SAE)["security"] == "wpa3" and c(1, 0, nmmod.KM_SAE)["key_mgmt"] == "sae"
    assert c(1, nmmod.KM_PSK, 0)["security"] == "wpa"
    e = c(1, 0, nmmod.KM_8021X)
    assert e["security"] == "enterprise" and not e["supported"] and "Enterprise" in e["reason"]
    w = c(1, 0, 0)
    assert w["security"] == "wep" and not w["supported"]
    o = c(0, 0, 0)
    assert o["security"] == "open" and not o["needs_password"]


def test_no_wifi_adapter_present(nm):
    client, m = nm
    st = client.status()
    assert st["running"] and st["wifi"]["present"] is False
    with pytest.raises(OpError) as e:
        client.networks()
    assert e.value.code == "no_adapter"
    with pytest.raises(OpError):
        client.connect_wifi("X", "12345678")


def test_status_lists_adapters_with_real_values(nm):
    client, m = nm
    add_wifi(m)
    mock_iface(m).AddEthernetDevice("mock_eth", "eth0", DEV_DISCONNECTED)
    st = client.status()
    assert st["wifi"]["present"] and st["wifi"]["enabled"] and st["wifi"]["devices"][0]["iface"] == "wlan0"
    assert st["ethernet"]["devices"][0]["iface"] == "eth0" and st["ethernet"]["devices"][0]["carrier"] is False


def test_scan_and_network_list(nm):
    client, m = nm
    dev, _ = add_wifi(m, ap_security=0x0, ssid="Offen", strength=40)
    mock_iface(m).AddAccessPoint(dev, "ap2", "Sicher", "AA:BB:CC:DD:EE:01", 2, 5180, 300000, 85, 0x0)
    assert client.scan()["scanning"] is True
    nets = client.networks()
    assert [n["ssid"] for n in nets] == ["Sicher", "Offen"]            # strongest first
    assert nets[0]["signal"] == 85 and nets[0]["band"] == "5 GHz" and nets[1]["band"] == "2,4 GHz" and nets[0]["known"] is False


def test_scan_refused_when_wifi_is_switched_off(nm):
    client, m = nm
    add_wifi(m)
    client.set_wifi_enabled(False)
    with pytest.raises(OpError) as e:
        client.scan()
    assert e.value.code == "wifi_disabled"
    with pytest.raises(OpError):
        client.connect_wifi("HeimWLAN", "12345678")
    client.set_wifi_enabled(True)
    assert client.status()["wifi"]["enabled"] is True


def sent(log, name):
    return [a for n, a in log if n == name]


def test_connect_sends_password_only_inside_the_dbus_call(nm, caplog):
    client, m = nm
    dev, ap = add_wifi(m, ssid="HeimWLAN")
    mock_iface(m).SetProperty(ap, "org.freedesktop.NetworkManager.AccessPoint", "RsnFlags", dbus.UInt32(nmmod.KM_PSK))
    mock_iface(m).SetProperty(ap, "org.freedesktop.NetworkManager.AccessPoint", "Flags", dbus.UInt32(1))
    log = recording(client)
    secret = "Sup3r-Geheim-Passwort!"
    r = client.connect_wifi("HeimWLAN", secret)
    assert r["op"] and r["new_uuid"]
    (settings, device, ap_path), = sent(log, "AddAndActivateConnection")
    assert settings["802-11-wireless-security"]["key-mgmt"] == "wpa-psk" and settings["802-11-wireless-security"]["psk"] == secret
    assert settings["802-11-wireless-security"]["psk-flags"] == 0, "stored by NetworkManager (root-only keyfile), not requested interactively"
    assert settings["connection"]["autoconnect"] is True and settings["802-11-wireless"]["hidden"] is False and settings["ipv4"]["method"] == "auto"
    assert bytes(settings["802-11-wireless"]["ssid"]) == b"HeimWLAN" and str(ap_path) == str(ap)
    assert secret not in repr(client.status()) and secret not in caplog.text and secret not in repr(client.networks())


def test_wpa3_only_network_uses_sae_and_open_network_has_no_security_section(nm):
    client, m = nm
    dev, ap = add_wifi(m, ssid="Drei")
    mock_iface(m).SetProperty(ap, "org.freedesktop.NetworkManager.AccessPoint", "RsnFlags", dbus.UInt32(nmmod.KM_SAE))
    mock_iface(m).SetProperty(ap, "org.freedesktop.NetworkManager.AccessPoint", "Flags", dbus.UInt32(1))
    log = recording(client)
    client.connect_wifi("Drei", "12345678")
    assert sent(log, "AddAndActivateConnection")[0][0]["802-11-wireless-security"]["key-mgmt"] == "sae"
    add_wifi(m, ssid="Cafe", name="wlan1")
    log.clear()
    client.connect_wifi("Cafe", None, iface="wlan1")
    assert "802-11-wireless-security" not in sent(log, "AddAndActivateConnection")[0][0]


def test_hidden_network_is_connected_without_an_access_point(nm):
    client, m = nm
    add_wifi(m, ssid="Sichtbar")
    with pytest.raises(OpError) as e:
        client.connect_wifi("Unsichtbar", "12345678")
    assert e.value.code == "not_found"
    log = recording(client, fake={"AddAndActivateConnection": ("/c", "/a")})
    client.connect_wifi("Unsichtbar", "12345678", hidden=True)
    (settings, _dev, ap), = sent(log, "AddAndActivateConnection")
    assert settings["802-11-wireless"]["hidden"] is True and str(ap) == "/" and settings["802-11-wireless-security"]["key-mgmt"] == "wpa-psk"


def test_saved_network_is_reactivated_without_resending_a_password(nm):
    client, m = nm
    dev, ap = add_wifi(m, ssid="Netz")
    client.connect_wifi("Netz", None)
    log = recording(client)
    r = client.connect_wifi("Netz", None)
    assert r["new_uuid"] == "" and sent(log, "ActivateConnection") and not sent(log, "AddAndActivateConnection")


@pytest.mark.parametrize("pw", ["short", "x" * 64 + "z", "ä" * 10, "a" * 64 + "b", "pass\nword!!", ""])
def test_invalid_passwords_rejected_before_touching_networkmanager(nm, pw):
    client, m = nm
    add_wifi(m, ssid="Netz")
    with pytest.raises(ValueError):
        client.connect_wifi("Netz", pw)
    assert client.status()["known"] == []


@pytest.mark.parametrize("ssid", ["", "x" * 33, "a\x00b", "tab\there", "ü" * 17])
def test_invalid_ssids_rejected(nm, ssid):
    client, m = nm
    add_wifi(m)
    with pytest.raises(ValueError):
        client.connect_wifi(ssid, "12345678", hidden=True)


def test_unsupported_security_gives_clear_errors(nm):
    client, m = nm
    dev, ap = add_wifi(m, ssid="Firma")
    mock_iface(m).SetProperty(ap, "org.freedesktop.NetworkManager.AccessPoint", "RsnFlags", dbus.UInt32(nmmod.KM_8021X))
    mock_iface(m).SetProperty(ap, "org.freedesktop.NetworkManager.AccessPoint", "Flags", dbus.UInt32(1))
    with pytest.raises(OpError) as e:
        client.connect_wifi("Firma", "12345678")
    assert e.value.code == "unsupported_security" and "Enterprise" in str(e.value)
    mock_iface(m).SetProperty(ap, "org.freedesktop.NetworkManager.AccessPoint", "RsnFlags", dbus.UInt32(0))
    with pytest.raises(OpError) as e:
        client.connect_wifi("Firma", "12345678")
    assert "WEP" in str(e.value)


def test_password_required_for_new_secured_network(nm):
    client, m = nm
    dev, ap = add_wifi(m, ssid="Zu")
    mock_iface(m).SetProperty(ap, "org.freedesktop.NetworkManager.AccessPoint", "RsnFlags", dbus.UInt32(nmmod.KM_PSK))
    mock_iface(m).SetProperty(ap, "org.freedesktop.NetworkManager.AccessPoint", "Flags", dbus.UInt32(1))
    with pytest.raises(OpError) as e:
        client.connect_wifi("Zu")
    assert e.value.code == "password_required"


def test_operation_reports_success_when_device_activates(nm):
    client, m = nm
    dev, ap = add_wifi(m, ssid="Netz")
    r = client.connect_wifi("Netz", None)                       # open network
    o = client.operation(r["op"])
    assert o["state"] in ("activating", "connected")


def test_wrong_password_failure_is_explained_and_the_new_profile_removed(nm):
    client, m = nm
    dev, ap = add_wifi(m, ssid="Netz")
    # a profile as NetworkManager would have stored it (same UUID we generated) ...
    uuid = "11111111-2222-3333-4444-555555555555"
    client._obj(nmmod.PATH + "/Settings", nmmod.NM + ".Settings").AddConnection({"connection": {"id": "Netz", "uuid": uuid, "type": "802-11-wireless"}, "802-11-wireless": {"ssid": dbus.ByteArray(b"Netz")}})
    assert [c["uuid"] for c in client.status()["known"]] == [uuid]
    import time
    client.ops["op1"] = {"state": "activating", "iface": "wlan0", "ssid": "Netz", "uuid": uuid, "new_uuid": uuid, "started": time.time() - 5, "message": "", "previous": {}}
    # ... then NetworkManager reports: activation failed, reason = supplicant failed (wrong 4-way handshake)
    mock_iface(m).SetProperty(dev, "org.freedesktop.NetworkManager.Device", "State", dbus.UInt32(120))
    mock_iface(m).SetProperty(dev, "org.freedesktop.NetworkManager.Device", "StateReason", dbus.Struct((dbus.UInt32(120), dbus.UInt32(10)), signature="uu"))
    o = client.operation("op1")
    assert o["state"] == "failed" and "Passwort" in o["message"] and o["reason"] == 10
    assert client.status()["known"] == [], "failed profile with the bad password is not kept"
    assert client.operation("op1")["state"] == "failed", "final state is sticky"
    with pytest.raises(OpError):
        client.operation("nope")


@pytest.mark.parametrize("reason,expect", [(53, "nicht gefunden"), (16, "DHCP"), (5, "IP-Adresse"), (11, "Zeitüberschreitung"), (7, "Passwort")])
def test_failure_reasons_are_human_readable(nm, reason, expect):
    client, m = nm
    dev, ap = add_wifi(m, ssid="Netz")
    import time
    client.ops["x"] = {"state": "activating", "iface": "wlan0", "ssid": "Netz", "uuid": "u", "new_uuid": "", "started": time.time() - 5, "message": "", "previous": {}}
    mock_iface(m).SetProperty(dev, "org.freedesktop.NetworkManager.Device", "State", dbus.UInt32(120))
    mock_iface(m).SetProperty(dev, "org.freedesktop.NetworkManager.Device", "StateReason", dbus.Struct((dbus.UInt32(120), dbus.UInt32(reason)), signature="uu"))
    assert expect in client.operation("x")["message"]


def test_active_connection_details_ip_gateway_dns(nm):
    client, m = nm
    dev, ap = add_wifi(m, ssid="Netz")
    conn = mock_iface(m).AddWiFiConnection(dev, "Netz", "Netz", "wpa-psk")
    active = mock_iface(m).AddActiveConnection([dev], conn, ap, "Netz", 2)
    mock_iface(m).SetDeviceActive(dev, active)
    import dbusmock
    dbus.Interface(m.bus.get_object("org.freedesktop.NetworkManager", dev), dbusmock.MOCK_IFACE).AddProperty("org.freedesktop.NetworkManager.Device.Wireless", "ActiveAccessPoint", dbus.ObjectPath(ap))
    d = client.status()["wifi"]["devices"][0]
    assert d["state"] == DEV_ACTIVATED and d["connection"]["id"] == "Netz" and d["active_ap"]["ssid"] == "Netz"
    assert any(n["in_use"] for n in client.networks())
    assert client.status()["known"][0]["active"] is True


def test_forget_and_autoconnect_and_unknown_uuid(nm):
    client, m = nm
    add_wifi(m, ssid="Netz")
    client.connect_wifi("Netz", None)
    uuid = client.status()["known"][0]["uuid"]
    client.set_autoconnect(uuid, False)
    assert next(c for c in client.status()["known"] if c["uuid"] == uuid)["autoconnect"] is False
    client.delete_connection(uuid)
    assert client.status()["known"] == []
    with pytest.raises(OpError):
        client.delete_connection(uuid)
    with pytest.raises(ValueError):
        client.delete_connection("not-a-uuid; rm -rf /")


def test_ethernet_dhcp_profile_created_when_missing(nm):
    client, m = nm
    mock_iface(m).AddEthernetDevice("mock_eth", "eth0", DEV_DISCONNECTED)
    log = recording(client, fake={"AddAndActivateConnection": ("/c", "/a")})
    r = client.set_ethernet_dhcp("eth0")
    assert r["created"] is True
    (settings, _d, _ap), = sent(log, "AddAndActivateConnection")
    assert settings["connection"]["type"] == "802-3-ethernet" and settings["ipv4"]["method"] == "auto" and settings["connection"]["interface-name"] == "eth0"
    with pytest.raises(ValueError):
        client.set_ethernet_dhcp("eth0; reboot")
    with pytest.raises(OpError):
        client.set_ethernet_dhcp("eth9")


def test_networkmanager_not_running(system_bus):
    client = nmmod.NMClient(dbus.SystemBus())
    assert client.status() == {"running": False, "wifi": {"present": False, "devices": []}, "ethernet": {"devices": []}, "known": []}
