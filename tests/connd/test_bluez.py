import threading
import time

import dbus
import dbusmock
import pytest

from pios_connd import bluez as bz
from pios_connd.ipc import OpError


MAC = "11:22:33:44:55:66"
DEV = "/org/bluez/hci0/dev_11_22_33_44_55_66"


@pytest.fixture()
def bt(bt_mock, monkeypatch):
    # python-dbusmock patches dbus.service method lookup process-wide and expects every service object to have .methods (tests only)
    monkeypatch.setattr(bz.Agent, "methods", {}, raising=False)
    monkeypatch.setattr(bz.Agent, "interface", None, raising=False)
    events = []
    client = bz.BluezClient(bt_mock.bus, events=lambda name, **kw: events.append((name, kw)), glib_call=bt_mock.glib_call)
    client.events_log = events
    client.m = bt_mock
    yield client
    client.cancel_pairing()
    client.close()


def props(**kw):
    """Explicit a{sv}: the proxy of a main-loop connection cannot introspect the mock, so dbus-python must not guess the types."""
    return dbus.Dictionary(kw, signature="sv")


def with_adapter(bt, powered=True):
    bt.m.bluez.AddAdapter("hci0", "pios")
    ad = bt.m.device_mock("/org/bluez/hci0")
    ad.UpdateProperties("org.bluez.Adapter1", props(Powered=dbus.Boolean(powered)))


def with_device(bt, name="MX Maus", mac=MAC, icon="input-mouse", paired=False, uuids=None):
    bt.m.bluez.AddDevice("hci0", mac, name)
    bt.m.device_mock(DEV).UpdateProperties("org.bluez.Device1", props(Icon=icon, UUIDs=dbus.Array(uuids if uuids is not None else ["00001124-0000-1000-8000-00805f9b34fb"], signature="s"), Paired=dbus.Boolean(paired)))


def pair_code(bt, mode="confirm", pin="0000", fail=None):
    """Replace the stand-in's Pair(): behave like BlueZ and call the registered agent."""
    code = f"""
import dbus
bus = dbus.SystemBus()
agent = dbus.Interface(bus.get_object("{bt.m.agent_name}", "{bz.AGENT_PATH}"), "org.bluez.Agent1")
dev = self.path
fail = {fail!r}
if fail:
    raise dbus.exceptions.DBusException("x", name=fail)
mode = "{mode}"
if mode == "confirm":
    agent.RequestConfirmation(dev, dbus.UInt32(123456), timeout=80)
elif mode == "pin":
    got = str(agent.RequestPinCode(dev, timeout=80))
    if got != "{pin}":
        raise dbus.exceptions.DBusException("wrong pin", name="org.bluez.Error.AuthenticationFailed")
elif mode == "passkey":
    got = int(agent.RequestPasskey(dev, timeout=80))
    if got != 654321:
        raise dbus.exceptions.DBusException("wrong passkey", name="org.bluez.Error.AuthenticationFailed")
elif mode == "display":
    agent.DisplayPasskey(dev, dbus.UInt32(424242), dbus.UInt16(0))
    import time; time.sleep(0.5)
self.UpdateProperties("org.bluez.Device1", {{"Paired": dbus.Boolean(True)}})
"""
    bt.m.device_mock(DEV).AddMethod("org.bluez.Device1", "Pair", "", "", code)


def wait(cond, timeout=8.0):
    end = time.time() + timeout
    while time.time() < end:
        v = cond()
        if v:
            return v
        time.sleep(0.05)
    raise AssertionError("condition not reached")


def request(bt):
    return wait(lambda: (bt.pairing_state()["requests"] or [None])[0])


def session(bt, sid):
    return next(s for s in bt.pairing_state()["sessions"] if s["id"] == sid)


def test_no_controller_present(bt):
    st = bt.status()
    assert st["running"] and st["adapters"] == []
    with pytest.raises(OpError) as e:
        bt.start_scan(10)
    assert e.value.code == "no_adapter"
    with pytest.raises(OpError):
        bt.set_powered(True)


def test_power_scan_and_device_list(bt):
    with_adapter(bt, powered=False)
    with pytest.raises(OpError) as e:
        bt.start_scan(10)
    assert e.value.code == "powered_off"
    bt.set_powered(True)
    assert bt.status()["adapters"][0]["powered"] is True
    with_device(bt)
    r = bt.start_scan(10)
    assert r["scanning"] and bt.status()["adapters"][0]["discovering"] is True
    d = bt.status()["devices"][0]
    assert d["name"] == "MX Maus" and d["type"] == "mouse" and d["type_label"] == "Maus" and d["hid"] and d["paired"] is False
    bt.stop_scan()
    assert bt.status()["adapters"][0]["discovering"] is False


@pytest.mark.parametrize("secs", [0, 1, 61, "30", None, True])
def test_scan_duration_validated(bt, secs):
    with_adapter(bt)
    with pytest.raises(ValueError):
        bt.start_scan(secs)


@pytest.mark.parametrize("mac", ["zz", "11:22:33:44:55", "11:22:33:44:55:66; reboot", "", "../../etc", "11-22-33-44-55-66"])
def test_invalid_device_addresses_rejected(bt, mac):
    with_adapter(bt); with_device(bt)
    for fn in (bt.pair, bt.connect, bt.disconnect, bt.remove):
        with pytest.raises(ValueError):
            fn(mac)


def test_pairing_with_numeric_confirmation_succeeds_and_trusts_the_device(bt):
    with_adapter(bt); with_device(bt); pair_code(bt, "confirm")
    s = bt.pair(MAC)
    r = request(bt)
    assert r["kind"] == "confirm" and r["passkey"] == "123456" and r["address"] == MAC and r["expires_in"] <= 60
    assert session(bt, s["id"])["state"] == "awaiting_user"
    bt.answer(r["id"], True)
    wait(lambda: session(bt, s["id"])["state"] == "paired")
    d = bt.status()["devices"][0]
    assert d["paired"] and d["trusted"], "trusted so HID devices can reconnect automatically"
    wait(lambda: any(k == "bt.paired" for k, _ in bt.events_log))
    assert not bt.status()["requests"]
    assert bt.status()["adapters"][0]["pairable"] is False, "pairable window closed again"


def test_user_rejects_the_confirmation(bt):
    with_adapter(bt); with_device(bt); pair_code(bt, "confirm")
    s = bt.pair(MAC)
    bt.answer(request(bt)["id"], False)
    wait(lambda: session(bt, s["id"])["state"] == "failed")
    assert bt.status()["devices"][0]["paired"] is False


def test_legacy_pin_pairing_right_and_wrong_pin(bt):
    with_adapter(bt); with_device(bt, name="Headset", icon="audio-headset", uuids=[]); pair_code(bt, "pin", pin="1234")
    s = bt.pair(MAC)
    r = request(bt)
    assert r["kind"] == "pin" and r["wants_input"] is True
    with pytest.raises(ValueError):
        bt.answer(r["id"], True, "")
    with pytest.raises(ValueError):
        bt.answer(r["id"], True, "x" * 17)
    bt.answer(r["id"], True, "0000")                                  # wrong PIN -> device refuses
    wait(lambda: session(bt, s["id"])["state"] == "failed")
    assert "PIN" in session(bt, s["id"])["message"] or "abgelehnt" in session(bt, s["id"])["message"]
    s2 = bt.pair(MAC)
    bt.answer(request(bt)["id"], True, "1234")
    wait(lambda: session(bt, s2["id"])["state"] == "paired")


def test_passkey_entry_validated(bt):
    with_adapter(bt); with_device(bt, icon="input-keyboard"); pair_code(bt, "passkey")
    s = bt.pair(MAC)
    r = request(bt)
    assert r["kind"] == "passkey"
    for bad in ("abc", -1, 1000000, None):
        with pytest.raises(ValueError):
            bt.answer(r["id"], True, bad)
    bt.answer(r["id"], True, "654321")
    wait(lambda: session(bt, s["id"])["state"] == "paired")


def test_display_passkey_for_keyboards_is_shown_to_the_user(bt):
    with_adapter(bt); with_device(bt, icon="input-keyboard"); pair_code(bt, "display")
    s = bt.pair(MAC)
    wait(lambda: bt.pairing_state()["display"])
    assert bt.pairing_state()["display"][0]["value"] == "424242" and "424242" in session(bt, s["id"])["message"]
    wait(lambda: session(bt, s["id"])["state"] == "paired")


def test_request_times_out_and_is_rejected(bt, monkeypatch):
    monkeypatch.setattr(bz, "REQUEST_TIMEOUT", 1)
    with_adapter(bt); with_device(bt); pair_code(bt, "confirm")
    s = bt.pair(MAC)
    wait(lambda: bt.pairing_state()["requests"])
    wait(lambda: session(bt, s["id"])["state"] == "failed", timeout=10)
    assert any(k == "bt.pairing_request_expired" for k, _ in bt.events_log)
    with pytest.raises(OpError) as e:
        bt.answer("deadbeef", True)
    assert e.value.code == "request_gone"


def test_unsolicited_pairing_request_is_rejected_and_reported(bt):
    with_adapter(bt); with_device(bt)
    bt.ensure_agent()
    remote = dbus.SystemBus(private=True)             # a different D-Bus connection, like bluetoothd calling us
    agent = dbus.Interface(remote.get_object(bt.m.agent_name, bz.AGENT_PATH), "org.bluez.Agent1")
    with pytest.raises(dbus.DBusException) as e:
        agent.RequestConfirmation(DEV, dbus.UInt32(111111), timeout=10)
    assert e.value.get_dbus_name() == "org.bluez.Error.Rejected"
    with pytest.raises(dbus.DBusException):
        agent.RequestPinCode(DEV, timeout=10)
    with pytest.raises(dbus.DBusException):
        agent.AuthorizeService(DEV, "0000110b-0000-1000-8000-00805f9b34fb", timeout=10)
    ev = [kw for k, kw in bt.events_log if k in ("bt.pairing_rejected_unsolicited", "bt.service_rejected")]
    assert len(ev) == 3 and all(kw["severity"] == "warning" for kw in ev)
    assert bt.status()["requests"] == []


def test_a_session_for_one_device_does_not_authorise_another(bt):
    with_adapter(bt); with_device(bt); pair_code(bt, "confirm")
    bt.m.bluez.AddDevice("hci0", "AA:BB:CC:DD:EE:FF", "Fremdes Gerät")
    bt.pair(MAC)
    remote = dbus.SystemBus(private=True)
    agent = dbus.Interface(remote.get_object(bt.m.agent_name, bz.AGENT_PATH), "org.bluez.Agent1")
    with pytest.raises(dbus.DBusException) as e:
        agent.RequestConfirmation("/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF", dbus.UInt32(5), timeout=10)
    assert e.value.get_dbus_name() == "org.bluez.Error.Rejected"
    bt.cancel_pairing()


@pytest.mark.parametrize("err,expect", [("org.bluez.Error.ConnectionAttemptFailed", "außer Reichweite"), ("org.bluez.Error.AuthenticationTimeout", "Kopplungsmodus"), ("org.bluez.Error.AuthenticationRejected", "abgelehnt"),
                                         ("org.bluez.Error.NotReady", "nicht bereit")])
def test_pairing_failures_are_explained_and_device_unreachable(bt, err, expect):
    with_adapter(bt); with_device(bt); pair_code(bt, fail=err)
    s = bt.pair(MAC)
    wait(lambda: session(bt, s["id"])["state"] == "failed")
    assert expect in session(bt, s["id"])["message"]
    assert any(k == "bt.pairing_failed" for k, _ in bt.events_log)


def test_already_paired_and_only_one_pairing_at_a_time(bt):
    with_adapter(bt); with_device(bt, paired=True)
    with pytest.raises(OpError) as e:
        bt.pair(MAC)
    assert e.value.code == "already_paired" and "verbinden" in str(e.value)
    bt.m.bluez.AddDevice("hci0", "AA:BB:CC:DD:EE:FF", "Zweites")
    bt.m.device_mock(DEV).UpdateProperties("org.bluez.Device1", props(Paired=dbus.Boolean(False)))
    pair_code(bt, "confirm")
    bt.pair(MAC)
    with pytest.raises(OpError) as e:
        bt.pair("AA:BB:CC:DD:EE:FF")
    assert e.value.code == "busy"
    bt.cancel_pairing()


def test_pair_requires_powered_adapter_and_known_device(bt):
    with_adapter(bt, powered=False); with_device(bt)
    with pytest.raises(OpError) as e:
        bt.pair(MAC)
    assert e.value.code == "powered_off"
    bt.set_powered(True)
    with pytest.raises(OpError) as e:
        bt.pair("AA:BB:CC:DD:EE:FF")
    assert e.value.code == "not_found"


def test_connect_disconnect_trust_remove(bt):
    with_adapter(bt); with_device(bt, paired=True)
    assert bt.connect(MAC) == {"connected": True}                    # (the stand-in does not reflect Connected in GetManagedObjects; its state is checked via the next calls)
    with pytest.raises(OpError) as e:
        bt.connect(MAC)
    assert "bereits verbunden" in str(e.value)
    assert bt.disconnect(MAC) == {"connected": False}
    with pytest.raises(OpError) as e:
        bt.disconnect(MAC)
    assert "nicht verbunden" in str(e.value)
    bt.set_trusted(MAC, True)
    assert bt.status()["devices"][0]["trusted"] is True
    with pytest.raises(ValueError):
        bt.set_trusted(MAC, "yes")
    bt.remove(MAC)
    assert bt.status()["devices"] == []


@pytest.mark.parametrize("icon,cod,app,uuids,expect", [("input-mouse", 0, 0, [], "mouse"), ("", 0, 0x03C2, [], "mouse"), ("input-keyboard", 0, 0, [], "keyboard"), ("audio-headset", 0, 0, [], "headphones"),
                                                       ("audio-headphones", 0, 0, [], "headphones"), ("audio-speakers", 0, 0, [], "speaker"), ("", 0x240414, 0, [], "speaker"), ("phone", 0, 0, [], "phone"),
                                                       ("", 0x002540, 0, [], "keyboard"), ("", 0x002580, 0, [], "mouse"), ("", 0, 0, ["00001124-0000-1000-8000-00805f9b34fb"], "hid"), ("", 0, 0, [], "other")])
def test_device_classification(icon, cod, app, uuids, expect):
    assert bz.device_type(icon, cod, app, uuids)[0] == expect


def test_priority_devices_listed_first(bt):
    with_adapter(bt)
    bt.m.bluez.AddDevice("hci0", "AA:AA:AA:AA:AA:01", "Handy")
    bt.m.device_mock("/org/bluez/hci0/dev_AA_AA_AA_AA_AA_01").UpdateProperties("org.bluez.Device1", props(Icon="phone"))
    with_device(bt)
    assert [d["type"] for d in bt.status()["devices"]] == ["mouse", "phone"]
