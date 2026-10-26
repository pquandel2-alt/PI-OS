import json
import time

import pytest

from pios_connd import netguard
from pios_connd.ipc import OpError
from tests.connd.fakehw import Runner


class FakeNM:
    def __init__(self):
        self.calls = []

    def set_wifi_enabled(self, v): self.calls.append(("wifi_enabled", v))
    def delete_connection(self, u): self.calls.append(("delete", u))
    def restore_ipv4(self, u, prev): self.calls.append(("ipv4", u, prev))
    def activate(self, u, iface=None): self.calls.append(("activate", u, iface))


@pytest.fixture()
def guard(tmp_path):
    nm = FakeNM()
    events = []
    g = netguard.Guard(nm, tmp_path / "state", runner=Runner(**{"ip|-j|route|get|192.168.1.50": (0, json.dumps([{"dst": "192.168.1.50", "dev": "wlan0"}])),
                                                                "ip|-j|route|get|10.0.0.2": (0, json.dumps([{"dst": "10.0.0.2", "dev": "eth0"}])),
                                                                "ip|-j|route|get|203.0.113.5": (1, "")}),
                       confirm_seconds=60, events=lambda name, **kw: events.append((name, kw)))
    g.fake, g.events_log = nm, events
    return g


def test_admin_interface_detection(guard):
    assert guard.admin_iface("192.168.1.50") == "wlan0" and guard.admin_iface("10.0.0.2") == "eth0"
    assert guard.admin_iface("127.0.0.1") is None and guard.admin_iface("::1") is None and guard.admin_iface(None) is None, "the HDMI kiosk cannot lock itself out over the network"
    assert guard.admin_iface("203.0.113.5") is None, "unknown route -> no claim"
    with pytest.raises(ValueError):
        guard.admin_iface("1.2.3.4; reboot")


UNDO = {"delete_uuids": ["11111111-2222-3333-4444-555555555555"], "activate": {"uuid": "99999999-2222-3333-4444-555555555555", "iface": "wlan0"}, "wifi_enabled": True}


def test_unconfirmed_change_is_reverted_automatically(tmp_path):
    nm = FakeNM()
    g = netguard.Guard(nm, tmp_path, runner=Runner(), confirm_seconds=1)
    g.begin("wifi_connect", "WLAN wechseln", "wlan0", UNDO)
    assert g.pending()["seconds_left"] <= 1
    time.sleep(1.6)
    assert g.pending() is None and ("delete", "11111111-2222-3333-4444-555555555555") in nm.calls and ("activate", "99999999-2222-3333-4444-555555555555", "wlan0") in nm.calls
    assert ("wifi_enabled", True) in nm.calls and not (tmp_path / "pending.json").exists()


def test_confirmed_change_stays(guard):
    guard.begin("wifi_connect", "x", "wlan0", UNDO)
    assert (guard.path).exists() and oct(guard.path.stat().st_mode & 0o777) == "0o600"
    guard.confirm()
    assert guard.pending() is None and guard.fake.calls == [] and not guard.path.exists()
    with pytest.raises(OpError):
        guard.confirm()
    with pytest.raises(OpError):
        guard.revert()


def test_only_one_pending_change(guard):
    guard.begin("a", "x", "wlan0", {})
    with pytest.raises(OpError) as e:
        guard.begin("b", "y", "wlan0", {})
    assert e.value.code == "pending"
    guard.revert("test")


def test_manual_revert_runs_every_step_even_if_one_fails(guard):
    def boom(u): raise RuntimeError("gone")
    guard.fake.delete_connection = boom
    guard.begin("a", "x", "wlan0", UNDO)
    guard.revert("manuell")
    assert ("activate", "99999999-2222-3333-4444-555555555555", "wlan0") in guard.fake.calls and ("wifi_enabled", True) in guard.fake.calls


def test_revert_on_failed_operation_only_for_the_matching_op(guard):
    guard.begin("wifi_connect", "x", "wlan0", UNDO, op="op1")
    assert guard.revert_if_op("other", "r") is False and guard.pending() is not None
    assert guard.revert_if_op("op1", "Passwort falsch") is True and guard.pending() is None


def test_power_loss_during_the_window_rolls_back_on_next_start(tmp_path):
    nm = FakeNM()
    g1 = netguard.Guard(nm, tmp_path, runner=Runner(), confirm_seconds=300)
    g1.begin("ethernet_dhcp", "IP wechselt", "eth0", {"ipv4": {"uuid": "11111111-2222-3333-4444-555555555555", "previous": {"method": "manual"}}})
    # "power cut": the process disappears, the timer never fires; the journal file survives
    g2 = netguard.Guard(nm, tmp_path, runner=Runner())
    assert g2.recover() is True
    assert nm.calls == [("ipv4", "11111111-2222-3333-4444-555555555555", {"method": "manual"})] and not (tmp_path / "pending.json").exists()
    assert netguard.Guard(nm, tmp_path, runner=Runner()).recover() is False


def test_events_are_emitted(guard):
    guard.begin("a", "Beschreibung", "wlan0", {})
    guard.confirm()
    guard.begin("a", "Zweite", "wlan0", {})
    guard.revert("weil")
    assert [n for n, _ in guard.events_log] == ["net.change_pending", "net.change_confirmed", "net.change_pending", "net.change_reverted"]
