"""Backend gateway to pios-connd: authorisation, secret handling, error mapping, events -> notifications/audit, Shield check.
connd is replaced by a recording stand-in on a real unix socket (the real daemon is covered in tests/connd)."""
import json
import os
import threading

import pytest

from pios_connd.ipc import OpError, Server

PSK = "hunter2-secret-psk"


@pytest.fixture()
def connd(admin, tmp_path, monkeypatch):
    calls, state = [], {"events": [], "fail": None}

    def verb(name, result=None):
        def f(a):
            calls.append((name, dict(a)))
            if state["fail"]:
                raise OpError(*state["fail"])
            return result if result is not None else {"ok": True}
        return f
    verbs = {n: verb(n) for n in ("net.status", "wifi.scan", "wifi.networks", "wifi.set_enabled", "wifi.forget", "wifi.autoconnect", "net.disconnect", "eth.set_dhcp", "wifi.set_country",
                                  "net.confirm", "net.revert", "bt.status", "bt.pairing", "bt.set_powered", "bt.scan", "bt.scan_stop", "bt.pair", "bt.answer", "bt.cancel", "bt.connect",
                                  "bt.disconnect", "bt.trust", "bt.remove", "hw.input_diag", "hw.drivers", "hw.rescan")}
    verbs["wifi.connect"] = verb("wifi.connect", {"op": "abc123", "protected": True})
    verbs["net.summary"] = verb("net.summary", {"online": True, "pending": {"seconds_left": 40, "description": "WLAN wechseln", "iface": "wlan0"}})
    verbs["net.security"] = verb("net.security", {"nm": True, "bluez": True, "findings": [], "pending": None})
    verbs["hw.inventory"] = verb("hw.inventory", {"platform": {"model": "Raspberry Pi 5", "revision": "d04170"}, "network": [{"name": "wlan0", "mac": "aa:bb", "modalias": "x"}],
                                                  "input": [{"name": "Maus", "uniq": "11:22", "phys": "p", "sysfs": "/s"}], "usb": [{"product": "Receiver", "bus": 1, "dev": 4,
                                                  "interfaces": [{"modalias": "usb:x"}]}], "problems": [{"id": "usb1", "text": "Kein Treiber"}]})
    verbs["events.since"] = lambda a: {"last": len(state["events"]), "events": [e for e in state["events"] if e["id"] > a["since"]]}
    sock = tmp_path / "c.sock"
    monkeypatch.setenv("PIOS_CONND_SOCKET", str(sock))
    srv = Server(sock, verbs, {os.getuid()})
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield type("C", (), {"calls": calls, "state": state, "c": admin})
    srv.shutdown(); srv.server_close()


@pytest.fixture()
def anna(connd, client):
    connd.c.post("/api/users", json={"username": "anna", "password": "anna-long-password"})
    from fastapi.testclient import TestClient
    from pios import main
    with TestClient(main.app, base_url="http://testserver", client=("192.168.1.60", 5555)) as c:
        c.headers.update({"X-PiOS": "1"})
        assert c.post("/api/login", json={"username": "anna", "password": "anna-long-password"}).status_code == 200
        yield c


def audit_text():
    from pios import audit
    return json.dumps(audit.recent(200))


def test_wifi_password_reaches_connd_only_and_never_audit_or_response(connd):
    r = connd.c.post("/api/net/wifi/connect", json={"ssid": "Heim", "psk": PSK})
    assert r.status_code == 200 and PSK not in r.text
    name, args = connd.calls[-1]
    assert name == "wifi.connect" and args["psk"] == PSK and args["client_ip"] == "192.168.1.50"
    assert PSK not in audit_text() and "net.wifi_connect" in audit_text()


def test_validation_errors_never_echo_submitted_values(connd):
    r = connd.c.post("/api/net/wifi/connect", json={"ssid": "Heim", "psk": PSK * 20})
    assert r.status_code == 422 and PSK not in r.text
    assert connd.c.post("/api/net/wifi/connect", json={"ssid": "Heim", "psk": PSK, "extra": 1}).status_code == 422
    assert not [c for c in connd.calls if c[0] == "wifi.connect"]


def test_mutations_are_admin_only_and_summary_is_redacted_for_users(connd, anna):
    for method, url, body in [("post", "/api/net/wifi/connect", {"ssid": "x"}), ("post", "/api/net/wifi/scan", None), ("get", "/api/net", None), ("post", "/api/bt/pair", {"address": "11:22:33:44:55:66"}),
                              ("get", "/api/bt", None), ("post", "/api/hw/packages/install", {"package": "firmware-realtek", "version": "1"}), ("get", "/api/hw/input-diagnosis", None),
                              ("post", "/api/net/ethernet/dhcp", {"iface": "eth0"}), ("delete", "/api/net/wifi/known/abc", None)]:
        r = getattr(anna, method)(url, **({"json": body} if body is not None else {}))
        assert r.status_code == 403, (url, r.status_code)
    assert connd.calls == [] or all(c[0] in ("net.summary", "hw.inventory") for c in connd.calls)
    s = anna.get("/api/net/summary").json()
    assert s["pending"] == {"seconds_left": 40}, "users learn that a change is pending, not what"
    hw = anna.get("/api/hw").json()
    flat = json.dumps(hw)
    for secret in ("aa:bb", "11:22", "d04170", "/s"):
        assert secret not in flat
    assert "Raspberry Pi 5" in flat
    assert "aa:bb" in json.dumps(connd.c.get("/api/hw").json()), "admins see everything"


def test_csrf_header_is_required(connd):
    connd.c.headers.pop("X-PiOS")
    assert connd.c.post("/api/net/confirm").status_code in (400, 403)


def test_connd_error_codes_map_to_http_and_messages_pass_through(connd):
    connd.state["fail"] = ("Eine Netzwerkänderung wartet noch auf Bestätigung.", "pending")
    r = connd.c.post("/api/net/wifi/connect", json={"ssid": "Heim", "psk": PSK})
    assert r.status_code == 409 and "Bestätigung" in r.json()["detail"]
    connd.state["fail"] = ("WEP ist unsicher", "unsupported_security")
    assert connd.c.post("/api/net/wifi/connect", json={"ssid": "Heim"}).status_code == 422
    connd.state["fail"] = ("Netzwerk nicht gefunden", "not_found")
    assert connd.c.delete("/api/net/wifi/known/abc").status_code == 404


def test_missing_connd_gives_a_clear_503(admin, tmp_path, monkeypatch):
    monkeypatch.setenv("PIOS_CONND_SOCKET", str(tmp_path / "nope.sock"))
    r = admin.get("/api/net")
    assert r.status_code == 503 and "pios-connd" in r.json()["detail"]


def test_pairing_answers_and_changes_are_audited_without_secrets(connd):
    connd.c.post("/api/bt/pair", json={"address": "aa:bb:cc:dd:ee:ff"})
    connd.c.post("/api/bt/pair/answer", json={"id": "r1", "accept": True, "value": "123456"})
    connd.c.post("/api/bt/trust", json={"address": "AA:BB:CC:DD:EE:FF", "trusted": True})
    connd.c.post("/api/bt/remove", json={"address": "AA:BB:CC:DD:EE:FF"})
    t = audit_text()
    for k in ("bt.pair_started", "bt.pair_answered", "bt.trust", "bt.remove"):
        assert k in t
    assert "123456" not in t
    assert connd.c.post("/api/bt/pair/answer", json={"id": "r1", "accept": True, "value": "x" * 40}).status_code == 422


def test_package_install_goes_through_sysops_with_explicit_version_and_is_audited(connd, monkeypatch):
    from pios import sysops
    seen = []
    monkeypatch.setattr(sysops, "call", lambda m, a, t=30: seen.append((m, a)) or {"started": True})
    r = connd.c.post("/api/hw/packages/install", json={"package": "firmware-realtek", "version": "20240709-2"})
    assert r.status_code == 200 and seen == [("pkg.install", {"package": "firmware-realtek", "version": "20240709-2"})]
    assert "hw.package_install" in audit_text()
    assert connd.c.post("/api/hw/packages/install", json={"package": "firmware-realtek"}).status_code == 422, "version confirmation is mandatory"

    def refuse(m, a, t=30):
        raise sysops.OpError("Paket nicht erlaubt", "not_allowed")
    monkeypatch.setattr(sysops, "call", refuse)
    r = connd.c.post("/api/hw/packages/install", json={"package": "evil", "version": "1"})
    assert r.status_code == 403 and "hw.package_refused" in audit_text()


def test_events_become_notifications_and_audit_entries_exactly_once(connd):
    from pios import connectivity as cv, events
    connd.state["events"] += [
        {"id": 1, "name": "net.wifi_connected", "detail": {"ssid": "Heim"}},
        {"id": 2, "name": "bt.pairing_rejected_unsolicited", "detail": {"device_name": "Fremdgerät", "severity": "warning"}},
        {"id": 3, "name": "net.change_reverted", "detail": {"description": "WLAN wechseln", "reason": "Zeit abgelaufen"}},
        {"id": 4, "name": "hw.usb_added", "detail": {"device": "USB Receiver"}}]
    batch = cv.call("events.since", {"since": 0})
    cv._last["id"] = 0
    cv.process_events(batch); cv.process_events(batch)
    notes = [e for e in events._log if e["kind"] == "notification" and e["app"] == "network"]
    assert [n["title"] for n in notes] == ["WLAN verbunden", "Unerwartete Bluetooth-Kopplungsanfrage abgelehnt", "Netzwerkänderung zurückgesetzt", "USB-Gerät angeschlossen"]
    assert notes[1]["level"] == "warn"
    t = audit_text()
    assert "bt.pairing_rejected_unsolicited" in t and "net.change_reverted" in t and "net.wifi_connected" not in t


def test_shield_connectivity_check_is_honest(connd, monkeypatch):
    from pios import shield
    assert shield.check_connectivity()["level"] == "ok"
    connd.state["fail"] = None
    sec = {"nm": True, "bluez": True, "pending": None, "findings": [{"id": "bt_discoverable", "level": "attention", "text": "Bluetooth sichtbar"}]}
    monkeypatch.setattr("pios.connectivity.call", lambda m, a=None, timeout=0: sec)
    c = shield.check_connectivity()
    assert c["level"] == "attention" and "sichtbar" in c["detail"]
    sec.update(bluez=False, findings=[])
    assert shield.check_connectivity()["level"] == "limited"
    sec.update(nm=False)
    assert shield.check_connectivity()["level"] == "unknown"

    def down(*a, **k):
        raise OSError("nope")
    monkeypatch.setattr("pios.connectivity.call", down)
    c = shield.check_connectivity()
    assert c["level"] == "unknown" and "konnten nicht geprüft" in c["detail"]
