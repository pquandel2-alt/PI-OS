"""Backend <-> unix socket <-> firewall daemon (with a recording nft stand-in; the real nft is covered in tests/firewall)."""
import os
import threading

import pytest

from pios_firewall.engine import Firewall, FirewallError
from pios_firewall.server import Server


class RecNft:
    def __init__(self): self.loaded, self.checked, self.fail_check = [], [], False
    def check(self, script):
        if self.fail_check:
            raise FirewallError("Regelwerk ungültig: kaputt", "invalid_ruleset")
        self.checked.append(script)
    def load(self, script): self.loaded.append(script)
    def table_json(self):
        return {"nftables": [{"chain": {"name": "input", "hook": "input", "policy": "drop"}}, {"chain": {"name": "forward", "hook": "forward", "policy": "drop"}}]}


@pytest.fixture()
def fwd(admin, tmp_path, monkeypatch):
    nft = RecNft()
    fw = Firewall(nft, tmp_path / "state", detect=lambda: ([], []), confirm_seconds=60)
    sock = tmp_path / "fw.sock"
    monkeypatch.setenv("PIOS_FIREWALL_SOCKET", str(sock))
    srv = Server(sock, fw, {os.getuid()})
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    fw.boot()
    fwd = type("F", (), {"fw": fw, "nft": nft, "srv": srv, "c": admin})
    yield fwd
    srv.shutdown(); srv.server_close()


def kinds():
    from pios import audit
    return [e["kind"] for e in audit.recent(100)]


def test_status_through_the_api(fwd):
    st = fwd.c.get("/api/shield/firewall").json()
    assert st["config"]["web_scope"] == "lan" and st["pending"] is None


def test_apply_confirm_flow_is_audited(fwd):
    body = {"web_scope": "lan", "ssh": True}
    p = fwd.c.post("/api/shield/firewall/preview", json=body).json()
    assert "tcp dport 22" in p["script"] and "flush ruleset" not in p["script"]
    r = fwd.c.post("/api/shield/firewall/apply", json=body)
    assert r.status_code == 200 and r.json()["pending"]["seconds_left"] > 0
    assert fwd.c.post("/api/shield/firewall/apply", json=body).status_code == 409, "second change must wait for confirmation"
    assert fwd.c.post("/api/shield/firewall/confirm").status_code == 200
    assert fwd.c.get("/api/shield/firewall").json()["config"]["ssh"] is True
    assert fwd.c.post("/api/shield/firewall/confirm").status_code == 409
    assert {"firewall.change_applied", "firewall.change_confirmed"} <= set(kinds())


def test_revert_restores_confirmed_policy(fwd):
    fwd.c.post("/api/shield/firewall/apply", json={"ssh": True})
    r = fwd.c.post("/api/shield/firewall/revert")
    assert r.status_code == 200 and r.json()["pending"] is None and r.json()["config"]["ssh"] is False
    assert "tcp dport 22" not in fwd.nft.loaded[-1]
    assert "firewall.reverted" in kinds()


def test_invalid_input_is_rejected_before_anything_is_loaded(fwd):
    n = len(fwd.nft.loaded)
    for bad in ({"web_scope": "custom"}, {"web_scope": "custom", "web_cidrs": ["0.0.0.0/0"]}, {"web_scope": "custom", "web_cidrs": ["x"]}):
        assert fwd.c.post("/api/shield/firewall/apply", json=bad).status_code == 400, bad
    assert fwd.c.post("/api/shield/firewall/apply", json={"web_scope": "evil"}).status_code == 422
    assert fwd.c.post("/api/shield/firewall/apply", json={"nft": "flush ruleset"}).status_code == 422
    assert len(fwd.nft.loaded) == n
    fwd.nft.fail_check = True
    r = fwd.c.post("/api/shield/firewall/apply", json={"ssh": True})
    assert r.status_code == 400 and "ungültig" in r.json()["detail"] and len(fwd.nft.loaded) == n


def test_firewall_down_gives_503_and_status_is_not_protected(fwd):
    fwd.srv.shutdown(); fwd.srv.server_close()
    assert fwd.c.get("/api/shield/firewall").status_code == 503
    j = fwd.c.get("/api/shield").json()
    fw = next(c for c in j["checks"] if c["id"] == "firewall")
    assert fw["level"] == "unknown" and j["status"] != "protected"


def test_daemon_refuses_foreign_uid(fwd):
    fwd.srv.allowed_uids = {123456}
    assert fwd.c.get("/api/shield/firewall").status_code == 502
