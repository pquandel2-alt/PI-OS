"""The overall status must never say "Geschützt" unless every required check actually ran and passed."""
import time

import pytest

FW_OK = {"api": 1, "active": True, "problems": [], "config": {"web_scope": "lan", "web_cidrs": [], "ssh": False, "mdns": True, "ping": True}, "pending": None,
         "expected_ports": {"tcp": [80], "udp": [68, 546, 5353]}, "last_event": None, "confirm_seconds": 60}
OS_OK = {"status": {"checked_at": int(time.time()), "ok": True, "signature_ok": True, "upgradable": [], "security": [], "source_problems": [], "reboot_required": False},
         "last_upgrade": {"ok": True}, "auto_security": True, "check_running": False, "upgrade_running": False, "reboot_required": False}
OTA_OK = {"installed": {"version": "0.2.0"}, "available": None, "last_success": int(time.time()), "last_error": None, "job": None, "rejected": {}}


@pytest.fixture()
def shield(admin, monkeypatch, tmp_path):
    from pios import firewall, malware, shield as sh, sysops, updates
    state = {"fw": dict(FW_OK), "os": dict(OS_OK), "ota": dict(OTA_OK)}

    def fw_call(method, args=None, timeout=0):
        if state["fw"] is None:
            raise firewall.Unavailable("down")
        return state["fw"]
    def sys_call(method, args=None, timeout=0):
        if state["os"] is None:
            raise sysops.Unavailable("down")
        return state["os"]
    def ota_call(method, args=None, timeout=0):
        if state["ota"] is None:
            raise updates.Unavailable("down")
        return state["ota"]
    monkeypatch.setattr(firewall, "call", fw_call); monkeypatch.setattr(sysops, "call", sys_call); monkeypatch.setattr(updates, "call", ota_call)
    monkeypatch.setattr(sh, "check_hardening", lambda: sh.chk("service", "Dienst-Härtung", "ok", "ok"))
    # healthy scanner: signatures present and fresh, a finished scan, ClamAV "installed"
    monkeypatch.setenv("PIOS_MALWARE", "")
    monkeypatch.setattr(malware, "env_off", lambda: False)
    monkeypatch.setattr(malware, "installed", lambda: True)
    monkeypatch.setattr(malware, "signature_info", lambda: {"present": True, "newest": int(time.time()) - 3600, "age_days": 0.1, "files": []})
    from pios import db
    with db.connect() as c:
        c.execute("INSERT INTO scans(kind,state,started,finished) VALUES('manual','done',?,?)", (int(time.time()) - 100, int(time.time()) - 50))
    admin.state = state
    return admin


def status(c):
    r = c.get("/api/shield")
    assert r.status_code == 200, r.text
    return r.json()


def check(j, cid):
    return next(x for x in j["checks"] if x["id"] == cid)


def test_everything_verified_gives_protected(shield):
    j = status(shield)
    assert j["status"] == "protected" and j["label"] == "Geschützt", [(c["id"], c["level"], c["detail"]) for c in j["checks"] if c["level"] not in ("ok", "info")]


def test_unreachable_firewall_is_never_reported_as_protected(shield):
    shield.state["fw"] = None
    j = status(shield)
    assert j["status"] == "unknown" and check(j, "firewall")["level"] == "unknown" and "nicht geprüft werden" in check(j, "firewall")["detail"]


def test_inactive_firewall_is_critical(shield):
    shield.state["fw"] = {**FW_OK, "active": False, "problems": ["Tabelle inet pios_fw ist nicht geladen"]}
    j = status(shield)
    assert j["status"] == "critical" and "nicht geladen" in check(j, "firewall")["detail"]


def test_open_ssh_and_pending_confirmation_are_visible(shield):
    shield.state["fw"] = {**FW_OK, "config": {**FW_OK["config"], "ssh": True}, "expected_ports": {"tcp": [22, 80], "udp": []}}
    j = status(shield)
    assert j["status"] == "limited" and "SSH" in check(j, "firewall")["detail"]
    shield.state["fw"] = {**FW_OK, "pending": {"seconds_left": 42, "config": {}}}
    assert check(status(shield), "firewall")["level"] == "attention"


def test_pending_security_updates_need_attention(shield):
    shield.state["os"]["status"] = {**OS_OK["status"], "security": ["libssl3t64", "openssh-server"]}
    j = status(shield)
    assert j["status"] == "attention" and "libssl3t64" in check(j, "os")["detail"]


def test_reboot_required_and_failed_auto_upgrade_are_reported(shield):
    shield.state["os"] = {**OS_OK, "reboot_required": True}
    assert "Neustart" in check(status(shield), "os")["detail"]
    shield.state["os"] = {**OS_OK, "last_upgrade": {"ok": False, "error": "dpkg returned an error"}}
    assert check(status(shield), "os")["level"] == "attention"


def test_apt_signature_failure_is_critical(shield):
    shield.state["os"]["status"] = {**OS_OK["status"], "ok": False, "signature_ok": False, "error": "NO_PUBKEY"}
    j = status(shield)
    assert j["status"] == "critical" and "Signaturprüfung" in check(j, "os")["detail"]
    shield.state["os"]["status"] = {**OS_OK["status"], "source_problems": ["Eine APT-Quelle ist als trusted=yes markiert"]}
    assert check(status(shield), "os")["level"] == "critical"


def test_never_checked_os_updates_is_unknown_not_ok(shield):
    shield.state["os"] = {**OS_OK, "status": {}}
    j = status(shield)
    assert check(j, "os")["level"] == "unknown" and j["status"] == "unknown"


def test_stale_os_check_is_limited(shield):
    shield.state["os"]["status"] = {**OS_OK["status"], "checked_at": int(time.time()) - 5 * 86400}
    assert check(status(shield), "os")["level"] == "limited"


def test_rejected_update_signature_is_surfaced(shield):
    shield.state["ota"] = {**OTA_OK, "rejected": {"v9.9.9": "Signatur ungültig"}}
    j = status(shield)
    assert j["status"] == "attention" and "v9.9.9" in check(j, "ota")["detail"]


def test_available_ota_update_needs_attention_and_never_checked_is_unknown(shield):
    shield.state["ota"] = {**OTA_OK, "available": {"version": "0.3.0", "compatible": True}}
    assert check(status(shield), "ota")["level"] == "attention"
    shield.state["ota"] = {**OTA_OK, "last_success": None, "last_error": "offline"}
    c = check(status(shield), "ota"); assert c["level"] == "unknown" and "offline" in c["detail"]


def test_malware_protection_states(shield, monkeypatch):
    from pios import malware, db
    assert check(status(shield), "malware")["level"] == "ok"
    monkeypatch.setattr(malware, "signature_info", lambda: {"present": False, "newest": None, "files": []})
    c = check(status(shield), "malware"); assert c["level"] == "limited" and "keine Virensignaturen" in c["detail"]
    monkeypatch.setattr(malware, "signature_info", lambda: {"present": True, "newest": 1, "age_days": 45, "files": []})
    assert check(status(shield), "malware")["level"] == "attention"
    monkeypatch.setattr(malware, "signature_info", lambda: {"present": True, "newest": 1, "age_days": 1, "files": []})
    shield.put("/api/shield/malware/settings", json={"enabled": False})
    c = check(status(shield), "malware"); assert c["level"] == "limited" and "deaktiviert" in c["detail"]
    shield.put("/api/shield/malware/settings", json={"enabled": True})
    with db.connect() as cn:
        cn.execute("INSERT INTO users(id,username,password,role,created) VALUES(9,'x','x','user',1) ON CONFLICT DO NOTHING")
        cn.execute("INSERT INTO quarantine(id,uid,dest_dir,name,size,sha256,detected_type,state,created) VALUES('a'||hex(randomblob(15)),9,'','x',1,'0','t','infected',1)")
    c = check(status(shield), "malware"); assert c["level"] == "attention" and "Bedrohung" in c["detail"]
    assert status(shield)["threats"] == 1


def test_never_scanned_is_limited(shield):
    from pios import db
    with db.connect() as c:
        c.execute("DELETE FROM scans")
    assert check(status(shield), "malware")["level"] == "limited"


def test_sandbox_check_verifies_real_headers(shield, monkeypatch):
    assert check(status(shield), "sandbox")["level"] == "ok"
    from pios import apps
    from fastapi.responses import Response
    monkeypatch.setattr(apps, "app_asset", lambda app_id, path="": Response(headers={"content-security-policy": "default-src 'self'"}))
    c = check(status(shield), "sandbox"); assert c["level"] == "critical" and "Sandbox-Header" in c["detail"]


def test_failed_logins_and_lockouts_show_up(shield):
    from pios import audit
    for _ in range(11):
        audit.event("auth.login_failed", "warning", actor="x", ip="1.2.3.4")
    c = check(status(shield), "access"); assert c["level"] == "attention" and c["failed_24h"] >= 11
    audit.event("auth.locked_out", "warning", actor="x")
    assert "gesperrt" in check(status(shield), "access")["detail"]


def test_tampered_audit_log_is_critical(shield):
    import sqlite3
    from pios import audit, config
    audit.event("t.a", "info"); audit.event("t.b", "info"); audit.event("t.c", "info")
    c = sqlite3.connect(config.DATA / "pios.db"); c.execute("DELETE FROM audit WHERE kind='t.b'"); c.commit(); c.close()
    j = status(shield)
    assert j["status"] == "critical" and check(j, "audit")["level"] == "critical"


def test_hardening_self_attestation_flags_root_or_missing_sandbox(shield, monkeypatch):
    from pios import shield as sh
    monkeypatch.undo()   # use the real check against the pytest process (unsandboxed dev run)
    c = sh.check_hardening()
    assert c["level"] in ("limited", "critical") and ("NoNewPrivileges" in c["detail"] or "root" in c["detail"])


def test_browser_check_detects_unsafe_flags(shield, monkeypatch, tmp_path):
    script = tmp_path / "kiosk"; script.write_text("exec chromium --kiosk --no-sandbox http://127.0.0.1/\n")
    pol = tmp_path / "pios.json"; pol.write_text("{}")
    monkeypatch.setenv("PIOS_KIOSK_SCRIPT", str(script)); monkeypatch.setenv("PIOS_CHROMIUM_POLICY", str(pol))
    assert check(status(shield), "browser")["level"] == "critical"
    script.write_text("exec chromium --kiosk http://127.0.0.1/\n")
    assert check(status(shield), "browser")["level"] == "ok"
    pol.unlink()
    assert check(status(shield), "browser")["level"] == "limited"


def test_overview_requires_admin(admin, client):
    from fastapi.testclient import TestClient
    admin.post("/api/users", json={"username": "anna", "password": "anna-long-password"})
    anna = TestClient(client.app, client=("192.168.1.8", 1)); anna.headers.update({"X-PiOS": "1"})
    anna.post("/api/login", json={"username": "anna", "password": "anna-long-password"})
    for url in ("/api/shield", "/api/shield/firewall", "/api/shield/os", "/api/shield/malware", "/api/shield/audit", "/api/shield/scans"):
        assert anna.get(url).status_code == 403, url
    for url in ("/api/shield/firewall/apply", "/api/shield/os/upgrade", "/api/shield/scans", "/api/shield/signatures/update"):
        assert anna.post(url, json={}).status_code == 403, url
    anon = TestClient(client.app, client=("192.168.1.9", 1)); anon.headers.update({"X-PiOS": "1"})
    assert anon.get("/api/shield").status_code == 401


def test_shipped_kiosk_script_and_policy_pass_the_browser_check(shield, monkeypatch):
    from pathlib import Path
    root = Path(__file__).resolve().parents[2] / "image/overlay"
    monkeypatch.setenv("PIOS_KIOSK_SCRIPT", str(root / "opt/pios/bin/pios-kiosk-browser"))
    monkeypatch.setenv("PIOS_CHROMIUM_POLICY", str(root / "etc/chromium/policies/managed/pios.json"))
    c = check(status(shield), "browser")
    assert c["level"] == "ok", c


def test_chromium_policy_blocks_everything_but_loopback_pios():
    import json
    from pathlib import Path
    pol = json.loads((Path(__file__).resolve().parents[2] / "image/overlay/etc/chromium/policies/managed/pios.json").read_text())
    assert pol["URLBlocklist"] == ["*"] and set(pol["URLAllowlist"]) == {"http://127.0.0.1/*", "http://localhost/*"}
    assert pol["DeveloperToolsAvailability"] == 2 and pol["DownloadRestrictions"] == 3 and pol["RemoteDebuggingAllowed"] is False
    assert pol["ExtensionInstallBlocklist"] == ["*"] and pol["SitePerProcess"] is True


def test_kiosk_unit_never_runs_as_root_and_script_has_no_unsafe_flags():
    from pathlib import Path
    root = Path(__file__).resolve().parents[2] / "image/overlay"
    unit = (root / "etc/systemd/system/pios-kiosk.service").read_text()
    assert "User=pios-kiosk" in unit and "NoNewPrivileges=yes" in unit and "CapabilityBoundingSet=" in unit
    code = "\n".join(l for l in (root / "opt/pios/bin/pios-kiosk-browser").read_text().splitlines() if not l.lstrip().startswith("#"))
    for flag in ("--no-sandbox", "--remote-debugging", "--disable-web-security", "--ignore-certificate-errors", "--disable-site-isolation", "--allow-running-insecure-content"):
        assert flag not in code
    assert "umask 077" in code
