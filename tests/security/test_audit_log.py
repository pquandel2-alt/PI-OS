import json
import sqlite3

import pytest

import importlib


class _Lazy:
    """The app modules are re-imported per test (fresh DATA dir); resolve them at use time, not at import time."""
    def __init__(self, name): self._n = name
    def __getattr__(self, a): return getattr(importlib.import_module(self._n), a)


audit, db = _Lazy("pios.audit"), _Lazy("pios.db")


def rows(kind=None):
    return audit.recent(1000, kind=kind)


def test_events_are_recorded_for_auth_flow(client, code):
    client.post("/api/setup", json={"username": "admin", "password": "correct horse battery", "setup_code": "WRONGCODE"})
    client.post("/api/setup", json={"username": "admin", "password": "correct horse battery", "setup_code": code})
    client.post("/api/login", json={"username": "admin", "password": "nope-nope-nope"})
    client.post("/api/login", json={"username": "admin", "password": "correct horse battery"})
    kinds = [r["kind"] for r in rows()]
    for k in ("auth.setup_code_rejected", "auth.setup_complete", "auth.login_failed", "auth.login"):
        assert k in kinds, k
    assert audit.verify()["ok"]


def test_lockout_and_password_change_and_user_admin_audited(admin):
    admin.put("/api/me/password", json={"current": "wrong", "new": "another long password!"})
    admin.put("/api/me/password", json={"current": "correct horse battery", "new": "another long password!"})
    admin.post("/api/users", json={"username": "anna", "password": "anna-long-password"})
    kinds = [r["kind"] for r in rows()]
    assert {"auth.password_change_failed", "auth.password_changed", "user.created"} <= set(kinds)


def test_no_secrets_in_audit_log(client, code):
    pw = "correct horse battery"
    client.post("/api/setup", json={"username": "admin", "password": pw, "setup_code": code})
    r = client.post("/api/login", json={"username": "admin", "password": pw})
    cookie = r.cookies.get("pios_session")
    dump = json.dumps(rows()) + json.dumps([list(map(str, x)) for x in sqlite3.connect(db.config.DATA / "pios.db").execute("select * from audit").fetchall()])
    for secret in (pw, cookie, code):
        assert secret not in dump
    audit.event("x.test", "info", password="hunter2", token="abc", session_cookie="zzz", note="ok")
    last = rows("x.test")[0]["detail"]
    assert last == {"note": "ok"}


def test_hash_chain_detects_edit_and_deletion(client):
    for i in range(5):
        audit.event("t.event", "info", n=i)
    assert audit.verify()["ok"]
    path = db.config.DATA / "pios.db"
    c = sqlite3.connect(path); ids = [r[0] for r in c.execute("select id from audit order by id")]
    c.execute("update audit set detail='{\"n\": 99}' where id=?", (ids[2],)); c.commit()
    v = audit.verify()
    assert not v["ok"] and v["first_bad_id"] == ids[2]
    c.execute("update audit set detail='{\"n\": 2}' where id=?", (ids[2],))
    c.execute("delete from audit where id=?", (ids[3],)); c.commit(); c.close()
    v = audit.verify()
    assert not v["ok"] and v["first_bad_id"] == ids[4]


def test_retention_caps_rows_and_keeps_chain_valid(client, monkeypatch):
    monkeypatch.setattr("pios.audit.MAX_ROWS", 50); monkeypatch.setattr("pios.audit.KEEP_ROWS", 40)
    for i in range(60):
        audit.event("t.fill", "info", n=i)
        importlib.import_module("pios.audit")._last_prune = 0
    n = sqlite3.connect(db.config.DATA / "pios.db").execute("select count(*) from audit").fetchone()[0]
    assert n <= 50
    assert audit.verify()["ok"], "anchor keeps the chain verifiable after old rows are dropped"


def test_users_cannot_read_modify_or_delete_the_log(admin, client):
    from fastapi.testclient import TestClient
    admin.post("/api/users", json={"username": "anna", "password": "anna-long-password"})
    anna = TestClient(client.app, client=("192.168.1.8", 1)); anna.headers.update({"X-PiOS": "1"})
    anna.post("/api/login", json={"username": "anna", "password": "anna-long-password"})
    assert anna.get("/api/shield/audit").status_code == 403
    for m in ("put", "delete", "post", "patch"):
        r = getattr(admin, m)("/api/shield/audit")
        assert r.status_code in (404, 405), m          # not even an admin can alter entries through the API
