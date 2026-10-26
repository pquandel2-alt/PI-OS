"""Regression tests for the findings of the NOVA Shield security audit (docs/SECURITY_AUDIT.md).
Each test demonstrates an attack and asserts the secure behaviour."""
import time

import pytest


# F-01 DNS rebinding / Host header injection
@pytest.mark.parametrize("host", ["evil.example", "pios.local.evil.example", "attacker.com:80", ""])
def test_f01_unknown_host_header_rejected(client, host):
    r = client.get("/healthz", headers={"Host": host})
    assert r.status_code in (400, 421), host


@pytest.mark.parametrize("host", ["pios.local", "192.168.1.20", "192.168.1.20:80", "[fe80::1]", "localhost", "127.0.0.1:8080", "testserver"])
def test_f01_legit_hosts_accepted(client, host):
    assert client.get("/healthz", headers={"Host": host}).status_code == 200


# F-02 unbounded request bodies (memory/disk exhaustion before authentication)
def test_f02_oversized_json_body_rejected_before_parsing(client):
    r = client.post("/api/login", content=b'{"username":"' + b"a" * (3 * 1024 * 1024) + b'"}', headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_f02_oversized_upload_rejected_by_content_length(admin, monkeypatch):
    from pios import config
    monkeypatch.setattr(config, "MAX_UPLOAD", 1024 * 1024)
    r = admin.post("/api/files/upload", files={"file": ("big.bin", b"x" * (3 * 1024 * 1024))})
    assert r.status_code == 413
    assert admin.get("/api/files").json()["entries"] == []


def test_f02_chunked_body_without_content_length_is_still_limited(client):
    def gen():
        for _ in range(40):
            yield b"x" * 100_000
    r = client.post("/api/login", content=gen(), headers={"Content-Type": "application/json"})
    assert r.status_code == 413


# F-03 capability tokens outlive the session / permission
def _app_token(c, app="hello"):
    return {"Authorization": "Bearer " + c.post(f"/api/apps/{app}/token").json()["token"]}


def test_f03_token_dies_with_logout(admin):
    h = _app_token(admin)
    assert admin.get("/api/sdk/storage/k", headers=h).status_code == 200
    admin.post("/api/logout")
    assert admin.get("/api/sdk/storage/k", headers=h).status_code == 401


def test_f03_token_dies_when_session_revoked_elsewhere(admin, client):
    from fastapi.testclient import TestClient
    other = TestClient(client.app, client=("192.168.1.9", 1)); other.headers.update({"X-PiOS": "1"})
    other.post("/api/login", json={"username": "admin", "password": "correct horse battery"})
    h = _app_token(other)
    sid = [s for s in admin.get("/api/sessions").json() if not s["current"]][0]["id"]
    admin.delete(f"/api/sessions/{sid}")
    assert other.get("/api/sdk/storage/k", headers=h).status_code == 401


def test_f03_token_dies_on_password_change(admin, client):
    from fastapi.testclient import TestClient
    other = TestClient(client.app, client=("192.168.1.9", 1)); other.headers.update({"X-PiOS": "1"})
    other.post("/api/login", json={"username": "admin", "password": "correct horse battery"})
    h = _app_token(other)
    admin.put("/api/me/password", json={"current": "correct horse battery", "new": "another long password!"})
    assert other.get("/api/sdk/storage/k", headers=h).status_code == 401


# F-04 no idle timeout
def test_f04_idle_session_expires(admin):
    from pios import db
    with db.connect() as c:
        c.execute("UPDATE sessions SET last_seen=?", (int(time.time()) - 13 * 3600,))
    assert admin.get("/api/me").status_code == 401


def test_f04_active_session_survives(admin):
    from pios import db
    with db.connect() as c:
        c.execute("UPDATE sessions SET last_seen=?", (int(time.time()) - 3600,))
    assert admin.get("/api/me").status_code == 200


# F-05 filename spoofing with bidi/zero-width characters
@pytest.mark.parametrize("name", ["rechnung‮fdp.exe", "a​b.txt", "x⁦y", "evil﻿.txt"])
def test_f05_bidi_and_invisible_characters_in_names_rejected(admin, name):
    assert admin.post("/api/files/mkdir", json={"path": "", "name": name}).status_code == 400
    assert admin.post("/api/files/upload", files={"file": (name, b"x")}).status_code == 400


# F-06 information leaks / missing hardening headers
def test_f06_unauthenticated_requests_get_no_validation_details(client):
    r = client.post("/api/notes", json={"title": 123})
    assert r.status_code == 401 and "loc" not in r.text and "input" not in r.text


def test_f06_security_headers_present(client):
    for url in ("/", "/healthz", "/api/setup-status"):
        h = client.get(url).headers
        assert h["cross-origin-opener-policy"] == "same-origin", url
        assert h["cross-origin-resource-policy"] == "same-origin", url
        assert "camera=()" in h["permissions-policy"], url
        assert h["x-content-type-options"] == "nosniff"


def test_f06_api_errors_are_not_cacheable_and_have_no_server_banner(client):
    r = client.get("/api/me")
    assert r.headers["cache-control"] == "no-store"
    assert "server" not in {k.lower() for k in r.headers} or "uvicorn" not in r.headers.get("server", "").lower()


# F-07 manipulated/forged session cookies
@pytest.mark.parametrize("cookie", ["", "x", "A" * 5000, "../../etc/passwd", "' OR 1=1 --", "\x00"])
def test_f07_forged_session_cookies_rejected(client, cookie):
    r = client.get("/api/me", headers={"Cookie": f"pios_session={cookie}"} if cookie.isprintable() else {})
    assert r.status_code == 401


# F-08 per-user disk quota (a user must not be able to fill the device)
def test_f08_user_quota_enforced(admin, monkeypatch):
    from pios import config
    monkeypatch.setattr(config, "USER_QUOTA", 10)
    assert admin.post("/api/files/upload", files={"file": ("a.bin", b"12345")}).status_code == 200
    assert admin.post("/api/files/upload", files={"file": ("b.bin", b"123456789")}).status_code == 507
