import time

from pios import config


def test_setup_requires_code_remotely(client, code):
    assert client.get("/api/setup-status").json() == {"needs_setup": True, "needs_code": True}
    r = client.post("/api/setup", json={"username": "admin", "password": "a long enough pass", "setup_code": "WRONG"})
    assert r.status_code == 403
    r = client.post("/api/setup", json={"username": "admin", "password": "a long enough pass", "setup_code": code})
    assert r.status_code == 200
    assert not (config.DATA / "setup-code").exists()
    assert client.get("/api/setup-status").json()["needs_setup"] is False
    # second setup must fail
    r = client.post("/api/setup", json={"username": "evil", "password": "a long enough pass", "setup_code": code})
    assert r.status_code in (403, 409)


def test_setup_without_code_from_loopback(tmp_path, monkeypatch):
    import importlib, sys
    monkeypatch.setenv("PIOS_DATA", str(tmp_path / "d"))
    monkeypatch.setenv("PIOS_ALLOWED_HOSTS", "testserver")
    for m in [m for m in sys.modules if m == "pios" or m.startswith("pios.")]:
        del sys.modules[m]
    from fastapi.testclient import TestClient
    main = importlib.import_module("pios.main")
    with TestClient(main.app, client=("127.0.0.1", 1)) as c:
        c.headers.update({"X-PiOS": "1"})
        assert c.get("/api/setup-status").json()["needs_code"] is False
        assert c.post("/api/setup", json={"username": "local", "password": "a long enough pass"}).status_code == 200
        c.post("/api/login", json={"username": "local", "password": "a long enough pass"})
        assert c.get("/api/me").json()["kind"] == "local"


def test_weak_password_rejected(client, code):
    r = client.post("/api/setup", json={"username": "admin", "password": "short", "setup_code": code})
    assert r.status_code == 422


def test_unauthenticated_access_denied(client):
    for method, url in [("get", "/api/me"), ("get", "/api/system"), ("get", "/api/notes"), ("get", "/api/files"),
                        ("get", "/api/files/download?path=x"), ("get", "/api/apps"), ("get", "/api/prefs"),
                        ("get", "/api/desktop"), ("get", "/api/users"), ("get", "/api/events"),
                        ("get", "/api/sessions")]:
        assert getattr(client, method)(url).status_code == 401, url


def test_login_logout_cookie_flags(admin):
    r = admin.get("/api/me")
    assert r.json()["username"] == "admin" and r.json()["kind"] == "remote"
    assert admin.post("/api/logout").status_code == 200
    assert admin.get("/api/me").status_code == 401


def test_cookie_is_httponly_samesite(client, code):
    client.post("/api/setup", json={"username": "admin", "password": "a long enough pass", "setup_code": code})
    r = client.post("/api/login", json={"username": "admin", "password": "a long enough pass"})
    c = r.headers["set-cookie"].lower()
    assert "httponly" in c and "samesite=strict" in c


def test_bruteforce_lockout(client, code):
    client.post("/api/setup", json={"username": "admin", "password": "a long enough pass", "setup_code": code})
    for _ in range(5):
        assert client.post("/api/login", json={"username": "admin", "password": "wrong"}).status_code == 401
    r = client.post("/api/login", json={"username": "admin", "password": "a long enough pass"})
    assert r.status_code == 429 and "Retry-After" in r.headers


def test_csrf_header_required(admin):
    r = admin.post("/api/notes", json={"title": "x", "body": "y"}, headers={"X-PiOS": ""})
    assert r.status_code == 403
    r = admin.post("/api/notes", json={"title": "x", "body": "y"}, headers={"Origin": "http://evil.example"})
    assert r.status_code == 403


def test_change_password_revokes_other_sessions(admin, client):
    from fastapi.testclient import TestClient
    other = TestClient(client.app, client=("192.168.1.60", 1))
    other.headers.update({"X-PiOS": "1"})
    other.post("/api/login", json={"username": "admin", "password": "correct horse battery"})
    assert other.get("/api/me").status_code == 200
    assert admin.put("/api/me/password", json={"current": "nope", "new": "another long password"}).status_code == 403
    assert admin.put("/api/me/password", json={"current": "correct horse battery", "new": "another long password"}).status_code == 200
    assert other.get("/api/me").status_code == 401
    assert admin.get("/api/me").status_code == 200


def test_session_expiry(admin):
    from pios import db
    with db.connect() as c:
        c.execute("UPDATE sessions SET expires=?", (int(time.time()) - 1,))
    assert admin.get("/api/me").status_code == 401


def test_user_admin_and_isolation(admin, client):
    from fastapi.testclient import TestClient
    assert admin.post("/api/users", json={"username": "anna", "password": "anna-long-password"}).status_code == 200
    assert admin.post("/api/users", json={"username": "ANNA", "password": "anna-long-password"}).status_code == 409
    anna = TestClient(client.app, client=("192.168.1.70", 1))
    anna.headers.update({"X-PiOS": "1"})
    anna.post("/api/login", json={"username": "anna", "password": "anna-long-password"})
    assert anna.get("/api/users").status_code == 403
    admin.post("/api/notes", json={"title": "secret", "body": "admin only"})
    assert anna.get("/api/notes").json() == []
    admin.post("/api/files/mkdir", json={"path": "", "name": "private"})
    assert anna.get("/api/files").json()["entries"] == []
