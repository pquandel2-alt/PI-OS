import json
import pytest


def tok(c, app):
    return {"Authorization": "Bearer " + c.post(f"/api/apps/{app}/token").json()["token"]}


def test_registry_lists_system_and_bundled(admin):
    d = admin.get("/api/apps").json()
    ids = {a["id"] for a in d["apps"]}
    assert {"files", "notes", "monitor", "settings", "hello"} <= ids
    assert d["api"] == 1 and d["errors"] == {}


def test_system_apps_have_no_token(admin):
    assert admin.post("/api/apps/files/token").status_code == 404


def test_token_required_and_forged_rejected(admin):
    assert admin.get("/api/sdk/system").status_code == 401
    assert admin.get("/api/sdk/system", headers={"Authorization": "Bearer abc.def"}).status_code == 401
    t = tok(admin, "hello")["Authorization"]
    forged = t[:-3] + "000"
    assert admin.get("/api/sdk/system", headers={"Authorization": forged}).status_code == 401


def test_permissions_enforced_server_side(admin):
    h = tok(admin, "hello")
    m = json.loads(open("apps/hello/manifest.json").read())
    assert "storage" in m["permissions"] and "files.read" not in m["permissions"]
    assert admin.put("/api/sdk/storage/k", json={"value": {"a": 1}}, headers=h).status_code == 200
    assert admin.get("/api/sdk/storage/k", headers=h).json() == {"value": {"a": 1}}
    # not requested in manifest -> denied by the server, regardless of what the iframe claims
    assert admin.get("/api/sdk/files/content", params={"path": "x"}, headers=h).status_code in (403,)
    assert admin.get("/api/sdk/files", headers=h).status_code == 403


def test_app_file_scope(admin, tmp_path):
    from pios import security, vfs
    t = security.issue_app_token("demo", 1, ["files.app"])
    h = {"Authorization": "Bearer " + t}
    assert admin.put("/api/sdk/files/content", params={"path": "a.txt"}, content=b"data", headers=h).status_code == 200
    assert admin.get("/api/sdk/files/content", params={"path": "a.txt"}, headers=h).content == b"data"
    assert admin.get("/api/sdk/files/content", params={"path": "../../x"}, headers=h).status_code in (400, 404)
    assert (vfs.user_root(1) / "Apps" / "demo" / "a.txt").exists()
    # scoped token cannot see the rest of the user's files
    assert [e["name"] for e in admin.get("/api/sdk/files", headers=h).json()["entries"]] == ["a.txt"]


def test_storage_isolated_per_app(admin):
    from pios import security
    a = {"Authorization": "Bearer " + security.issue_app_token("app-a", 1, ["storage"])}
    b = {"Authorization": "Bearer " + security.issue_app_token("app-b", 1, ["storage"])}
    admin.put("/api/sdk/storage/k", json={"value": 1}, headers=a)
    assert admin.get("/api/sdk/storage/k", headers=b).json() == {"value": None}


def test_storage_quota(admin):
    h = tok(admin, "hello")
    big = "x" * 200_000
    codes = [admin.put(f"/api/sdk/storage/k{i}", json={"value": big}, headers=h).status_code for i in range(25)]
    assert 200 in codes and 413 in codes


def test_notifications_reach_event_log(admin):
    from pios import security
    h = {"Authorization": "Bearer " + security.issue_app_token("hello", 1, ["notifications"])}
    assert admin.post("/api/sdk/notifications", json={"title": "Hi"}, headers=h).status_code == 200
    ev = admin.get("/api/events").json()["events"]
    assert ev[-1]["title"] == "Hi" and ev[-1]["app"] == "hello"


def test_app_assets_sandboxed_headers(admin, client):
    from fastapi.testclient import TestClient
    anon = TestClient(client.app)
    r = anon.get("/apps/hello/index.html")  # public: opaque-origin iframes carry no cookies
    assert r.status_code == 200
    csp = r.headers["content-security-policy"]
    assert "sandbox allow-scripts" in csp and "connect-src 'none'" in csp
    assert anon.get("/apps/hello/../../pios/main.py").status_code in (400, 404)
    assert anon.get("/apps/files/index.html").status_code == 404


def test_bad_manifests_are_skipped(tmp_path):
    from pios.apps import Registry
    (tmp_path / "bad").mkdir()
    (tmp_path / "bad" / "manifest.json").write_text(json.dumps({"id": "bad", "name": "B", "version": "1.0.0", "permissions": ["root"]}))
    (tmp_path / "future").mkdir()
    (tmp_path / "future" / "manifest.json").write_text(json.dumps({"id": "future", "name": "F", "version": "1.0.0", "api": 99}))
    (tmp_path / "evil").mkdir()
    (tmp_path / "evil" / "manifest.json").write_text(json.dumps({"id": "evil", "name": "E", "version": "1.0.0", "kind": "system"}))
    r = Registry(tmp_path)
    assert set(r.errors) == {"bad", "future", "evil"}
    assert "bad" not in r.apps


def test_sdk_needs_no_csrf_header_but_cookie_api_does(admin):
    from pios import security
    h = {"Authorization": "Bearer " + security.issue_app_token("hello", 1, ["storage"]), "X-PiOS": ""}
    assert admin.put("/api/sdk/storage/k", json={"value": 1}, headers=h).status_code == 200
    # a cookie alone is not accepted by the SDK API
    assert admin.put("/api/sdk/storage/k", json={"value": 1}, headers={"X-PiOS": ""}).status_code == 401
