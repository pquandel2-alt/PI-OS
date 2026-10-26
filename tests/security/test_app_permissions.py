"""App permission model: requested vs granted, revocation takes effect immediately, uninstall kills tokens."""
import pytest

from tests.conftest import register_app


def tok(c, app="hello"):
    return {"Authorization": "Bearer " + c.post(f"/api/apps/{app}/token").json()["token"]}


def overview(c, app):
    return next(a for a in c.get("/api/shield/apps").json()["apps"] if a["id"] == app)


def test_bundled_app_grants_are_recorded_with_origin(admin):
    a = overview(admin, "hello")
    assert a["origin"] == "bundled" and set(a["granted"]) == set(a["requested"]) and a["pending"] == []
    assert a["grants"]["storage"]["by"] == "system:bundled"
    assert "sandbox" in a["isolation"]


def test_revoking_a_permission_is_enforced_server_side_immediately(admin):
    h = tok(admin)
    assert admin.put("/api/sdk/storage/k", json={"value": 1}, headers=h).status_code == 200
    r = admin.put("/api/shield/apps/hello/grants", json={"permission": "storage", "allow": False})
    assert r.status_code == 200 and "storage" not in r.json()["app"]["granted"]
    # the SAME token (still validly signed, not expired) is now refused
    assert admin.put("/api/sdk/storage/k", json={"value": 1}, headers=h).status_code == 403
    assert admin.get("/api/sdk/storage/k", headers=h).status_code == 403
    # re-granting restores access without a new token
    admin.put("/api/shield/apps/hello/grants", json={"permission": "storage", "allow": True})
    assert admin.get("/api/sdk/storage/k", headers=h).status_code == 200


def test_cannot_grant_what_the_app_did_not_request(admin):
    assert admin.put("/api/shield/apps/hello/grants", json={"permission": "files.write", "allow": True}).status_code == 400
    assert admin.put("/api/shield/apps/files/grants", json={"permission": "files.read", "allow": True}).status_code == 404


def test_new_permission_in_app_update_is_not_auto_granted(admin):
    from pios import apps
    register_app(admin, "grower", ["storage"])
    m = apps.registry.apps["grower"]
    apps.registry.apps["grower"] = apps.Manifest(id="grower", name="Grower", version="2.0.0", permissions=["storage", "files.write"])
    apps.sync_app_state()
    a = overview(admin, "grower")
    assert a["version"] == "2.0.0" and a["pending"] == ["files.write"] and "files.write" not in a["granted"]
    h = tok(admin, "grower")
    assert admin.put("/api/sdk/files/content", params={"path": "x.txt"}, content=b"x", headers=h).status_code == 403
    admin.put("/api/shield/apps/grower/grants", json={"permission": "files.write", "allow": True})
    h = tok(admin, "grower")
    assert admin.put("/api/sdk/files/content", params={"path": "x.txt"}, content=b"x", headers=h).status_code == 200


def test_uninstalling_an_app_invalidates_its_tokens(admin):
    from pios import apps
    h = register_app(admin, "ephemeral", ["storage"])
    assert admin.put("/api/sdk/storage/k", json={"value": 1}, headers=h).status_code == 200
    del apps.registry.apps["ephemeral"]
    apps.sync_app_state()
    assert admin.get("/api/sdk/storage/k", headers=h).status_code == 401
    assert not apps.granted("ephemeral")


def test_denied_attempts_are_audited_once_per_minute(admin):
    from pios import audit
    h = tok(admin)
    for _ in range(5):
        admin.get("/api/sdk/files", headers=h)
    denied = [e for e in audit.recent(100, kind="app.denied") if e["actor"] == "app:hello"]
    assert len(denied) == 1


def test_forged_and_foreign_tokens_rejected(admin, client):
    from pios import security
    forged = {"Authorization": "Bearer " + security.issue_app_token("hello", 1, ["files.write"], sid="a" * 32)}
    assert admin.get("/api/sdk/files", headers=forged).status_code == 401           # session id does not exist
    h = tok(admin)
    body, sig = h["Authorization"][7:].rsplit(".", 1)
    assert admin.get("/api/sdk/storage/k", headers={"Authorization": f"Bearer {body}.{'0' * len(sig)}"}).status_code == 401
    assert admin.get("/api/sdk/storage/k", headers={"Authorization": "Bearer "}).status_code == 401
    assert admin.get("/api/sdk/storage/k", headers={"Authorization": "Basic abc"}).status_code == 401


def test_token_cannot_be_used_for_another_apps_namespace(admin):
    a = register_app(admin, "app-a", ["storage"]); b = register_app(admin, "app-b", ["storage"])
    admin.put("/api/sdk/storage/secret", json={"value": "A-only"}, headers=a)
    assert admin.get("/api/sdk/storage/secret", headers=b).json() == {"value": None}


def test_non_admin_cannot_change_grants(admin, client):
    from fastapi.testclient import TestClient
    admin.post("/api/users", json={"username": "anna", "password": "anna-long-password"})
    anna = TestClient(client.app, client=("192.168.1.8", 1)); anna.headers.update({"X-PiOS": "1"})
    anna.post("/api/login", json={"username": "anna", "password": "anna-long-password"})
    assert anna.put("/api/shield/apps/hello/grants", json={"permission": "storage", "allow": False}).status_code == 403
    assert anna.get("/api/shield/apps").status_code == 403
