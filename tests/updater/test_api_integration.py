"""Backend API <-> unix socket <-> real Update Manager <-> mock GitHub (no hardware needed)."""
import json
import os
import threading
import time

import pytest

from pios_updater.server import Server


@pytest.fixture()
def stack(system, client, code, tmp_path, monkeypatch):
    sock = tmp_path / "updater.sock"
    monkeypatch.setenv("PIOS_UPDATER_SOCKET", str(sock))
    system.u.async_jobs = True
    srv = Server(sock, system.u, {os.getuid()})
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    r = client.post("/api/setup", json={"username": "admin", "password": "correct horse battery", "setup_code": code})
    assert r.status_code == 200
    client.post("/api/login", json={"username": "admin", "password": "correct horse battery"})
    system.srv, system.client = srv, client
    yield system
    srv.shutdown(); srv.server_close()


def wait_job(client, states=("success", "rolled_back", "failed", "failed_critical"), timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        j = client.get("/api/updates").json()["job"]
        if j and j["state"] in states:
            return j
        time.sleep(0.1)
    raise AssertionError("job did not finish")


def test_requires_admin_and_login(stack, client):
    from fastapi.testclient import TestClient
    anon = TestClient(client.app, client=("192.168.1.9", 1)); anon.headers.update({"X-PiOS": "1"})
    for m, u in (("get", "/api/updates"), ("post", "/api/updates/check"), ("post", "/api/updates/install"), ("get", "/api/updates/stream"),
                 ("post", "/api/updates/rollback"), ("put", "/api/updates/config")):
        assert getattr(anon, m)(u).status_code == 401, u
    client.post("/api/users", json={"username": "anna", "password": "anna-long-password"})
    anna = TestClient(client.app, client=("192.168.1.8", 1)); anna.headers.update({"X-PiOS": "1"})
    anna.post("/api/login", json={"username": "anna", "password": "anna-long-password"})
    for m, u, body in (("get", "/api/updates", None), ("post", "/api/updates/check", None), ("post", "/api/updates/install", {"version": "0.2.0"}),
                       ("post", "/api/updates/rollback", {}), ("put", "/api/updates/config", {"channel": "beta"}), ("get", "/api/updates/stream", None)):
        r = getattr(anna, m)(u, **({"json": body} if body is not None else {}))
        assert r.status_code == 403, (u, r.status_code)
    assert stack.u.installed()["version"] == "0.1.0"


def test_update_flow_through_the_api(stack, client):
    stack.publish("0.2.0", notes="- Neu")
    assert client.get("/api/updates").json()["installed"]["version"] == "0.1.0"
    st = client.post("/api/updates/check").json()
    assert st["available"]["version"] == "0.2.0"
    assert client.post("/api/updates/install", json={"version": "0.2.0"}).status_code == 200
    job = wait_job(client)
    assert job["state"] == "success"
    assert client.get("/api/updates").json()["installed"]["version"] == "0.2.0"
    # notifications reach the admin
    from pios import updates
    updates.notify_once(client.get("/api/updates").json())
    titles = [e["title"] for e in client.get("/api/events").json()["events"]]
    assert "Update installiert" in titles
    updates.notify_once(client.get("/api/updates").json())
    assert [e["title"] for e in client.get("/api/events").json()["events"]].count("Update installiert") == 1, "only once"


def test_new_version_notification(stack, client):
    from pios import updates
    stack.publish("0.2.0"); client.post("/api/updates/check")
    updates.notify_once(client.get("/api/updates").json())
    assert any("0.2.0 verfügbar" in e["title"] for e in client.get("/api/events").json()["events"])


def test_errors_map_to_http_codes(stack, client):
    assert client.post("/api/updates/install", json={"version": "9.9.9"}).status_code == 404
    stack.publish("0.5.0", min_version="0.4.0"); client.post("/api/updates/check")
    assert client.post("/api/updates/install", json={"version": "0.5.0"}).status_code == 409
    assert client.post("/api/updates/rollback", json={}).status_code == 404
    assert client.put("/api/updates/config", json={"channel": "nightly"}).status_code == 422
    assert client.put("/api/updates/config", json={"channel": "beta"}).json()["channel"] == "beta"


def test_concurrent_install_requests_via_api(stack, client):
    stack.publish("0.2.0"); client.post("/api/updates/check")
    gate = threading.Event(); orig = stack.env.restart_backend
    stack.env.restart_backend = lambda: (gate.wait(10), orig())[1]
    assert client.post("/api/updates/install", json={"version": "0.2.0"}).status_code == 200
    assert client.post("/api/updates/install", json={"version": "0.2.0"}).status_code == 409
    gate.set(); assert wait_job(client)["state"] == "success"


def test_failed_update_via_api_rolls_back_and_reports(stack, client):
    stack.publish("0.2.0"); stack.env.crash_versions.add("0.2.0"); client.post("/api/updates/check")
    client.post("/api/updates/install", json={"version": "0.2.0"})
    job = wait_job(client)
    assert job["state"] == "rolled_back" and job["error"]
    assert client.get("/api/updates").json()["installed"]["version"] == "0.1.0"


def test_socket_refuses_foreign_uid(stack, client, tmp_path):
    stack.srv.allowed_uids = {123456}
    r = client.get("/api/updates")
    assert r.status_code == 502


def test_updater_down_gives_clean_503_and_app_still_works(stack, client):
    stack.srv.shutdown(); stack.srv.server_close()
    assert client.get("/api/updates").status_code == 503
    assert client.get("/api/system").status_code == 200


def test_sse_stream_pushes_status(stack, client):
    with client.stream("GET", "/api/updates/stream?once=true") as r:
        assert r.headers["content-type"].startswith("text/event-stream")
        got = None
        for line in r.iter_lines():
            if line.startswith("data:"):
                got = json.loads(line[5:]); break
    assert got["installed"]["version"] == "0.1.0"
