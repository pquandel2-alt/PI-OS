import importlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PIOS_DATA", str(tmp_path / "data"))
    monkeypatch.setenv("PIOS_APPS", str(Path(__file__).resolve().parent.parent / "apps"))
    for m in [m for m in sys.modules if m == "pios" or m.startswith("pios.")]:
        del sys.modules[m]
    from fastapi.testclient import TestClient
    main = importlib.import_module("pios.main")
    with TestClient(main.app, base_url="http://testserver", client=("192.168.1.50", 5555)) as c:
        c.headers.update({"X-PiOS": "1"})
        yield c


@pytest.fixture()
def code(client):
    from pios import config
    return (config.DATA / "setup-code").read_text().strip()


@pytest.fixture()
def admin(client, code):
    r = client.post("/api/setup", json={"username": "admin", "password": "correct horse battery", "setup_code": code})
    assert r.status_code == 200, r.text
    r = client.post("/api/login", json={"username": "admin", "password": "correct horse battery"})
    assert r.status_code == 200
    return client
