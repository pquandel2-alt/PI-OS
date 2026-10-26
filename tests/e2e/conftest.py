import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def server(tmp_path_factory):
    pytest.importorskip("playwright")
    data = tmp_path_factory.mktemp("pios-data")
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    from tests.shield.fake_clamd import FakeClamd
    clam = FakeClamd(data.parent / "clamd.sock")          # speaks the real clamd protocol (incl. FILDES descriptor passing)
    env = {**os.environ, "PIOS_DATA": str(data), "PIOS_CLAMD_SOCKET": clam.path}
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "pios.main:app", "--host", "127.0.0.1", "--port", str(port)],
                            cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    url = f"http://127.0.0.1:{port}"
    for _ in range(60):
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close(); break
        except OSError:
            time.sleep(0.2)
    yield url
    proc.terminate(); proc.wait(5); clam.stop()


@pytest.fixture(scope="session")
def browser():
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


@pytest.fixture()
def page(browser, server):
    ctx = browser.new_context(viewport={"width": 1280, "height": 800})
    pg = ctx.new_page()
    pg.errors = []
    pg.on("pageerror", lambda e: pg.errors.append(str(e)))
    pg.on("console", lambda m: m.type == "error" and pg.errors.append(m.text))
    yield pg
    ctx.close()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    pg = item.funcargs.get("page") if hasattr(item, "funcargs") else None
    if rep.when == "call" and rep.failed and pg is not None:
        shots = Path(__file__).parent / "screens"
        shots.mkdir(exist_ok=True)
        try:
            pg.screenshot(path=str(shots / f"FAIL-{item.name}.png"))
        except Exception:
            pass
