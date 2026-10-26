"""End-to-end against a REAL clamd (set PIOS_REAL_CLAMD=/path/to/clamd.ctl; signatures must be loaded). Skipped otherwise.
CI: `apt install clamav-daemon; freshclam; clamd` and export the variable; locally: see docs/SHIELD.md (docker recipe)."""
import os
import time

import pytest

from tests.shield.fake_clamd import EICAR

SOCK = os.getenv("PIOS_REAL_CLAMD", "")
pytestmark = pytest.mark.skipif(not SOCK or not os.path.exists(SOCK), reason="PIOS_REAL_CLAMD not set")


@pytest.fixture()
def real(admin, monkeypatch):
    monkeypatch.delenv("PIOS_MALWARE", raising=False)
    monkeypatch.setenv("PIOS_CLAMD_SOCKET", SOCK)
    from pios import malware
    assert malware.Clamd().ping(), "clamd must be running"
    return admin


def test_real_clamd_detects_eicar_and_releases_clean_files(real):
    c = real
    ok = c.post("/api/files/upload", files={"file": ("readme.txt", b"just text\n" * 100)}).json()
    assert ok["status"] == "released"
    bad = c.post("/api/files/upload", files={"file": ("invoice.pdf", EICAR)}).json()
    assert bad["status"] == "infected" and "Eicar" in bad["detection"], bad
    assert [e["name"] for e in c.get("/api/files").json()["entries"]] == ["readme.txt"]
    q = c.get("/api/shield/quarantine").json()
    assert q[0]["state"] == "infected" and q[0]["detection"].startswith("Eicar")


def test_real_clamd_eicar_inside_zip_and_gzip(real):
    import gzip, io, zipfile
    z = io.BytesIO()
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("harmless/readme.txt", "hi"); f.writestr("sub/eicar.com", EICAR)
    assert real.post("/api/files/upload", files={"file": ("archive.zip", z.getvalue())}).json()["status"] == "infected"
    assert real.post("/api/files/upload", files={"file": ("x.gz", gzip.compress(EICAR))}).json()["status"] == "infected"


def test_real_clamd_scan_job_over_existing_files(real):
    from pios import malware, vfs
    root = vfs.user_root(1)
    (root / "a.txt").write_text("fine"); (root / "bad.exe").write_bytes(EICAR)
    jid = malware.start_scan("manual", throttle=0)
    while malware.scan_job_running():
        time.sleep(0.2)
    s = real.get("/api/shield/scans").json()["scans"][0]
    assert s["state"] == "done" and s["infected"] == 1 and (root / "a.txt").exists() and not (root / "bad.exe").exists()
