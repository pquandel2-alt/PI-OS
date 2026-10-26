"""Runs pios-sysops under real systemd with the sandbox of its unit file (no capabilities at all) and proves it can still ask systemd
to start a whitelisted unit. Uses a transient dummy unit named like the real one. Needs root via sudo and systemd."""
import json
import re
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
UNIT = ROOT / "image/overlay/etc/systemd/system/pios-sysops.service"
pytestmark = pytest.mark.skipif(not (shutil.which("systemd-run") and Path("/run/systemd/system").exists() and subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0),
                                reason="needs systemd and passwordless sudo")
sh = lambda *a, check=True: subprocess.run(["sudo", "-n", *a], capture_output=True, text=True, check=check)


def props():
    sec, out = None, []
    for line in UNIT.read_text().splitlines():
        if line.startswith("["):
            sec = line.strip("[]")
        elif sec == "Service" and "=" in line and not line.startswith("#"):
            out.append(tuple(line.split("=", 1)))
    return out


def ask(sock, method, args=None):
    code = ("import socket,sys,json;s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);s.sendall((json.dumps({'method':sys.argv[2],'args':json.loads(sys.argv[3])})+'\\n').encode());print(s.makefile().readline())")
    r = subprocess.run(["sudo", "-n", sys.executable, "-c", code, sock, method, json.dumps(args or {})], capture_output=True, text=True, timeout=30)
    return json.loads(r.stdout)


@pytest.fixture()
def helper():
    tag = uuid.uuid4().hex[:6]
    name, unit = f"pios-sysops-test-{tag}", f"pios-sysops-test-{tag}"
    app = Path(f"/opt/{name}")
    sh("mkdir", "-p", str(app), f"/etc/pios-test-{tag}"); sh("cp", "-r", str(ROOT / "pios_sysops"), str(app))
    # a harmless stand-in for the real unit (runtime unit dir, removed afterwards)
    dummy = Path("/run/systemd/system/pios-os-check.service")
    if dummy.exists():
        pytest.skip("a real pios-os-check.service exists on this machine")
    sh("sh", "-c", f"printf '[Service]\\nType=oneshot\\nExecStart=/bin/true\\n' > {dummy}"); sh("systemctl", "daemon-reload")
    skip = {"User", "Group", "Environment", "ExecStart", "RuntimeDirectory", "StateDirectory", "RuntimeDirectoryMode", "StateDirectoryMode", "Restart", "RestartSec", "UMask", "ReadWritePaths"}
    args = ["systemd-run", f"--unit={unit}", "--quiet", "--collect", "-p", "User=root", "-p", "Group=adm", "-p", f"RuntimeDirectory={name}", "-p", f"StateDirectory={name}",
            "-p", "UMask=0022", "-p", f"ReadWritePaths=/etc/pios-test-{tag}"]
    for k, v in props():
        if k not in skip:
            args += ["-p", f"{k}={v}"]
    args += ["-p", f"Environment=PYTHONPATH={app} PYTHONDONTWRITEBYTECODE=1 PIOS_SYSOPS_SOCKET=/run/{name}/s.sock PIOS_SYSOPS_STATE=/var/lib/{name} PIOS_OS_CONF=/etc/pios-test-{tag}/os.conf",
             "/usr/bin/python3", "-m", "pios_sysops.server"]
    assert sh(*args, check=False).returncode == 0
    sock = f"/run/{name}/s.sock"
    for _ in range(50):
        if sh("test", "-S", sock, check=False).returncode == 0:
            break
        time.sleep(0.2)
    else:
        log = sh("journalctl", "-u", unit, "-n", "30", "--no-pager", check=False).stdout
        cleanup(unit, app, tag, name)
        pytest.fail("helper did not start:\n" + log)
    yield type("H", (), {"sock": sock, "unit": unit})
    cleanup(unit, app, tag, name)


def cleanup(unit, app, tag, name):
    sh("systemctl", "stop", unit, check=False)
    sh("rm", "-rf", str(app), f"/etc/pios-test-{tag}", "/run/systemd/system/pios-os-check.service", f"/var/lib/{name}", f"/run/{name}", check=False)
    sh("systemctl", "daemon-reload", check=False)


def test_helper_starts_a_whitelisted_unit_without_any_capability(helper):
    pid = sh("systemctl", "show", helper.unit, "-p", "MainPID", "--value").stdout.strip()
    status = sh("cat", f"/proc/{pid}/status").stdout
    assert int(re.search(r"CapEff:\s*([0-9a-f]+)", status).group(1), 16) == 0, "no capabilities"
    assert ask(helper.sock, "ping")["ok"]
    r = ask(helper.sock, "os.check")
    assert r["ok"], r
    for _ in range(30):
        if sh("systemctl", "show", "pios-os-check.service", "-p", "Result", "--value").stdout.strip() == "success":
            break
        time.sleep(0.2)
    else:
        pytest.fail("systemd never ran the unit: " + sh("journalctl", "-u", helper.unit, "-n", "20", "--no-pager", check=False).stdout)
    st = ask(helper.sock, "os.status")
    assert st["ok"] and st["result"]["auto_security"] is True and st["result"]["status"] == {}
    assert ask(helper.sock, "rm -rf /")["code"] == "bad_request"
