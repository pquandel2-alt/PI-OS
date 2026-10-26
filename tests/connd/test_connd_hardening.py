"""Runs pios-connd under real systemd with exactly the sandbox of its unit file (transient unit) and checks that it still works:
capability set, D-Bus access to the system bus, hardware inventory, input diagnosis, rejection of malformed requests.
Needs root via sudo and systemd. First-run radio changes are disabled so the test never touches the host's Wi-Fi."""
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
UNIT = ROOT / "image/overlay/etc/systemd/system/pios-connd.service"
pytestmark = pytest.mark.skipif(not (shutil.which("systemd-run") and Path("/run/systemd/system").exists() and subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0
                                     and subprocess.run(["/usr/bin/python3", "-c", "import dbus, gi"], capture_output=True).returncode == 0),
                                reason="needs systemd, passwordless sudo and python3-dbus/python3-gi")
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
    code = ("import socket,sys,json;s=socket.socket(socket.AF_UNIX);s.settimeout(40);s.connect(sys.argv[1]);s.sendall((json.dumps({'method':sys.argv[2],'args':json.loads(sys.argv[3])})+'\\n').encode());print(s.makefile().readline())")
    r = subprocess.run(["sudo", "-n", "/usr/bin/python3", "-c", code, sock, method, json.dumps(args or {})], capture_output=True, text=True, timeout=60)
    return json.loads(r.stdout)


@pytest.fixture()
def helper():
    tag = uuid.uuid4().hex[:6]
    name = unit = f"pios-connd-test-{tag}"
    app = Path(f"/opt/{name}")
    sh("mkdir", "-p", str(app), f"/etc/{name}-modprobe"); sh("cp", "-r", str(ROOT / "pios_connd"), str(app))
    skip = {"User", "Group", "Environment", "ExecStart", "RuntimeDirectory", "StateDirectory", "RuntimeDirectoryMode", "StateDirectoryMode", "Restart", "RestartSec", "UMask", "ReadWritePaths"}
    args = ["systemd-run", f"--unit={unit}", "--quiet", "--collect", "-p", "User=root", "-p", "Group=adm", "-p", f"RuntimeDirectory={name}", "-p", f"StateDirectory={name}",
            "-p", "UMask=0077", "-p", f"ReadWritePaths=/etc/{name}-modprobe"]
    for k, v in props():
        if k not in skip:
            args += ["-p", f"{k}={v}"]
    args += ["-p", f"Environment=PYTHONPATH={app} PYTHONDONTWRITEBYTECODE=1 PIOS_CONND_SOCKET=/run/{name}/c.sock PIOS_CONND_STATE=/var/lib/{name} "
                   f"PIOS_REGDOM_CONF=/etc/{name}-modprobe/regdom.conf PIOS_CONND_FIRST_RUN=off",
             "/usr/bin/python3", "-m", "pios_connd.server"]
    assert sh(*args, check=False).returncode == 0
    sock = f"/run/{name}/c.sock"
    for _ in range(60):
        if sh("test", "-S", sock, check=False).returncode == 0:
            break
        time.sleep(0.2)
    else:
        log = sh("journalctl", "-u", unit, "-n", "40", "--no-pager", check=False).stdout
        cleanup(unit, app, name)
        pytest.fail("pios-connd did not start under its sandbox:\n" + log)
    yield type("H", (), {"sock": sock, "unit": unit})
    cleanup(unit, app, name)


def cleanup(unit, app, name):
    sh("systemctl", "stop", unit, check=False)
    sh("rm", "-rf", str(app), f"/etc/{name}-modprobe", f"/var/lib/{name}", f"/run/{name}", check=False)


def test_connd_works_inside_its_sandbox_with_only_the_declared_capabilities(helper):
    pid = sh("systemctl", "show", helper.unit, "-p", "MainPID", "--value").stdout.strip()
    status = sh("cat", f"/proc/{pid}/status").stdout
    eff = int(re.search(r"CapEff:\s*([0-9a-f]+)", status).group(1), 16)
    CAP_NET_ADMIN, CAP_DAC_READ_SEARCH, CAP_SYS_PTRACE = 12, 2, 19
    assert eff == (1 << CAP_NET_ADMIN) | (1 << CAP_DAC_READ_SEARCH) | (1 << CAP_SYS_PTRACE), hex(eff)
    assert re.search(r"NoNewPrivs:\s*1", status) and re.search(r"Seccomp:\s*2", status)
    inv = ask(helper.sock, "hw.inventory")
    assert inv["ok"] and "platform" in inv["result"] and "usb" in inv["result"], inv
    diag = ask(helper.sock, "hw.input_diag")
    assert diag["ok"] and diag["result"]["verdict"] and diag["result"]["stages"], diag
    s = ask(helper.sock, "net.summary")
    assert s["ok"] and "online" in s["result"], s                       # works with or without NetworkManager on the machine
    # malformed / hostile input is rejected without touching anything
    assert ask(helper.sock, "rm -rf /")["code"] == "bad_request"
    r = ask(helper.sock, "wifi.set_country", {"code": "00"})
    assert not r["ok"] and r["code"] in ("invalid_input", "bad_request")
    r = ask(helper.sock, "wifi.connect", {"ssid": "x\nlf", "psk": "short"})
    assert not r["ok"]
    assert sh("systemctl", "is-active", helper.unit).stdout.strip() == "active"
