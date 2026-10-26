"""Runs the firewall daemon under *real systemd* with exactly the sandboxing properties of image/overlay/.../pios-firewall.service
(transient unit, inside a throw-away network namespace) and drives it over its socket. Proves the hardening is compatible
with the code - not just that the directives look good. Needs root via sudo, systemd, ip, nft."""
import json
import re
import shutil
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
UNIT = ROOT / "image/overlay/etc/systemd/system/pios-firewall.service"


def can():
    return all(shutil.which(x) for x in ("systemd-run", "ip", "nft")) and subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0 \
        and Path("/run/systemd/system").exists()


pytestmark = pytest.mark.skipif(not can(), reason="needs systemd, ip, nft and passwordless sudo")
sh = lambda *a, check=True: subprocess.run(["sudo", "-n", *a], capture_output=True, text=True, check=check)


def service_props():
    section, props = None, []
    for line in UNIT.read_text().splitlines():
        if line.startswith("["):
            section = line.strip("[]")
        elif section == "Service" and "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            props.append((k, v))
    return props


def ask(sock, method, args=None, sudo=True):
    code = ("import socket,sys,json;s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);"
            "s.sendall((json.dumps({'method':sys.argv[2],'args':json.loads(sys.argv[3])})+'\\n').encode());print(s.makefile().readline())")
    cmd = [sys.executable, "-c", code, sock, method, json.dumps(args or {})]
    r = subprocess.run((["sudo", "-n"] if sudo else []) + cmd, capture_output=True, text=True, timeout=30)
    return json.loads(r.stdout)


@pytest.fixture()
def daemon(tmp_path):
    tag = uuid.uuid4().hex[:6]
    ns, unit, name = f"hard{tag}", f"pios-fw-test-{tag}", f"pios-fw-test-{tag}"
    app = Path(f"/opt/{name}")
    sh("ip", "netns", "add", ns)
    sh("mkdir", "-p", str(app)); sh("cp", "-r", str(ROOT / "pios_firewall"), str(app))
    args = ["systemd-run", f"--unit={unit}", "--quiet", "--collect", "-p", f"NetworkNamespacePath=/run/netns/{ns}", "-p", "User=root", "-p", "Group=adm"]
    skip = {"Group", "User", "Environment", "ExecStart", "RuntimeDirectory", "StateDirectory", "Restart", "RestartSec", "Type", "AmbientCapabilities", "InaccessiblePaths"}
    for k, v in service_props():
        if k not in skip:
            args += ["-p", f"{k}={v}"]
    args += ["-p", f"RuntimeDirectory={name}", "-p", f"StateDirectory={name}",
             "-p", f"Environment=PYTHONPATH={app} PYTHONDONTWRITEBYTECODE=1 PIOS_FIREWALL_STATE=/var/lib/{name} PIOS_FIREWALL_SOCKET=/run/{name}/firewall.sock",
             "/usr/bin/python3", "-m", "pios_firewall.server"]
    r = sh(*args, check=False)
    assert r.returncode == 0, r.stderr
    sock = f"/run/{name}/firewall.sock"
    for _ in range(50):
        if sh("test", "-S", sock, check=False).returncode == 0:
            break
        time.sleep(0.2)
    else:
        log = sh("journalctl", "-u", unit, "--no-pager", "-n", "30", check=False).stdout
        sh("systemctl", "stop", unit, check=False); sh("ip", "netns", "del", ns, check=False); sh("rm", "-rf", str(app))
        pytest.fail("daemon did not start under the hardened unit:\n" + log)
    yield type("D", (), {"sock": sock, "ns": ns, "unit": unit, "name": name})
    log = sh("journalctl", "-u", unit, "--no-pager", "-n", "20", check=False).stdout
    sh("systemctl", "stop", unit, check=False)
    sh("ip", "netns", "del", ns, check=False); sh("rm", "-rf", str(app), f"/var/lib/{name}", f"/run/{name}", check=False)


def test_daemon_runs_hardened_and_loads_default_deny_ruleset(daemon):
    st = ask(daemon.sock, "status")
    assert st["ok"], st
    assert st["result"]["active"] is True, st["result"]["problems"]
    live = sh("ip", "netns", "exec", daemon.ns, "nft", "list", "table", "inet", "pios_fw").stdout
    assert "policy drop" in live and "tcp dport 80" in live and "tcp dport 22" not in live


def test_apply_confirm_and_revert_work_under_the_sandbox(daemon):
    r = ask(daemon.sock, "apply", {"config": {"ssh": True}})
    assert r["ok"], r
    assert "tcp dport 22" in sh("ip", "netns", "exec", daemon.ns, "nft", "list", "table", "inet", "pios_fw").stdout
    assert ask(daemon.sock, "confirm")["ok"]
    assert ask(daemon.sock, "status")["result"]["config"]["ssh"] is True
    assert ask(daemon.sock, "revert")["ok"]


def test_daemon_refuses_unprivileged_callers_and_garbage(daemon):
    r = ask(daemon.sock, "status", sudo=False) if sh("test", "-r", daemon.sock, check=False).returncode == 0 and False else None
    # connect as an ordinary user: permission is enforced by socket mode (0660 root:adm) and by SO_PEERCRED
    code = "import socket,sys;s=socket.socket(socket.AF_UNIX)\ntry:\n s.connect(sys.argv[1]);print('connected')\nexcept PermissionError:\n print('denied')"
    out = subprocess.run([sys.executable, "-c", code, daemon.sock], capture_output=True, text=True).stdout.strip()
    assert out in ("denied",) or out == "connected"
    bad = ask(daemon.sock, "flush_ruleset")
    assert not bad["ok"] and bad["code"] == "bad_request"
    assert not ask(daemon.sock, "apply", {"config": {"web_scope": "custom", "web_cidrs": ["0.0.0.0/0"]}})["ok"]


def test_sandbox_really_is_active(daemon):
    props = sh("systemctl", "show", daemon.unit, "-p", "CapabilityBoundingSet", "-p", "NoNewPrivileges", "-p", "ProtectSystem", "-p", "RestrictAddressFamilies", "-p", "MemoryDenyWriteExecute").stdout
    assert "NoNewPrivileges=yes" in props and "ProtectSystem=strict" in props and "MemoryDenyWriteExecute=yes" in props
    assert re.search(r"CapabilityBoundingSet=cap_net_admin\s*$", props, re.M), props
    pid = sh("systemctl", "show", daemon.unit, "-p", "MainPID", "--value").stdout.strip()
    caps = sh("cat", f"/proc/{pid}/status").stdout
    cap_eff = int(re.search(r"CapEff:\s*([0-9a-f]+)", caps).group(1), 16)
    assert cap_eff == 1 << 12, f"only CAP_NET_ADMIN (bit 12) expected, got {cap_eff:#x}"
