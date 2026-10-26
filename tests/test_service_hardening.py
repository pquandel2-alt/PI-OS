"""Starts the backend under real systemd with exactly the sandboxing properties of pios.service (transient unit in a throw-away
network namespace) and exercises login, uploads, system metrics and the static UI. Proves that the hardening does not break the
application. Needs root via sudo, systemd, ip."""
import json
import re
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "image/overlay/etc/systemd/system/pios.service"


def can():
    return all(shutil.which(x) for x in ("systemd-run", "ip", "curl")) and subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0 \
        and Path("/run/systemd/system").exists() and (ROOT.parent / "venv/bin/uvicorn").exists()


pytestmark = pytest.mark.skipif(not can(), reason="needs systemd, ip, curl, passwordless sudo and the dev venv")
sh = lambda *a, check=True: subprocess.run(["sudo", "-n", *a], capture_output=True, text=True, check=check)


def props():
    section, out = None, []
    for line in UNIT.read_text().splitlines():
        if line.startswith("["):
            section = line.strip("[]")
        elif section == "Service" and "=" in line and not line.startswith("#"):
            out.append(tuple(line.split("=", 1)))
    return out


@pytest.fixture()
def svc():
    tag = uuid.uuid4().hex[:6]
    ns, unit, name = f"pios{tag}", f"pios-hard-{tag}", f"pios-hard-{tag}"
    sh("ip", "netns", "add", ns); sh("ip", "-n", ns, "link", "set", "lo", "up")
    venv = ROOT.parent / "venv"
    skip = {"User", "Group", "Environment", "ExecStart", "StateDirectory", "StateDirectoryMode", "Restart", "RestartSec", "Type", "WorkingDirectory", "ProtectHome", "UMask"}
    args = ["systemd-run", f"--unit={unit}", "--quiet", "--collect", "-p", f"NetworkNamespacePath=/run/netns/{ns}", "-p", "User=philipp",
            # the dev venv lives in /home, so the test relaxes ONLY ProtectHome (no effect on syscalls/capabilities)
            "-p", "ProtectHome=read-only", "-p", f"StateDirectory={name}", "-p", "UMask=0077", "-p", f"WorkingDirectory={ROOT}"]
    for k, v in props():
        if k not in skip:
            args += ["-p", f"{k}={v}"]
    args += ["-p", f"Environment=PIOS_DATA=/var/lib/{name} PIOS_WEB={ROOT}/web PIOS_APPS={ROOT}/apps PYTHONDONTWRITEBYTECODE=1 PIOS_MALWARE=off PIOS_ALLOWED_HOSTS=127.0.0.1",
             str(venv / "bin/python"), "-m", "uvicorn", "pios.main:app", "--host", "127.0.0.1", "--port", "80", "--no-server-header", "--log-level", "warning"]
    r = sh(*args, check=False)
    assert r.returncode == 0, r.stderr

    def curl(*a):
        r = sh("ip", "netns", "exec", ns, "curl", "-sS", "-m", "10", *a, check=False)
        return r.stdout if r.returncode == 0 else "CURL-ERR " + r.stderr
    for _ in range(60):
        if "ok" in curl("http://127.0.0.1/healthz"):
            break
        time.sleep(0.3)
    else:
        log = sh("journalctl", "-u", unit, "--no-pager", "-n", "40", check=False).stdout
        sh("systemctl", "stop", unit, check=False); sh("ip", "netns", "del", ns, check=False)
        pytest.fail("backend failed to start under the hardened unit:\n" + log)
    yield type("S", (), {"curl": staticmethod(curl), "unit": unit, "ns": ns, "name": name})
    sh("systemctl", "stop", unit, check=False); sh("ip", "netns", "del", ns, check=False); sh("rm", "-rf", f"/var/lib/{name}", check=False)


def test_backend_fully_functional_inside_the_sandbox(svc, tmp_path):
    code = svc.curl("http://127.0.0.1/api/setup-status")
    assert '"needs_setup":true' in code.replace(" ", "")
    jar = tmp_path / "jar"
    sh("cat", f"/var/lib/{svc.name}/setup-code") if False else None
    # loopback is exempt from the setup code (HDMI kiosk), the netns client connects via 127.0.0.1
    hdr = ["-H", "X-PiOS: 1", "-H", "Content-Type: application/json", "-c", str(jar), "-b", str(jar)]
    assert '"ok":true' in svc.curl(*hdr, "-d", json.dumps({"username": "admin", "password": "correct horse battery"}), "http://127.0.0.1/api/setup").replace(" ", "")
    assert '"ok":true' in svc.curl(*hdr, "-d", json.dumps({"username": "admin", "password": "correct horse battery"}), "http://127.0.0.1/api/login").replace(" ", "")
    sysj = json.loads(svc.curl("-b", str(jar), "http://127.0.0.1/api/system"))
    assert sysj["cores"] >= 1 and sysj["ram"]["total"] > 0 and sysj["uptime"] > 0, "psutil works under ProtectProc/ProtectKernel*"
    up = tmp_path / "x.txt"; up.write_text("hallo")
    assert '"size":5' in svc.curl(*hdr[:2], "-b", str(jar), "-F", f"file=@{up}", "http://127.0.0.1/api/files/upload?path=").replace(" ", "")
    assert svc.curl("-b", str(jar), "http://127.0.0.1/api/files/download?path=x.txt") == "hallo"
    assert "PiOS NOVA" in svc.curl("http://127.0.0.1/")
    sh("ls", "-la", f"/var/lib/{svc.name}")


def test_sandbox_properties_are_really_applied(svc):
    p = sh("systemctl", "show", svc.unit, "-p", "NoNewPrivileges", "-p", "ProtectSystem", "-p", "MemoryDenyWriteExecute", "-p", "PrivateDevices", "-p", "MemoryMax", "-p", "RestrictNamespaces").stdout
    for want in ("NoNewPrivileges=yes", "ProtectSystem=strict", "MemoryDenyWriteExecute=yes", "PrivateDevices=yes", "RestrictNamespaces=yes"):
        assert want in p, p
    pid = sh("systemctl", "show", svc.unit, "-p", "MainPID", "--value").stdout.strip()
    st = sh("cat", f"/proc/{pid}/status").stdout
    eff = int(re.search(r"CapEff:\s*([0-9a-f]+)", st).group(1), 16)
    assert eff == 1 << 10, f"only CAP_NET_BIND_SERVICE (bit 10) expected, got {eff:#x}"
    assert re.search(r"Seccomp:\s*2", st), "syscall filter active"
    assert re.search(r"NoNewPrivs:\s*1", st)


def test_service_cannot_write_outside_its_state_directory(svc):
    r = sh("nsenter", "-t", sh("systemctl", "show", svc.unit, "-p", "MainPID", "--value").stdout.strip(), "-m", "sh", "-c", "touch /etc/pios-hack 2>&1; echo rc=$?", check=False)
    assert "rc=0" not in r.stdout, "ProtectSystem=strict must make /etc read-only"
