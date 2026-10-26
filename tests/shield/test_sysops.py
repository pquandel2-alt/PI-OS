import json
import os
import socket
import stat
import threading
from pathlib import Path

import pytest

from pios_sysops import osstatus
from pios_sysops.server import Ops, OpError, Server

APT_LIST = """Listing...
libssl3t64/stable-security 3.5.1-1+deb13u1 arm64 [upgradable from: 3.5.0-1]
chromium/stable 141.0.7390.54-1~deb13u1 arm64 [upgradable from: 140.0.7339.185-1~deb13u1]
tzdata/stable-updates 2025c-0+deb13u1 all [upgradable from: 2025b-5]
"""
UA_DRY = """Initial blacklist:
Initial whitelist (not strict):
Starting unattended upgrades script
Allowed origins are: origin=Debian,codename=trixie-security,label=Debian-Security
Checking: libssl3t64 ([<Origin component:'main' archive:'stable-security'>])
Packages that will be upgraded: libssl3t64 libssl-dev
Writing dpkg log to /var/log/unattended-upgrades/unattended-upgrades-dpkg.log
"""
UA_NONE = "No packages found that can be upgraded unattended and no pending auto-removals\n"
UA_FAIL = "Packages that were upgraded: libssl3t64\nAn error occurred: 'dpkg returned an error! (1)'\n"


def test_parse_apt_list_and_unattended_output():
    up = osstatus.parse_upgradable(APT_LIST)
    assert [u["name"] for u in up] == ["libssl3t64", "chromium", "tzdata"] and up[0]["current"] == "3.5.0-1" and up[1]["new"].startswith("141")
    assert osstatus.parse_unattended(UA_DRY) == {"packages": ["libssl3t64", "libssl-dev"], "error": ""}
    assert osstatus.parse_unattended(UA_NONE) == {"packages": [], "error": ""}
    r = osstatus.parse_unattended(UA_FAIL)
    assert r["packages"] == ["libssl3t64"] and "error" in r["error"].lower()


@pytest.mark.parametrize("out,bad", [("W: GPG error: http://x InRelease: The following signatures couldn't be verified because the public key is not available: NO_PUBKEY AAAA", True),
                                     ("E: The repository 'http://x stable InRelease' is not signed.", True), ("Hit:1 http://deb.debian.org/debian trixie InRelease", False)])
def test_signature_problems_detected(out, bad):
    assert bool(osstatus.SIGNATURE_PROBLEMS.search(out)) is bad


def test_insecure_apt_configuration_is_flagged():
    assert osstatus.source_problems("deb [trusted=yes] http://evil/ stable main", "")
    assert osstatus.source_problems("", 'APT::Get::AllowUnauthenticated "true";')
    assert osstatus.source_problems("deb [signed-by=/usr/share/keyrings/debian.gpg] http://deb.debian.org/debian trixie main", 'Acquire::Retries "3";') == []


def test_job_check_with_fake_apt(tmp_path, monkeypatch):
    monkeypatch.setattr(osstatus, "STATE", tmp_path)
    replies = {("apt-get", "update", "-q"): (0, "Hit:1 http://deb.debian.org/debian trixie InRelease\n"), ("apt", "list", "--upgradable"): (0, APT_LIST),
               ("unattended-upgrade", "--dry-run", "-v"): (0, UA_DRY)}
    monkeypatch.setattr(osstatus, "_run", lambda cmd, timeout=0: replies[tuple(cmd)])
    monkeypatch.setattr(osstatus, "read_apt_config", lambda: ("", ""))
    st = osstatus.job_check()
    assert st["ok"] and st["signature_ok"] is True and len(st["upgradable"]) == 3 and st["security"] == ["libssl3t64", "libssl-dev"]
    assert json.loads((tmp_path / "os-status.json").read_text())["checked_at"] == st["checked_at"]
    assert stat.S_IMODE((tmp_path / "os-status.json").stat().st_mode) == 0o644


def test_job_check_reports_signature_failure_and_never_claims_success(tmp_path, monkeypatch):
    monkeypatch.setattr(osstatus, "STATE", tmp_path)
    monkeypatch.setattr(osstatus, "_run", lambda cmd, timeout=0: (100, "W: GPG error: x InRelease: NO_PUBKEY ABC\nE: The repository is not signed.\n"))
    monkeypatch.setattr(osstatus, "read_apt_config", lambda: ("", ""))
    st = osstatus.job_check()
    assert st["ok"] is False and st["signature_ok"] is False and "Signatur" in st["error"] and st["upgradable"] == []


def test_job_upgrade_records_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(osstatus, "STATE", tmp_path)
    calls = []
    def run(cmd, timeout=0):
        calls.append(cmd[0])
        return (1, UA_FAIL) if cmd[:2] == ["unattended-upgrade", "-v"] else (0, "")
    monkeypatch.setattr(osstatus, "_run", run)
    monkeypatch.setattr(osstatus, "read_apt_config", lambda: ("", ""))
    res = osstatus.job_upgrade()
    assert res["ok"] is False and res["error"] and (tmp_path / "os-upgrade.json").exists()


def test_package_lock_is_exclusive(tmp_path, monkeypatch):
    import fcntl
    monkeypatch.setattr(osstatus, "LOCK", str(tmp_path / "pkg.lock"))
    fd = os.open(tmp_path / "pkg.lock", os.O_RDWR | os.O_CREAT)
    fcntl.flock(fd, fcntl.LOCK_EX)                                   # e.g. the OTA installer holds it
    ran = []
    t = threading.Thread(target=lambda: osstatus.with_lock(lambda: ran.append(1)))
    t.start(); t.join(0.4)
    assert not ran and t.is_alive(), "APT job waits while an OTA installation holds the lock"
    os.close(fd); t.join(3)
    assert ran == [1]


class FakeCtl:
    def __init__(self): self.calls = []; self.states = {}
    def start(self, u): self.calls.append(("start", u))
    def stop(self, u): self.calls.append(("stop", u))
    def show(self, u, *p): return self.states.get(u, {"ActiveState": "inactive", "Result": "success", "MainPID": "0"})
    def run(self, *a, timeout=0): self.calls.append(("run", a)); return 0, "", ""


def test_ops_only_ever_touch_whitelisted_units():
    ctl = FakeCtl(); ops = Ops(ctl)
    for m in ("clamd.start", "clamd.stop", "signatures.update", "os.check", "os.upgrade"):
        ops.dispatch(m, {"unit": "ssh.service", "x": "; rm -rf /"})
    units = {c[1] for c in ctl.calls if c[0] in ("start", "stop")}
    assert units == {"clamav-daemon.service", "pios-clam-update.service", "pios-os-check.service", "pios-os-upgrade.service"}
    with pytest.raises(OpError):
        ops.dispatch("systemctl", {"args": ["stop", "ssh"]})
    with pytest.raises(OpError):
        ops.dispatch("os.config", {"auto_security": "yes"})


def test_signature_update_refuses_to_run_twice():
    ctl = FakeCtl(); ctl.states["pios-clam-update.service"] = {"ActiveState": "active"}
    with pytest.raises(OpError) as e:
        Ops(ctl).dispatch("signatures.update", {})
    assert e.value.code == "busy"


def test_os_config_persists_and_toggles_timer(tmp_path, monkeypatch):
    import pios_sysops.server as srv
    monkeypatch.setattr(srv, "OS_CONF", tmp_path / "os-updates.conf")
    ctl = FakeCtl(); ops = Ops(ctl)
    assert ops.auto_security() is True
    ops.dispatch("os.config", {"auto_security": False})
    assert ops.auto_security() is False and ("run", ("disable", "--now", "pios-os-upgrade.timer")) in ctl.calls


def test_socket_server_enforces_caller_and_protocol(tmp_path):
    sock = tmp_path / "s.sock"
    s = Server(sock, Ops(FakeCtl()), {os.getuid()}); threading.Thread(target=s.serve_forever, daemon=True).start()
    def ask(raw: bytes):
        c = socket.socket(socket.AF_UNIX); c.connect(str(sock)); c.sendall(raw); r = c.makefile().readline(); c.close(); return json.loads(r)
    assert ask(b'{"method":"ping"}\n')["ok"]
    assert ask(b"garbage\n")["code"] == "bad_request"
    assert ask(b'{"method":"rm -rf /"}\n')["code"] == "bad_request"
    s.allowed_uids = {123456}
    assert ask(b'{"method":"ping"}\n')["code"] == "forbidden"
    s.shutdown(); s.server_close()


# ---- driver / firmware packages -------------------------------------------------------------------------------------
POLICY_NEW = "firmware-realtek:\n  Installed: (none)\n  Candidate: 20250410-2\n  Version table:\n     20250410-2 500\n        500 http://deb.debian.org/debian trixie/non-free-firmware arm64 Packages\n"
POLICY_FOREIGN = POLICY_NEW.replace("deb.debian.org", "evil.example")


def pkg_ops(policy):
    ctl = FakeCtl()
    return Ops(ctl, runner=lambda cmd, timeout=0: (0, policy)), ctl


def test_install_only_allow_listed_packages_with_confirmed_version():
    ops, ctl = pkg_ops(POLICY_NEW)
    r = ops.dispatch("pkg.install", {"package": "firmware-realtek", "version": "20250410-2"})
    assert r["started"] and ctl.calls == [("start", "pios-pkg-install@firmware-realtek.service")] and "Neustart" in r["reboot_hint"]


@pytest.mark.parametrize("pkg", ["openssh-server", "bash", "firmware-realtek; rm -rf /", "--allow-unauthenticated", "../x", "", None, 5, "FIRMWARE-REALTEK", "a" * 80])
def test_other_packages_and_injection_attempts_are_refused(pkg):
    ops, ctl = pkg_ops(POLICY_NEW)
    with pytest.raises(OpError):
        ops.dispatch("pkg.install", {"package": pkg, "version": "20250410-2"})
    assert ctl.calls == []


def test_version_must_match_what_the_user_confirmed():
    ops, ctl = pkg_ops(POLICY_NEW)
    with pytest.raises(OpError) as e:
        ops.dispatch("pkg.install", {"package": "firmware-realtek", "version": "1.0"})
    assert e.value.code == "version_changed"
    with pytest.raises(OpError):
        ops.dispatch("pkg.install", {"package": "firmware-realtek"})
    assert ctl.calls == []


def test_packages_from_unofficial_sources_are_never_installed():
    ops, ctl = pkg_ops(POLICY_FOREIGN)
    with pytest.raises(OpError) as e:
        ops.dispatch("pkg.install", {"package": "firmware-realtek", "version": "20250410-2"})
    assert e.value.code == "untrusted_source" and ctl.calls == []


def test_unavailable_installed_and_running_states():
    ops, ctl = pkg_ops("N: Unable to locate package firmware-realtek\n")
    with pytest.raises(OpError) as e:
        ops.dispatch("pkg.install", {"package": "firmware-realtek", "version": "x"})
    assert e.value.code == "unavailable"
    ops, ctl = pkg_ops(POLICY_NEW.replace("Installed: (none)", "Installed: 20250410-2"))
    with pytest.raises(OpError) as e:
        ops.dispatch("pkg.install", {"package": "firmware-realtek", "version": "20250410-2"})
    assert e.value.code == "already_installed"
    ops, ctl = pkg_ops(POLICY_NEW)
    ctl.states["pios-pkg-install@firmware-realtek.service"] = {"ActiveState": "active"}
    with pytest.raises(OpError) as e:
        ops.dispatch("pkg.install", {"package": "firmware-realtek", "version": "20250410-2"})
    assert e.value.code == "busy"
    st = ops.dispatch("pkg.status", {"package": "firmware-realtek"})
    assert st["running"] is True and st["official"] is True and st["candidate"] == "20250410-2"


def test_template_unit_uses_the_shared_lock_and_double_checks_the_allow_list():
    from pathlib import Path
    u = (Path(__file__).resolve().parents[2] / "image/overlay/etc/systemd/system/pios-pkg-install@.service").read_text()
    assert "/run/pios-pkg.lock" in u and "apt-get install -y --no-install-recommends -- %i" in u and "ALLOWED" in u and "ExecStartPre" in u
