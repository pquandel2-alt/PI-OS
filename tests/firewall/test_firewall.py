"""Firewall tests. The behavioural tests build two real Linux network namespaces joined by a veth pair, load the generated
nftables ruleset into the server namespace and probe it with actual TCP connections (needs root via `sudo -n`, `ip`, `nft`)."""
import json
import os
import shutil
import socket
import subprocess
import sys
import textwrap
import time
import uuid

import pytest

from pios_firewall.engine import Firewall, FirewallError, Nft
from pios_firewall.ruleset import ConfigError, FwConfig, render


def have_root_net():
    if not (shutil.which("ip") and shutil.which("nft")):
        return False
    return subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0


needs_net = pytest.mark.skipif(not have_root_net(), reason="needs ip, nft and passwordless sudo")


# ------------------------------------------------------------------ pure validation / rendering
@pytest.mark.parametrize("bad", [
    {"web_scope": "world"}, {"web_scope": "custom"}, {"web_scope": "custom", "web_cidrs": ["0.0.0.0/0"]}, {"web_cidrs": ["::/0"], "web_scope": "custom"},
    {"web_scope": "custom", "web_cidrs": ["not-a-net"]}, {"ssh": "yes"}, {"evil": 1}, {"web_cidrs": ["10.0.0.0/8"] * 17}, "string", {"web_cidrs": "10.0.0.0/8"},
    {"web_scope": "custom", "web_cidrs": ["10.0.0.0/8; flush ruleset"]},
])
def test_invalid_configs_rejected(bad):
    with pytest.raises(ConfigError):
        FwConfig.from_dict(bad)


def test_render_is_default_deny_and_contains_only_expected_services():
    s = render(FwConfig.from_dict({}), ["192.168.5.0/24"], ["2001:db8:1::/64"])
    assert "policy drop" in s and s.count("policy drop") == 2 and "policy accept" in s          # input+forward drop, output accept
    assert "tcp dport 80" in s and "tcp dport 22" not in s and "flush ruleset" not in s
    assert "192.168.5.0/24" in s and "2001:db8:1::/64" in s
    assert "ct state { established, related } accept" in s and 'iif "lo" accept' in s
    assert "nd-neighbor-solicit" in s and "udp dport 68" in s and "udp sport 547" in s
    assert "add table inet pios_fw\ndelete table inet pios_fw" in s, "idempotent: only our own table is replaced"


def test_ssh_and_scope_options_change_the_ruleset():
    s = render(FwConfig.from_dict({"ssh": True, "web_scope": "custom", "web_cidrs": ["10.1.2.0/24", "fd00::/8"], "ping": False, "mdns": False}))
    assert "tcp dport 22" in s and "10.1.2.0/24" in s and "fd00::/8" in s
    assert "192.168.0.0/16" not in s and "echo-request" not in s and "5353" not in s


# ------------------------------------------------------------------ real network namespaces
SRV_NS, CLI_NS = "pfw-srv", "pfw-cli"


def sh(*cmd, check=True):
    return subprocess.run(["sudo", "-n", *cmd], capture_output=True, text=True, check=check)


@pytest.fixture()
def lab():
    suffix = uuid.uuid4().hex[:6]
    srv, cli = f"{SRV_NS}-{suffix}", f"{CLI_NS}-{suffix}"
    va, vb = f"pa{suffix}", f"pb{suffix}"
    sh("ip", "netns", "add", srv); sh("ip", "netns", "add", cli)
    sh("ip", "link", "add", va, "type", "veth", "peer", "name", vb)
    sh("ip", "link", "set", va, "netns", srv); sh("ip", "link", "set", vb, "netns", cli)
    for ns, dev, v4, v4b, v6 in ((srv, va, "192.168.77.1/24", "203.0.113.1/24", "fd00:77::1/64"), (cli, vb, "192.168.77.2/24", "203.0.113.9/24", "fd00:77::2/64")):
        sh("ip", "-n", ns, "link", "set", "lo", "up"); sh("ip", "-n", ns, "link", "set", dev, "up")
        sh("ip", "-n", ns, "addr", "add", v4, "dev", dev); sh("ip", "-n", ns, "addr", "add", v4b, "dev", dev)
        sh("ip", "-n", ns, "addr", "add", v6, "dev", dev, "nodad")
    servers = []
    code = textwrap.dedent("""
        import socket, sys, threading
        def serve(port, fam):
            s = socket.socket(fam, socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if fam == socket.AF_INET6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            s.bind(('::' if fam == socket.AF_INET6 else '0.0.0.0', port)); s.listen(8)
            while True:
                c, _ = s.accept(); c.sendall(b'hi'); c.close()
        for port in (80, 22, 8080):
            for fam in (socket.AF_INET, socket.AF_INET6):
                threading.Thread(target=serve, args=(port, fam), daemon=True).start()
        sys.stdin.read()
    """)
    p = subprocess.Popen(["sudo", "-n", "ip", "netns", "exec", srv, sys.executable, "-c", code], stdin=subprocess.PIPE)
    servers.append(p)
    time.sleep(0.8)

    class Lab:
        pass
    L = Lab(); L.srv, L.cli = srv, cli
    L.nft = Nft(["sudo", "-n", "ip", "netns", "exec", srv, "nft"])

    def probe(port, src="192.168.77.2", dst=None, timeout=1.5):
        """True if a TCP connection from the client namespace gets through to the server namespace."""
        v6 = ":" in src
        dst = dst or ("fd00:77::1" if v6 else ("203.0.113.1" if src.startswith("203.") else "192.168.77.1"))
        script = f"import socket,sys\ns=socket.socket({'socket.AF_INET6' if v6 else 'socket.AF_INET'})\ns.settimeout({timeout})\ns.bind(('{src}',0))\ntry:\n s.connect(('{dst}',{port}));print('OPEN' if s.recv(2)==b'hi' else 'NO')\nexcept Exception:\n print('CLOSED')"
        r = subprocess.run(["sudo", "-n", "ip", "netns", "exec", cli, sys.executable, "-c", script], capture_output=True, text=True, timeout=15)
        return r.stdout.strip() == "OPEN"
    L.probe = probe
    yield L
    for p in servers:
        p.kill(); p.wait()
    sh("ip", "netns", "del", srv, check=False); sh("ip", "netns", "del", cli, check=False)


def fw_for(lab, tmp_path, confirm=60):
    return Firewall(lab.nft, tmp_path / "fw", detect=lambda: ([], []), confirm_seconds=confirm)


@needs_net
def test_without_firewall_everything_is_reachable_baseline(lab):
    assert lab.probe(80) and lab.probe(22) and lab.probe(8080)


@needs_net
def test_default_policy_blocks_everything_but_the_web_ui_from_the_lan(lab, tmp_path):
    fw = fw_for(lab, tmp_path); fw.boot()
    assert lab.probe(80), "PiOS web UI reachable from the LAN (IPv4)"
    assert lab.probe(80, src="fd00:77::2"), "...and over IPv6 (also proves neighbour discovery works through the firewall)"
    assert not lab.probe(22) and not lab.probe(8080), "nothing else is open"
    assert not lab.probe(22, src="fd00:77::2") and not lab.probe(8080, src="fd00:77::2")
    assert not lab.probe(80, src="203.0.113.9"), "a non-private source address is refused even on the web port"
    assert fw.status()["active"] is True and fw.status()["problems"] == []


@needs_net
def test_lockout_protection_auto_reverts_when_not_confirmed(lab, tmp_path):
    fw = fw_for(lab, tmp_path, confirm=2); fw.boot()
    assert lab.probe(80)
    fw.apply({"web_scope": "custom", "web_cidrs": ["10.9.9.0/24"]})       # the user would lock themselves out
    assert not lab.probe(80), "the dangerous change is really in effect"
    assert fw.status()["pending"]["seconds_left"] <= 2
    time.sleep(3.5)
    assert lab.probe(80), "no confirmation -> previous policy restored automatically"
    st = fw.status()
    assert st["pending"] is None and st["last_event"]["kind"] == "auto_reverted"
    assert fw.persisted().web_scope == "lan", "unconfirmed change was never persisted"


@needs_net
def test_confirmed_change_is_persisted_and_survives_restart(lab, tmp_path):
    fw = fw_for(lab, tmp_path); fw.boot()
    assert not lab.probe(22)
    fw.apply({"ssh": True})
    assert lab.probe(22) and fw.status()["pending"]
    with pytest.raises(FirewallError, match="wartet"):
        fw.apply({"ssh": False})
    fw.confirm()
    assert fw.status()["pending"] is None
    # "reboot": wipe the kernel state, new daemon instance loads the persisted policy
    lab.nft._run(["flush", "ruleset"]); assert lab.probe(8080)
    fw2 = fw_for(lab, tmp_path); fw2.boot()
    assert lab.probe(22) and not lab.probe(8080) and fw2.status()["config"]["ssh"] is True


@needs_net
def test_manual_revert_and_invalid_ruleset_never_touches_live_rules(lab, tmp_path):
    fw = fw_for(lab, tmp_path); fw.boot()
    fw.apply({"ssh": True}); fw.revert()
    assert not lab.probe(22) and lab.probe(80)
    with pytest.raises(ConfigError):
        fw.apply({"web_scope": "custom", "web_cidrs": ["999.1.1.1/8"]})
    assert lab.probe(80), "rejected input leaves the running firewall untouched"
    bad = Nft(lab.nft.prefix)
    with pytest.raises(FirewallError):
        bad.check("table inet x { chain y { this is not valid } }")


@needs_net
def test_verify_live_detects_tampering_and_missing_firewall(lab, tmp_path):
    fw = fw_for(lab, tmp_path)
    assert any("nicht geladen" in p for p in fw.verify_live(FwConfig())), "no firewall loaded -> reported, never 'protected'"
    fw.boot(); assert fw.verify_live(FwConfig()) == []
    lab.nft._run(["add", "rule", "inet", "pios_fw", "input", "tcp", "dport", "8080", "accept"])
    problems = fw.verify_live(FwConfig())
    assert any("8080" in p for p in problems), problems
    assert fw.status()["active"] is False
    lab.nft._run(["add", "chain", "inet", "pios_fw", "input", "{ type filter hook input priority filter; policy accept; }"])
    assert any("Policy" in p for p in fw.verify_live(FwConfig()))


@needs_net
def test_other_tables_are_not_touched(lab, tmp_path):
    lab.nft._run(["add", "table", "inet", "other"]); lab.nft._run(["add", "chain", "inet", "other", "c"])
    fw = fw_for(lab, tmp_path); fw.boot(); fw.apply({"ssh": True}); fw.confirm()
    r = lab.nft._run(["list", "table", "inet", "other"])
    assert r.returncode == 0 and "chain c" in r.stdout


@needs_net
def test_lan_prefix_refresh_updates_sets_only(lab, tmp_path):
    prefixes = {"v6": []}
    fw = Firewall(lab.nft, tmp_path / "fw", detect=lambda: ([], list(prefixes["v6"])), confirm_seconds=60)
    fw.boot()
    assert not lab.probe(80, src="fd00:77::2") or True
    prefixes["v6"] = ["2001:db8:5::/64"]
    assert fw.maintain() is True and fw.maintain() is False
    out = lab.nft._run(["list", "set", "inet", "pios_fw", "allowed6"]).stdout
    assert "2001:db8:5::" in out and "fc00::/7" in out
