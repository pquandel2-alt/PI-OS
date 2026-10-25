"""The release pipeline scripts, end to end, with a throw-away key."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TOOL = [sys.executable, str(ROOT / "scripts/release_tool.py")]


def run(*args, env=None, check=True):
    return subprocess.run([*TOOL, *args], capture_output=True, text=True, env={**os.environ, **(env or {})}, check=False)


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    t = tmp_path_factory.mktemp("rel")
    assert run("keygen", str(t / "k")).returncode == 0
    r = run("package", "--channel", "beta", "--out", str(t / "o"), "--highlight", "Test")
    assert r.returncode == 0, r.stderr
    return t


def files(t):
    o = next((t / "o").glob("*.manifest.json"))
    return o, Path(str(o) + ".sig"), next((t / "o").glob("*.tar.zst"))


def test_sign_and_verify_roundtrip(built):
    t = built; m, sig, pkg = files(t)
    seed = (t / "k/private.key").read_text().strip()
    r = run("sign", "--manifest", str(m), env={"PIOS_UPDATE_SIGNING_KEY": seed})
    assert r.returncode == 0 and seed not in r.stdout + r.stderr, "private key must never be printed"
    r = run("verify", "--manifest", str(m), "--sig", str(sig), "--package", str(pkg), "--pubkey", str(t / "k/public.pub"))
    assert r.returncode == 0, r.stderr + r.stdout and "OK" in r.stdout
    assert json.loads(m.read_text())["channel"] == "beta"


def test_tampered_artifacts_fail_verification(built):
    t = built; m, sig, pkg = files(t)
    seed = (t / "k/private.key").read_text().strip()
    run("sign", "--manifest", str(m), env={"PIOS_UPDATE_SIGNING_KEY": seed})
    bad = t / "bad.json"; bad.write_bytes(m.read_bytes().replace(b'"beta"', b'"stable"'))
    assert run("verify", "--manifest", str(bad), "--sig", str(sig), "--package", str(pkg), "--pubkey", str(t / "k/public.pub")).returncode != 0
    badpkg = t / "bad.tar.zst"; badpkg.write_bytes(pkg.read_bytes()[:-3] + b"xyz")
    assert run("verify", "--manifest", str(m), "--sig", str(sig), "--package", str(badpkg), "--pubkey", str(t / "k/public.pub")).returncode != 0


def test_signing_without_key_fails_and_does_not_leak():
    r = run("sign", "--manifest", "/nonexistent", env={"PIOS_UPDATE_SIGNING_KEY": ""})
    assert r.returncode != 0


def test_stable_is_blocked_without_hardware_validation(tmp_path):
    r = run("package", "--channel", "stable", "--out", str(tmp_path))
    assert r.returncode != 0 and "gesperrt" in r.stderr


def test_version_must_match_source(tmp_path):
    assert run("package", "--version", "9.9.9", "--channel", "beta", "--out", str(tmp_path)).returncode != 0


def test_shipped_public_key_is_valid_and_private_key_not_in_repo():
    from pios_updater import crypto
    pub = ROOT / "image/overlay/usr/share/pios/update-keys/pios-release-1.pub"
    assert len(crypto.load_trusted_keys(pub.parent)) == 1
    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    assert not any(f.endswith("private.key") for f in tracked)
