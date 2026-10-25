import io
import subprocess
import tarfile
from pathlib import Path

import pytest

from pios_updater import crypto, manifest as mf, package
from pios_updater.package import PackageError
from pios_updater.version import Version
from .conftest import make_tree


def zst_tar(tmp: Path, members) -> Path:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for ti, data in members:
            tf.addfile(ti, io.BytesIO(data) if data is not None else None)
    out = tmp / "evil.tar.zst"
    subprocess.run(["zstd", "-q", "-f", "-o", str(out)], input=raw.getvalue(), check=True)
    return out


def ti(name, typ=tarfile.REGTYPE, size=0, link=""):
    t = tarfile.TarInfo(name); t.type = typ; t.size = size; t.linkname = link; t.mode = 0o644
    return t


@pytest.mark.parametrize("name", ["../evil", "/etc/passwd", "pios/../../x", "etc/passwd", "..\\x"])
def test_unpack_rejects_dangerous_paths(tmp_path, name):
    pkg = zst_tar(tmp_path, [(ti(name, size=1), b"x")])
    with pytest.raises(PackageError):
        package.unpack(pkg, tmp_path / "out", 100)
    assert not (tmp_path / "evil").exists() and not Path("/etc/passwd.x").exists()


@pytest.mark.parametrize("typ", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE])
def test_unpack_rejects_links_and_devices(tmp_path, typ):
    pkg = zst_tar(tmp_path, [(ti("pios/x", typ, link="/etc/shadow"), None)])
    with pytest.raises(PackageError):
        package.unpack(pkg, tmp_path / "out", 100)


def test_unpack_enforces_size_budget(tmp_path):
    pkg = zst_tar(tmp_path, [(ti("pios/big", size=100000), b"a" * 100000)])
    with pytest.raises(PackageError, match="größer"):
        package.unpack(pkg, tmp_path / "out", 1000)


def test_build_is_deterministic_and_roundtrips(tmp_path):
    make_tree(tmp_path / "src", "0.2.0")
    a = package.build(tmp_path / "src", tmp_path / "a.tar.zst", {"version": "0.2.0", "db_schema": 1})
    b = package.build(tmp_path / "src", tmp_path / "b.tar.zst", {"version": "0.2.0", "db_schema": 1})
    assert a["sha256"] == b["sha256"]
    package.unpack(tmp_path / "a.tar.zst", tmp_path / "out", a["unpacked_size"])
    package.validate_tree(tmp_path / "out", "0.2.0", 1)
    assert (tmp_path / "out/bin/pios-wait-ready").stat().st_mode & 0o111
    assert not (tmp_path / "out/web/index.html").stat().st_mode & 0o022


def test_validate_tree_checks_release_json_against_manifest(tmp_path):
    make_tree(tmp_path / "src", "0.2.0")
    i = package.build(tmp_path / "src", tmp_path / "a.tar.zst", {"version": "0.2.0", "db_schema": 1})
    package.unpack(tmp_path / "a.tar.zst", tmp_path / "out", i["unpacked_size"])
    with pytest.raises(PackageError):
        package.validate_tree(tmp_path / "out", "0.3.0", 1)
    with pytest.raises(PackageError):
        package.validate_tree(tmp_path / "out", "0.2.0", 2)


def test_signature_roundtrip_and_tampering():
    seed, pub = crypto.generate_keypair()
    key = crypto.load_public_key(pub)
    keys = {crypto.key_id(key): key}
    sig = crypto.sign(b"data", seed)
    assert crypto.verify(b"data", sig, keys) == crypto.key_id(key)
    for bad in (b"datb", b""):
        with pytest.raises(crypto.SignatureError):
            crypto.verify(bad, sig, keys)
    with pytest.raises(crypto.SignatureError):
        crypto.verify(b"data", "not base64!!", keys)
    with pytest.raises(crypto.SignatureError):
        crypto.verify(b"data", sig, {})


def test_manifest_validation():
    base = {"format": 1, "version": "0.2.0", "channel": "stable", "released": "x", "min_version": "0.1.0", "db_schema": 1, "api": 1,
            "os_codename": "trixie", "arch": "arm64",
            "package": {"file": "PiOS-NOVA-update-0.2.0.tar.zst", "size": 5, "sha256": "a" * 64, "unpacked_size": 9}}
    import json, copy
    assert mf.parse(json.dumps(base).encode()).version == "0.2.0"
    for mut in (lambda d: d.update(format=2), lambda d: d.update(channel="nightly"), lambda d: d["package"].update(sha256="zz"),
                lambda d: d["package"].update(file="../x.tar.zst"), lambda d: d.update(version="0.2.0-beta.1"), lambda d: d.update(api=99),
                lambda d: d.update(version="0.3.0"), lambda d: d.pop("db_schema")):
        d = copy.deepcopy(base); mut(d)
        with pytest.raises(mf.ManifestError):
            mf.parse(json.dumps(d).encode())
    with pytest.raises(mf.ManifestError):
        mf.parse(b"not json")
    d = copy.deepcopy(base); d.update(version="0.2.0-beta.1", channel="stable"); d["package"]["file"] = "PiOS-NOVA-update-0.2.0-beta.1.tar.zst"
    with pytest.raises(mf.ManifestError, match="Vorabversion"):
        mf.parse(json.dumps(d).encode())


def test_version_ordering():
    order = ["0.1.0", "0.2.0-beta.1", "0.2.0-beta.2", "0.2.0-beta.10", "0.2.0", "0.10.0", "1.0.0"]
    assert sorted(order, key=Version, reverse=True)[::-1] == order
    for bad in ("1", "1.0", "v1.0.0", "01.0.0", "1.0.0+x", ""):
        with pytest.raises(ValueError):
            Version(bad)
