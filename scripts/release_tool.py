#!/usr/bin/env python3
"""Release tooling for OTA packages. Used by CI (and locally for tests); never runs on the device.

  keygen   <outdir>                      create an Ed25519 key pair (private seed is written ONLY to <outdir>/private.key, mode 0600)
  package  --version V --channel C --out DIR   build tar.zst + unsigned manifest
  sign     --manifest FILE               sign using the seed in $PIOS_UPDATE_SIGNING_KEY (never printed)
  verify   --manifest FILE --sig FILE --package FILE   verify signature (repo public key), checksum and package contents
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pios_updater import manifest as mf, package                 # noqa: E402
from pios_updater.version import Version                         # noqa: E402

PUBKEY = ROOT / "image/overlay/usr/share/pios/update-keys/pios-release-1.pub"
GATE = ROOT / "release/hardware-validation.json"


def source_version() -> str:
    m = re.search(r'^__version__ = "(.+)"', (ROOT / "pios/__init__.py").read_text(), re.M)
    return m.group(1)


def db_schema() -> int:
    return int(re.search(r"^DB_SCHEMA = (\d+)", (ROOT / "pios/__init__.py").read_text(), re.M).group(1))


def check_channel_gate(version: str, channel: str):
    """Stable requires a recorded real-hardware validation of exactly this minor line. CI results alone never qualify."""
    v = Version(version)
    if channel == "stable":
        if v.is_prerelease:
            sys.exit("Eine Vorabversion kann nicht als stable veröffentlicht werden")
        gate = json.loads(GATE.read_text()) if GATE.exists() else {}
        ok = gate.get("validated") is True and gate.get("hardware") and Version(gate.get("version", "0.0.0")).core[:2] == v.core[:2]
        if not ok:
            sys.exit("stable ist gesperrt: release/hardware-validation.json enthält keine Hardware-Validierung für diese Version "
                     "(Tests in CI reichen nicht). Veröffentliche als beta.")
    elif channel == "beta":
        pass
    else:
        sys.exit("Kanal muss stable oder beta sein")


def cmd_keygen(a):
    from pios_updater import crypto
    out = Path(a.outdir); out.mkdir(parents=True, exist_ok=True)
    seed, pub = crypto.generate_keypair()
    fd = os.open(out / "private.key", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(seed + "\n")
    (out / "public.pub").write_text("# PiOS NOVA release signing key (Ed25519)\n" + pub + "\n")
    print(f"public key: {out / 'public.pub'}\nprivate key: {out / 'private.key'} (keep secret, never commit)")


def cmd_package(a):
    version = a.version or source_version()
    if version != source_version():
        sys.exit(f"Version {version} stimmt nicht mit pios/__init__.py ({source_version()}) überein")
    check_channel_gate(version, a.channel)
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    pkg = out / f"PiOS-NOVA-update-{version}.tar.zst"
    epoch = int(os.getenv("SOURCE_DATE_EPOCH", "0"))
    info = package.build(ROOT, pkg, {"version": version, "db_schema": db_schema(), "api": 1}, epoch)
    notes = Path(a.notes).read_text() if a.notes else ""
    m = {"format": 1, "version": version, "channel": a.channel, "released": a.released or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
         "min_version": a.min_version, "db_schema": db_schema(), "api": 1, "os_codename": "trixie", "arch": "arm64",
         "notes": notes, "highlights": a.highlight or [],
         "package": {"file": pkg.name, "size": info["size"], "sha256": info["sha256"], "unpacked_size": info["unpacked_size"]}}
    mp = out / f"PiOS-NOVA-update-{version}.manifest.json"
    mp.write_bytes(json.dumps(m, indent=2, sort_keys=True).encode() + b"\n")
    mf.parse(mp.read_bytes())            # must satisfy the device's strict parser
    print(f"package {pkg.name} {info['size']} bytes sha256 {info['sha256']}")


def cmd_sign(a):
    from pios_updater import crypto
    seed = os.environ.get("PIOS_UPDATE_SIGNING_KEY", "").strip()
    if not seed:
        sys.exit("PIOS_UPDATE_SIGNING_KEY ist nicht gesetzt")
    mp = Path(a.manifest)
    try:
        sig = crypto.sign(mp.read_bytes(), seed)
    except Exception:
        sys.exit("Signieren fehlgeschlagen (Schlüsselformat?)")      # never include key material in messages
    Path(str(mp) + ".sig").write_text(sig + "\n")
    print(f"signed {mp.name}")


def cmd_verify(a):
    from pios_updater import crypto
    keys = {}
    pub = Path(a.pubkey) if a.pubkey else PUBKEY
    k = crypto.load_public_key(pub.read_text()); keys[crypto.key_id(k)] = k
    raw = Path(a.manifest).read_bytes()
    kid = crypto.verify(raw, Path(a.sig).read_text(), keys)
    m = mf.parse(raw)
    pkg = Path(a.package)
    if pkg.stat().st_size != m.size or package.sha256_file(pkg) != m.sha256:
        sys.exit("Paket passt nicht zum Manifest")
    with tempfile.TemporaryDirectory() as t:
        package.unpack(pkg, Path(t) / "r", m.unpacked_size)
        package.validate_tree(Path(t) / "r", m.version, m.db_schema)
    print(f"OK: {m.version} ({m.channel}) signed by key {kid}")


def cmd_stage(a):
    """Image build: produce the release tree exactly as an OTA package would unpack (same code path, no cryptography needed)."""
    version = source_version()
    with tempfile.TemporaryDirectory() as t:
        pkg = Path(t) / "p.tar.zst"
        info = package.build(ROOT, pkg, {"version": version, "db_schema": db_schema(), "api": 1})
        package.unpack(pkg, Path(a.dest), info["unpacked_size"])
        package.validate_tree(Path(a.dest), version, db_schema())
    print(f"staged release {version} in {a.dest}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("keygen"); p.add_argument("outdir"); p.set_defaults(fn=cmd_keygen)
    p = sub.add_parser("package"); p.add_argument("--version"); p.add_argument("--channel", required=True); p.add_argument("--out", required=True)
    p.add_argument("--min-version", default="0.2.0"); p.add_argument("--notes"); p.add_argument("--released"); p.add_argument("--highlight", action="append")
    p.set_defaults(fn=cmd_package)
    p = sub.add_parser("stage"); p.add_argument("--dest", required=True); p.set_defaults(fn=cmd_stage)
    p = sub.add_parser("sign"); p.add_argument("--manifest", required=True); p.set_defaults(fn=cmd_sign)
    p = sub.add_parser("verify"); p.add_argument("--manifest", required=True); p.add_argument("--sig", required=True)
    p.add_argument("--package", required=True); p.add_argument("--pubkey"); p.set_defaults(fn=cmd_verify)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
