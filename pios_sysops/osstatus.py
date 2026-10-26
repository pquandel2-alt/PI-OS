"""OS (Debian/APT) security-update monitoring: parsers + the two jobs run by pios-os-check/-upgrade.service.
Both jobs hold /run/pios-pkg.lock, the same lock the PiOS Update Manager takes while installing, so APT and the OTA
installer never run package operations at the same time."""
import fcntl
import json
import os
import re
import subprocess
import time
from pathlib import Path

STATE = Path(os.getenv("PIOS_SYSOPS_STATE", "/var/lib/pios-sysops"))
LOCK = "/run/pios-pkg.lock"
SIGNATURE_PROBLEMS = re.compile(r"NO_PUBKEY|EXPKEYSIG|BADSIG|KEYEXPIRED|REVKEYSIG|is not signed|not signed\.|signatures were invalid|GPG error", re.I)
INSECURE_SOURCE = re.compile(r"trusted\s*=\s*yes|allow-insecure\s*=\s*yes|allow-downgrade-to-insecure\s*=\s*yes", re.I)
INSECURE_CONF = re.compile(r"AllowInsecureRepositories|AllowUnauthenticated|AllowDowngradeToInsecureRepositories", re.I)


def parse_upgradable(text: str) -> list[dict]:
    """`apt list --upgradable` -> [{name, new, current}]"""
    out = []
    for line in text.splitlines():
        m = re.match(r"^([^/\s]+)/(\S+)\s+(\S+)\s+\S+\s+\[upgradable from: (\S+)\]", line)
        if m:
            out.append({"name": m.group(1), "origin": m.group(2), "new": m.group(3), "current": m.group(4)})
    return out


def parse_unattended(text: str) -> dict:
    """unattended-upgrade [--dry-run] -v output -> {candidates|upgraded: [...], error: str}"""
    res = {"packages": [], "error": ""}
    m = re.search(r"Packages that (?:will be|were) upgraded: (.*)", text)
    if m:
        res["packages"] = m.group(1).split()
    if re.search(r"(An error occurred|Installing the upgrades failed|dpkg returned an error|E: )", text):
        res["error"] = next((l.strip() for l in text.splitlines() if re.search(r"(error|E: |failed)", l, re.I)), "Fehler beim Installieren")[:300]
    return res


def source_problems(sources_text: str, conf_text: str) -> list[str]:
    p = []
    if INSECURE_SOURCE.search(sources_text):
        p.append("Eine APT-Quelle ist als trusted=yes/allow-insecure markiert: Paketsignaturen werden nicht geprüft")
    if INSECURE_CONF.search(conf_text):
        p.append("APT ist so konfiguriert, dass unsignierte Repositories erlaubt sind")
    return p


def read_apt_config() -> tuple[str, str]:
    src, conf = [], []
    for d in (Path("/etc/apt/sources.list"), *sorted(Path("/etc/apt/sources.list.d").glob("*"))):
        try:
            src.append(d.read_text())
        except OSError:
            pass
    for d in sorted(Path("/etc/apt/apt.conf.d").glob("*")):
        try:
            conf.append(d.read_text())
        except OSError:
            pass
    return "\n".join(src), "\n".join(conf)


def _write(name: str, data: dict):
    STATE.mkdir(parents=True, exist_ok=True)
    tmp = STATE / (name + ".tmp")
    tmp.write_text(json.dumps(data, indent=1))
    os.chmod(tmp, 0o644)
    os.replace(tmp, STATE / name)


def read(name: str) -> dict:
    try:
        return json.loads((STATE / name).read_text())
    except (OSError, ValueError):
        return {}


def _run(cmd, timeout=1500):
    env = {**os.environ, "LANG": "C", "LC_ALL": "C", "DEBIAN_FRONTEND": "noninteractive"}
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def job_check():
    """apt-get update (verifies repository signatures) + what would be installed automatically."""
    now = int(time.time())
    st = {"checked_at": now, "ok": False, "error": "", "signature_ok": None, "upgradable": [], "security": [], "reboot_required": os.path.exists("/run/reboot-required")}
    rc, out = _run(["apt-get", "update", "-q"], 600)
    sig_problem = bool(SIGNATURE_PROBLEMS.search(out))
    st["signature_ok"] = not sig_problem and rc == 0
    if rc != 0:
        st["error"] = ("Signaturprüfung der Paketquellen fehlgeschlagen: " if sig_problem else "apt-get update fehlgeschlagen: ") + out.strip().splitlines()[-1][:250] if out.strip() else "apt-get update fehlgeschlagen"
    else:
        _, listing = _run(["apt", "list", "--upgradable"], 120)
        st["upgradable"] = parse_upgradable(listing)
        _, ua = _run(["unattended-upgrade", "--dry-run", "-v"], 600)
        st["security"] = parse_unattended(ua)["packages"]
        st["ok"] = True
    src, conf = read_apt_config()
    st["source_problems"] = source_problems(src, conf)
    _write("os-status.json", st)
    return st


def job_upgrade():
    now = int(time.time())
    rc, out = _run(["unattended-upgrade", "-v"], 3000)
    parsed = parse_unattended(out)
    res = {"time": now, "ok": rc == 0 and not parsed["error"], "upgraded": parsed["packages"], "error": parsed["error"] or ("" if rc == 0 else f"unattended-upgrade endete mit Code {rc}")}
    _write("os-upgrade.json", res)
    job_check()                                  # refresh the picture after installing
    return res


def with_lock(fn):
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)           # wait for a running OTA installation / other package operation
        return fn()
    finally:
        os.close(fd)


if __name__ == "__main__":
    import sys
    which = sys.argv[1] if len(sys.argv) > 1 else ""
    if which == "check":
        with_lock(job_check)
    elif which == "upgrade":
        with_lock(job_upgrade)
    else:
        sys.exit("usage: osstatus (check|upgrade)")
