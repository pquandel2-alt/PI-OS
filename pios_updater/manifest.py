"""Release manifest: the signed description of one OTA package."""
import json
import re
from dataclasses import dataclass, field

from . import UPDATER_API
from .version import Version

CHANNELS = ("stable", "beta")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_FILE = re.compile(r"^PiOS-NOVA-update-[0-9A-Za-z.\-]+\.tar\.zst$")
MAX_NOTES = 20000


class ManifestError(Exception):
    pass


@dataclass(frozen=True)
class Manifest:
    version: str
    channel: str
    released: str
    min_version: str          # oldest installed version that may update directly to this one
    db_schema: int            # database schema version this release expects
    api: int                  # minimum Update Manager API required
    os_codename: str          # e.g. "trixie"
    arch: str                 # "arm64"
    file: str
    size: int
    sha256: str
    unpacked_size: int
    notes: str = ""
    highlights: list = field(default_factory=list)
    key_id: str = ""

    @property
    def v(self) -> Version:
        return Version(self.version)

    def to_public(self) -> dict:
        return {k: getattr(self, k) for k in ("version", "channel", "released", "min_version", "file", "size", "notes", "highlights")}


def parse(raw: bytes) -> Manifest:
    """Strict parser. Call only after the signature has been verified."""
    try:
        d = json.loads(raw)
    except ValueError:
        raise ManifestError("Manifest ist kein gültiges JSON") from None
    if not isinstance(d, dict) or d.get("format") != 1:
        raise ManifestError("Unbekanntes Manifest-Format")
    try:
        pkg = d["package"]
        m = Manifest(
            version=d["version"], channel=d["channel"], released=d["released"], min_version=d["min_version"],
            db_schema=int(d["db_schema"]), api=int(d["api"]), os_codename=d["os_codename"], arch=d["arch"],
            file=pkg["file"], size=int(pkg["size"]), sha256=pkg["sha256"], unpacked_size=int(pkg["unpacked_size"]),
            notes=str(d.get("notes", ""))[:MAX_NOTES], highlights=[str(x)[:200] for x in d.get("highlights", [])][:12])
        Version(m.version); Version(m.min_version)
    except (KeyError, TypeError, ValueError) as e:
        raise ManifestError(f"Manifest unvollständig oder ungültig: {e}") from None
    if m.channel not in CHANNELS:
        raise ManifestError("Unbekannter Kanal")
    if not _SHA.match(m.sha256) or not _FILE.match(m.file) or m.size <= 0 or m.unpacked_size <= 0:
        raise ManifestError("Paketangaben ungültig")
    if m.file != f"PiOS-NOVA-update-{m.version}.tar.zst":
        raise ManifestError("Dateiname passt nicht zur Version")
    if m.v.is_prerelease and m.channel == "stable":
        raise ManifestError("Eine Vorabversion kann nicht im Stable-Kanal liegen")
    if m.api > UPDATER_API:
        raise ManifestError(f"Benötigt Update Manager API {m.api}")
    return m
