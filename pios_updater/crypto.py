"""Ed25519 verification of signed manifests with a set of trusted public keys."""
import base64
import hashlib
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class SignatureError(Exception):
    pass


def key_id(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def load_public_key(text: str) -> Ed25519PublicKey:
    """Public key file: 'pios-update-key-v1 <base64 raw 32 bytes>' (comment lines start with #)."""
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            kind, _, b64 = line.partition(" ")
            if kind != "pios-update-key-v1":
                raise ValueError("unbekanntes Schlüsselformat")
            raw = base64.b64decode(b64.strip(), validate=True)
            return Ed25519PublicKey.from_public_bytes(raw)
    raise ValueError("kein Schlüssel gefunden")


def load_trusted_keys(directory: Path) -> dict[str, Ed25519PublicKey]:
    keys = {}
    for p in sorted(Path(directory).glob("*.pub")):
        k = load_public_key(p.read_text())
        keys[key_id(k)] = k
    return keys


def verify(data: bytes, signature_b64: str, keys: dict[str, Ed25519PublicKey]) -> str:
    """Return the key id that signed `data`; raise SignatureError otherwise."""
    try:
        sig = base64.b64decode(signature_b64.strip(), validate=True)
    except Exception:
        raise SignatureError("Signatur ist kein gültiges Base64") from None
    if not keys:
        raise SignatureError("Kein vertrauenswürdiger Schlüssel installiert")
    for kid, key in keys.items():
        try:
            key.verify(sig, data)
            return kid
        except InvalidSignature:
            continue
    raise SignatureError("Signatur ungültig")


# --- used by the release tooling (never by the device) ---
def generate_keypair() -> tuple[str, str]:
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(seed).decode(), "pios-update-key-v1 " + base64.b64encode(pub).decode()


def sign(data: bytes, seed_b64: str) -> str:
    priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(seed_b64.strip(), validate=True))
    return base64.b64encode(priv.sign(data)).decode()
