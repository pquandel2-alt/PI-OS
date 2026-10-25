"""Semantic versions: MAJOR.MINOR.PATCH[-prerelease.N] (no build metadata)."""
import re
from functools import total_ordering

_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*))?$")


@total_ordering
class Version:
    def __init__(self, text: str):
        m = _RE.match(text or "")
        if not m:
            raise ValueError(f"ungültige Version: {text!r}")
        self.text = text
        self.core = tuple(int(x) for x in m.groups()[:3])
        self.pre = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in m.group(4).split(".")) if m.group(4) else None

    @property
    def is_prerelease(self) -> bool:
        return self.pre is not None

    def _key(self):
        # a release sorts after any of its pre-releases
        return (self.core, 1 if self.pre is None else 0, self.pre or ())

    def __eq__(self, o):
        return isinstance(o, Version) and self._key() == o._key()

    def __lt__(self, o):
        return self._key() < o._key()

    def __hash__(self):
        return hash(self._key())

    def __str__(self):
        return self.text

    def __repr__(self):
        return f"Version({self.text!r})"


def valid(text: str) -> bool:
    try:
        Version(text)
        return True
    except ValueError:
        return False
