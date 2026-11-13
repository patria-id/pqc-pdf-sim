"""Small generic helpers."""
from __future__ import annotations

import importlib.metadata
import re


def parse_version(text: str) -> tuple[int, ...]:
    """Extract the first dotted version number from text, e.g. 'OpenSSL 3.2.4' -> (3, 2, 4)."""
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", text or "")
    return tuple(int(x) for x in m.groups(default="0")) if m else ()


def pkg_version(name: str) -> str | None:
    """Installed distribution version, or None."""
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def short_err(exc: BaseException) -> str:
    """One-line description of an exception."""
    return f"{type(exc).__name__}: {exc}".splitlines()[0][:300]


def rsa_bits(alg: str) -> int | None:
    """Modulus size for 'RSA-<bits>' names, else None."""
    m = re.fullmatch(r"RSA-(\d+)", alg, re.I)
    return int(m.group(1)) if m else None
