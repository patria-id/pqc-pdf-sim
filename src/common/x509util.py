"""X.509 parsing helpers (asn1crypto) that do not depend on a signature backend."""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from asn1crypto import pem
from asn1crypto import x509 as ax509


def read_der(path: Path) -> bytes:
    """Read a PEM or DER certificate file and return DER bytes."""
    data = path.read_bytes()
    return pem.unarmor(data)[2] if pem.detect(data) else data


def spki_of(cert_der: bytes) -> bytes:
    """DER SubjectPublicKeyInfo of a DER certificate."""
    return ax509.Certificate.load(cert_der)["tbs_certificate"]["subject_public_key_info"].dump()


def same_name(a: ax509.Name, b: ax509.Name) -> bool:
    """Byte comparison of two DER-encoded Names.

    asn1crypto's ``Name ==`` applies RFC 4518 LDAP string preparation in pure Python
    (~0.5 ms per comparison), which would dominate the verification timing without
    being related to the signature algorithm. Like OpenSSL's ``X509_NAME_cmp`` (which
    compares cached canonical encodings), names are compared as encodings; all
    certificates here come from the same issuer software, so equal names have equal DER.
    """
    return a.dump() == b.dump()


def verify_issued_by(child_der: bytes, issuer_der: bytes,
                     verify_spki: Callable[[bytes, bytes, bytes], bool]) -> bool:
    """Check the issuer's signature over the child's TBSCertificate (and issuer/subject names)."""
    child = ax509.Certificate.load(child_der)
    issuer = ax509.Certificate.load(issuer_der)
    if not same_name(child.issuer, issuer.subject):
        return False
    return verify_spki(spki_of(issuer_der), child["signature_value"].native, child["tbs_certificate"].dump())
