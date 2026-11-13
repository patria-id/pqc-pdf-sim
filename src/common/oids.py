"""Standard OIDs for signature algorithms used in X.509 and CMS.

ML-DSA: RFC 9881 (X.509) / RFC 9882 (CMS). SLH-DSA: RFC 9814 (CMS) / RFC 9909 (X.509).
All are NIST CSOR `sigAlgs` arcs, encoded with absent parameters.
"""
from __future__ import annotations

_NIST_SIGALGS = "2.16.840.1.101.3.4.3"

SIG_OIDS: dict[str, str] = {
    "ML-DSA-44": f"{_NIST_SIGALGS}.17",
    "ML-DSA-65": f"{_NIST_SIGALGS}.18",
    "ML-DSA-87": f"{_NIST_SIGALGS}.19",
    "SLH-DSA-SHA2-128s": f"{_NIST_SIGALGS}.20",
    "SLH-DSA-SHA2-128f": f"{_NIST_SIGALGS}.21",
    "SLH-DSA-SHA2-192s": f"{_NIST_SIGALGS}.22",
    "SLH-DSA-SHA2-192f": f"{_NIST_SIGALGS}.23",
    "SLH-DSA-SHA2-256s": f"{_NIST_SIGALGS}.24",
    "SLH-DSA-SHA2-256f": f"{_NIST_SIGALGS}.25",
    "SLH-DSA-SHAKE-128s": f"{_NIST_SIGALGS}.26",
    "SLH-DSA-SHAKE-128f": f"{_NIST_SIGALGS}.27",
    "SLH-DSA-SHAKE-192s": f"{_NIST_SIGALGS}.28",
    "SLH-DSA-SHAKE-192f": f"{_NIST_SIGALGS}.29",
    "SLH-DSA-SHAKE-256s": f"{_NIST_SIGALGS}.30",
    "SLH-DSA-SHAKE-256f": f"{_NIST_SIGALGS}.31",
}

RSA_PKCS1_SHA256_OID = "1.2.840.113549.1.1.11"


def sig_oid(alg_name: str) -> str:
    """Return the CMS/X.509 signatureAlgorithm OID for an algorithm name."""
    if alg_name.upper().startswith("RSA-"):
        return RSA_PKCS1_SHA256_OID
    return SIG_OIDS[alg_name]
