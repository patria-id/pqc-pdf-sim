"""Detached CMS SignedData (RFC 5652) assembled with asn1crypto.

The signature over DER(signedAttrs) is produced by a signature backend, so the
same code path serves RSA (PKCS#1 v1.5 + SHA-256), ML-DSA (RFC 9882) and
SLH-DSA (RFC 9814). signedAttrs = contentType, messageDigest, signingTime
(SPEC 4.4). Signature algorithm parameters are absent for PQC; for RSA the
OID is sha256WithRSAEncryption.
"""
from __future__ import annotations

import datetime as dt
import hashlib
from dataclasses import dataclass
from typing import Any, Callable

from asn1crypto import algos, cms
from asn1crypto import x509 as ax509

from src.common.oids import sig_oid
from src.common.x509util import same_name


@dataclass
class SignerContext:
    """Everything needed to produce SignedData for one signer, prepared once (outside timing)."""

    alg: str                                  # e.g. 'ML-DSA-44'
    sign: Callable[[bytes], bytes]            # signs DER(signedAttrs)
    signer_cert: ax509.Certificate
    chain: list[ax509.Certificate]            # extra certificates to embed (e.g. the CA)

    @classmethod
    def from_der(cls, alg: str, sign: Callable[[bytes], bytes], signer_der: bytes,
                 chain_der: list[bytes]) -> "SignerContext":
        """Build from DER certificates."""
        return cls(alg, sign, ax509.Certificate.load(signer_der), [ax509.Certificate.load(d) for d in chain_der])


def signed_attributes(digest: bytes, signing_time: dt.datetime) -> cms.CMSAttributes:
    """contentType=data, messageDigest, signingTime (UTCTime)."""
    return cms.CMSAttributes([
        cms.CMSAttribute({"type": "content_type", "values": ["data"]}),
        cms.CMSAttribute({"type": "message_digest", "values": [digest]}),
        cms.CMSAttribute({"type": "signing_time", "values": [cms.Time({"utc_time": signing_time})]}),
    ])


def build_signed_data_from_digest(digest: bytes, ctx: SignerContext,
                                  signing_time: dt.datetime | None = None) -> bytes:
    """Detached SignedData over a precomputed SHA-256 `digest`; returns DER ContentInfo."""
    attrs = signed_attributes(digest, signing_time or dt.datetime.now(dt.timezone.utc))
    signature = ctx.sign(attrs.dump())  # universal SET OF encoding is what gets signed
    digest_alg = algos.DigestAlgorithm({"algorithm": "sha256"})
    signer_info = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({"issuer_and_serial_number": cms.IssuerAndSerialNumber(
            {"issuer": ctx.signer_cert.issuer, "serial_number": ctx.signer_cert.serial_number})}),
        "digest_algorithm": digest_alg,
        "signed_attrs": attrs,
        "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": sig_oid(ctx.alg)}),
        "signature": signature,
    })
    signed_data = cms.SignedData({
        "version": "v1",
        "digest_algorithms": [digest_alg],
        "encap_content_info": {"content_type": "data"},
        "certificates": [ctx.signer_cert, *ctx.chain],
        "signer_infos": [signer_info],
    })
    return cms.ContentInfo({"content_type": "signed_data", "content": signed_data}).dump()


def build_cms_asn1(data: bytes, alg: str, backend: Any, key: Any,
                   signer_der: bytes, chain_der: list[bytes]) -> bytes:
    """Convenience wrapper: SignedData over SHA-256(`data`) signed with `backend`/`key`."""
    ctx = SignerContext.from_der(alg, lambda m: backend.sign(key, m), signer_der, chain_der)
    return build_signed_data_from_digest(hashlib.sha256(data).digest(), ctx)


def verify_cms_digest(cms_der: bytes, digest: bytes,
                      verify_with_cert: Callable[[bytes, bytes, bytes], bool] | None) -> dict[str, Any]:
    """Parse detached CMS, compare messageDigest with `digest`, optionally verify the signature.

    `verify_with_cert(signer_cert_der, signature, signed_attrs_der)` checks the signature.
    """
    ci = cms.ContentInfo.load(cms_der)
    sd = ci["content"]
    si = sd["signer_infos"][0]
    attrs = {a["type"].native: a["values"][0].native for a in si["signed_attrs"]}
    digest_ok = attrs.get("message_digest") == digest
    content_type_ok = attrs.get("content_type") == "data"
    sid = si["sid"].chosen
    signer = next(c.chosen for c in sd["certificates"]
                  if c.chosen.serial_number == sid["serial_number"].native
                  and same_name(c.chosen.issuer, sid["issuer"]))
    out: dict[str, Any] = {"digest_ok": digest_ok, "content_type_ok": content_type_ok,
                           "digest_alg": si["digest_algorithm"]["algorithm"].dotted,
                           "signature_alg": si["signature_algorithm"]["algorithm"].dotted,
                           "signed_attrs": sorted(attrs),
                           "signature_bytes": len(si["signature"].native),
                           "signing_time": attrs.get("signing_time"),
                           "signer_cert_der": signer.dump(),
                           "certs_der": [c.chosen.dump() for c in sd["certificates"]]}
    sig_ok = None
    if verify_with_cert is not None:
        attrs_der = si["signed_attrs"].dump()
        attrs_der = b"\x31" + attrs_der[1:]  # [0] IMPLICIT -> universal SET OF for verification
        sig_ok = verify_with_cert(out["signer_cert_der"], si["signature"].native, attrs_der)
    out["signature_ok"] = sig_ok
    out["valid"] = digest_ok and content_type_ok and sig_ok is not False
    return out


def der_length(buf: bytes) -> int:
    """Total length (header + content) of the DER element at the start of `buf` (ignores padding after it)."""
    if len(buf) < 2:
        raise ValueError("DER terlalu pendek")
    first = buf[1]
    if first < 0x80:
        return 2 + first
    n = first & 0x7F
    if n == 0 or n > 4 or len(buf) < 2 + n:
        raise ValueError("panjang DER tidak didukung")
    return 2 + n + int.from_bytes(buf[2:2 + n], "big")


def cms_certificates(cms_der: bytes) -> tuple[bytes, list[bytes]]:
    """(signer certificate DER, all embedded certificates DER) of a SignedData."""
    sd = cms.ContentInfo.load(cms_der)["content"]
    sid = sd["signer_infos"][0]["sid"].chosen
    certs = [c.chosen for c in sd["certificates"]]
    signer = next(c for c in certs
                  if c.serial_number == sid["serial_number"].native and same_name(c.issuer, sid["issuer"]))
    return signer.dump(), [c.dump() for c in certs]


def verify_cms_asn1(cms_der: bytes, data: bytes,
                    verify_with_cert: Callable[[bytes, bytes, bytes], bool] | None) -> dict[str, Any]:
    """Like `verify_cms_digest` but hashes `data` with SHA-256 first."""
    return verify_cms_digest(cms_der, hashlib.sha256(data).digest(), verify_with_cert)
