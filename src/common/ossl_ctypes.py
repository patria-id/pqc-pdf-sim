"""Thin ctypes binding to an OpenSSL >= 3.5 libcrypto (EVP API only).

No cryptography is implemented here: every operation is a call into libcrypto.
The same call path (EVP_DigestSign / EVP_DigestVerify) is used for RSA,
ML-DSA and SLH-DSA, so all algorithms are measured through one backend.
RSA uses PKCS#1 v1.5 with SHA-256 (OpenSSL default padding); ML-DSA and
SLH-DSA are "pure" signatures (digest name NULL, empty context string).
"""
from __future__ import annotations

import ctypes as ct
import os
import re
from pathlib import Path

_vp = ct.c_void_p
_cp = ct.c_char_p
_sz = ct.c_size_t


class OpenSSLError(RuntimeError):
    """Raised when a libcrypto call fails."""


def digest_name_for(alg: str) -> bytes | None:
    """Digest passed to EVP_DigestSignInit_ex: SHA-256 for RSA, NULL for pure PQC signatures."""
    return b"SHA256" if alg.upper().startswith("RSA-") else None


def keygen_spec(alg: str) -> tuple[bytes, int | None]:
    """OpenSSL key type name and (for RSA) the modulus size."""
    m = re.fullmatch(r"RSA-(\d+)", alg, re.I)
    if m:
        return b"RSA", int(m.group(1))
    return alg.encode(), None


class PKey:
    """Owned EVP_PKEY* handle (freed on garbage collection)."""

    __slots__ = ("_lib", "ptr", "alg", "max_sig")

    def __init__(self, lib: "LibCrypto", ptr: int, alg: str) -> None:
        self._lib, self.ptr, self.alg = lib, ptr, alg
        self.max_sig = lib._c.EVP_PKEY_get_size(ptr)

    def __del__(self) -> None:
        if getattr(self, "ptr", None):
            self._lib._c.EVP_PKEY_free(self.ptr)
            self.ptr = None


class LibCrypto:
    """Loaded libcrypto with typed EVP functions."""

    def __init__(self, dll_path: str | Path) -> None:
        p = Path(dll_path).resolve()
        if not p.exists():
            raise FileNotFoundError(p)
        if hasattr(os, "add_dll_directory"):
            self._dll_dir = os.add_dll_directory(str(p.parent))
        self.path = str(p)
        self._c = ct.CDLL(self.path)
        self._declare()

    def _fn(self, name: str, restype: object, argtypes: list[object]) -> None:
        f = getattr(self._c, name)
        f.restype, f.argtypes = restype, argtypes

    def _declare(self) -> None:
        f = self._fn
        f("OpenSSL_version", _cp, [ct.c_int])
        f("ERR_get_error", ct.c_ulong, [])
        f("ERR_error_string_n", None, [ct.c_ulong, _cp, _sz])
        f("EVP_PKEY_CTX_new_from_name", _vp, [_vp, _cp, _cp])
        f("EVP_PKEY_CTX_free", None, [_vp])
        f("EVP_PKEY_keygen_init", ct.c_int, [_vp])
        f("EVP_PKEY_CTX_set_rsa_keygen_bits", ct.c_int, [_vp, ct.c_int])
        f("EVP_PKEY_generate", ct.c_int, [_vp, ct.POINTER(_vp)])
        f("EVP_PKEY_free", None, [_vp])
        f("EVP_PKEY_get_size", ct.c_int, [_vp])
        f("EVP_PKEY_get_raw_public_key", ct.c_int, [_vp, _vp, ct.POINTER(_sz)])
        f("EVP_MD_CTX_new", _vp, [])
        f("EVP_MD_CTX_free", None, [_vp])
        f("EVP_DigestSignInit_ex", ct.c_int, [_vp, _vp, _cp, _vp, _cp, _vp, _vp])
        f("EVP_DigestSign", ct.c_int, [_vp, _vp, ct.POINTER(_sz), _cp, _sz])
        f("EVP_DigestVerifyInit_ex", ct.c_int, [_vp, _vp, _cp, _vp, _cp, _vp, _vp])
        f("EVP_DigestVerify", ct.c_int, [_vp, _cp, _sz, _cp, _sz])
        f("i2d_PUBKEY", ct.c_int, [_vp, ct.POINTER(_vp)])
        f("d2i_PUBKEY", _vp, [_vp, ct.POINTER(_vp), ct.c_long])
        f("BIO_new_mem_buf", _vp, [_cp, ct.c_int])
        f("BIO_free", ct.c_int, [_vp])
        f("PEM_read_bio_PrivateKey", _vp, [_vp, _vp, _vp, _vp])

    # ------------------------------------------------------------------ utils
    def version(self) -> str:
        """OpenSSL version string of this library."""
        return self._c.OpenSSL_version(0).decode()

    def _err(self, what: str) -> OpenSSLError:
        msgs = []
        while (code := self._c.ERR_get_error()) != 0:
            buf = ct.create_string_buffer(256)
            self._c.ERR_error_string_n(code, buf, 256)
            msgs.append(buf.value.decode(errors="replace"))
        return OpenSSLError(f"{what} gagal: {'; '.join(msgs) or 'tanpa detail'}")

    # ------------------------------------------------------------------ keys
    def generate(self, alg: str) -> PKey:
        """Generate a key pair for `alg` (e.g. 'RSA-2048', 'ML-DSA-44', 'SLH-DSA-SHA2-128f')."""
        name, bits = keygen_spec(alg)
        c = self._c
        ctx = c.EVP_PKEY_CTX_new_from_name(None, name, None)
        if not ctx:
            raise self._err(f"EVP_PKEY_CTX_new_from_name({alg})")
        try:
            if c.EVP_PKEY_keygen_init(ctx) <= 0:
                raise self._err("EVP_PKEY_keygen_init")
            if bits is not None and c.EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0:
                raise self._err("EVP_PKEY_CTX_set_rsa_keygen_bits")
            out = _vp()
            if c.EVP_PKEY_generate(ctx, ct.byref(out)) <= 0:
                raise self._err("EVP_PKEY_generate")
            return PKey(self, out.value, alg)
        finally:
            c.EVP_PKEY_CTX_free(ctx)

    def load_private_pem(self, pem: bytes, alg: str) -> PKey:
        """Load an unencrypted PEM private key."""
        bio = self._c.BIO_new_mem_buf(pem, len(pem))
        try:
            ptr = self._c.PEM_read_bio_PrivateKey(bio, None, None, None)
        finally:
            self._c.BIO_free(bio)
        if not ptr:
            raise self._err("PEM_read_bio_PrivateKey")
        return PKey(self, ptr, alg)

    def public_spki(self, key: PKey) -> bytes:
        """DER SubjectPublicKeyInfo of a key."""
        n = self._c.i2d_PUBKEY(key.ptr, None)
        if n <= 0:
            raise self._err("i2d_PUBKEY")
        buf = ct.create_string_buffer(n)
        pp = _vp(ct.addressof(buf))
        self._c.i2d_PUBKEY(key.ptr, ct.byref(pp))
        return buf.raw

    def public_raw(self, key: PKey) -> bytes:
        """Raw public key bytes (PQC); falls back to SPKI DER when not available (RSA)."""
        n = _sz(0)
        if self._c.EVP_PKEY_get_raw_public_key(key.ptr, None, ct.byref(n)) <= 0:
            self._err("EVP_PKEY_get_raw_public_key")  # drain error queue
            return self.public_spki(key)
        buf = ct.create_string_buffer(n.value)
        self._c.EVP_PKEY_get_raw_public_key(key.ptr, buf, ct.byref(n))
        return buf.raw[: n.value]

    def load_spki(self, spki_der: bytes, alg: str) -> PKey:
        """Load a public key from DER SubjectPublicKeyInfo."""
        buf = ct.create_string_buffer(spki_der, len(spki_der))
        pp = _vp(ct.addressof(buf))
        ptr = self._c.d2i_PUBKEY(None, ct.byref(pp), len(spki_der))
        if not ptr:
            raise self._err("d2i_PUBKEY")
        return PKey(self, ptr, alg)

    # ------------------------------------------------------------------ sign / verify
    def sign(self, key: PKey, data: bytes) -> bytes:
        """One-shot EVP_DigestSign over `data`."""
        c = self._c
        md = c.EVP_MD_CTX_new()
        try:
            if c.EVP_DigestSignInit_ex(md, None, digest_name_for(key.alg), None, None, key.ptr, None) <= 0:
                raise self._err("EVP_DigestSignInit_ex")
            siglen = _sz(key.max_sig)
            sig = ct.create_string_buffer(key.max_sig)
            if c.EVP_DigestSign(md, sig, ct.byref(siglen), data, len(data)) <= 0:
                raise self._err("EVP_DigestSign")
            return sig.raw[: siglen.value]
        finally:
            c.EVP_MD_CTX_free(md)

    def verify(self, key: PKey, signature: bytes, data: bytes) -> bool:
        """One-shot EVP_DigestVerify; True only for a valid signature."""
        c = self._c
        md = c.EVP_MD_CTX_new()
        try:
            if c.EVP_DigestVerifyInit_ex(md, None, digest_name_for(key.alg), None, None, key.ptr, None) <= 0:
                raise self._err("EVP_DigestVerifyInit_ex")
            ok = c.EVP_DigestVerify(md, signature, len(signature), data, len(data)) == 1
            if not ok:
                self._err("EVP_DigestVerify")  # drain error queue
            return ok
        finally:
            c.EVP_MD_CTX_free(md)
