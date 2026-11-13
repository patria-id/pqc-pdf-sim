"""Signature backends behind one interface.

* ``openssl-ctypes``: libcrypto (OpenSSL >= 3.5) via ctypes; all algorithms (default).
* ``cryptography``: pyca/cryptography; RSA and ML-DSA (no SLH-DSA API).
* ``liboqs-python``: optional, only when the native liboqs library is installed.
"""
from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

from src.common.opensslcli import resolve_openssl_bin
from src.common.util import parse_version, pkg_version, rsa_bits, short_err

BACKEND_NAMES = ("openssl-ctypes", "cryptography", "liboqs-python")


@dataclass
class Backend:
    """In-process signature backend for one algorithm."""

    name: str
    version: str
    generate: Callable[[], Any]
    sign: Callable[[Any, bytes], bytes]
    verify: Callable[[Any, bytes, bytes], bool]
    public_bytes: Callable[[Any], bytes]          # raw PQC public key / SPKI DER for RSA
    verify_spki: Callable[[bytes, bytes, bytes], bool] | None  # (spki_der, sig, msg)
    load_private_pem: Callable[[bytes], Any] | None
    x509_native: bool  # key object usable with cryptography's X.509 builder


# --------------------------------------------------------------------------- discovery
def libcrypto_info(cfg_path: str | None, openssl_bin: str | None, min_ver: tuple[int, ...]) -> dict[str, Any]:
    """Locate and load libcrypto for the ctypes backend (explicit path, else next to the CLI)."""
    from src.common.ossl_ctypes import LibCrypto

    cand: Path | None = Path(cfg_path) if cfg_path else None
    cli_path = resolve_openssl_bin(openssl_bin) if openssl_bin else None
    if cand is None and cli_path:
        d = Path(cli_path).parent
        cand = next((p for p in (d / "libcrypto-3-x64.dll", d / "libcrypto.so.3", d / "libcrypto.3.dylib")
                     if p.exists()), None)
    info: dict[str, Any] = {"path": str(cand) if cand else None, "usable": False}
    if not cand:
        info["error"] = "libcrypto tidak ditemukan (set tools.libcrypto_path)"
        return info
    try:
        lib = LibCrypto(cand)
        ver = lib.version()
        info.update(version_text=ver, meets_min=parse_version(ver) >= min_ver)
        info["usable"] = info["meets_min"]
        info["_lib"] = lib
    except Exception as exc:  # noqa: BLE001
        info["error"] = short_err(exc)
    return info


def liboqs_info(install_path: str | None, timeout: int) -> dict[str, Any]:
    """Detect liboqs-python and the native liboqs library WITHOUT triggering its auto-build."""
    import importlib.util

    info: dict[str, Any] = {"python_package": pkg_version("liboqs-python"),
                            "module_found": importlib.util.find_spec("oqs") is not None,
                            "native_lib": None, "usable": False, "enabled_sigs": []}
    base = Path(install_path) if install_path else Path.home() / "_oqs"
    sub = "bin" if platform.system() == "Windows" else "lib"
    names = ["oqs.dll", "liboqs.dll"] if platform.system() == "Windows" else ["liboqs.so", "liboqs.dylib"]
    for cand in [base / sub / n for n in names] + ([base / "lib64" / names[0]] if sub == "lib" else []):
        if cand.exists():
            info["native_lib"] = str(cand)
            break
    if not info["module_found"]:
        info["note"] = "liboqs-python tidak terpasang"
        return info
    if not info["native_lib"]:
        info["note"] = ("pustaka native liboqs tidak ditemukan; `import oqs` akan mencoba build "
                        "otomatis (git+cmake+compiler), jadi tidak diimpor")
        return info
    env = dict(os.environ, OQS_INSTALL_PATH=str(base))
    code = "import json,oqs;print(json.dumps([oqs.oqs_version(),oqs.get_enabled_sig_mechanisms()]))"
    try:
        proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                              timeout=timeout, env=env, check=False)
        ver, sigs = json.loads(proc.stdout.strip().splitlines()[-1])
        info.update(usable=True, liboqs_version=ver, enabled_sigs=sigs)
    except Exception as exc:  # noqa: BLE001
        info["error"] = short_err(exc)
    return info


def liboqs_name(alg: str, enabled: list[str]) -> str | None:
    """Map a FIPS algorithm name to its liboqs identifier (FIPS 204/205 variants only)."""
    cands = [alg]
    if alg.upper().startswith("SLH-DSA-"):
        cands.append("SLH_DSA_PURE_" + alg[len("SLH-DSA-"):].upper().replace("-", "_"))
    return next((c for c in cands if c in enabled), None)


# --------------------------------------------------------------------------- factories
def cryptography_backend(alg: str) -> Backend:
    """Backend on top of `cryptography` (RSA PKCS#1 v1.5 + SHA-256, ML-DSA, SLH-DSA if exposed)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    ver = pkg_version("cryptography") or "?"
    der_spki = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    def _ok(fn: Callable[[], None]) -> bool:
        try:
            fn()
            return True
        except InvalidSignature:
            return False

    def _verify_pub(pub: Any, s: bytes, d: bytes) -> bool:
        if isinstance(pub, rsa.RSAPublicKey):
            return _ok(lambda: pub.verify(s, d, padding.PKCS1v15(), hashes.SHA256()))
        return _ok(lambda: pub.verify(s, d))

    def _verify_spki(spki: bytes, s: bytes, d: bytes) -> bool:
        return _verify_pub(serialization.load_der_public_key(spki), s, d)

    def _load_pem(pem: bytes) -> Any:
        return serialization.load_pem_private_key(pem, password=None)

    bits = rsa_bits(alg)
    if bits:
        return Backend(
            "cryptography", ver,
            generate=lambda: rsa.generate_private_key(public_exponent=65537, key_size=bits),
            sign=lambda k, d: k.sign(d, padding.PKCS1v15(), hashes.SHA256()),
            verify=lambda k, s, d: _verify_pub(k.public_key(), s, d),
            public_bytes=lambda k: k.public_key().public_bytes(*der_spki),
            verify_spki=_verify_spki, load_private_pem=_load_pem, x509_native=True,
        )
    m = re.fullmatch(r"ML-DSA-(\d+)", alg, re.I)
    if m:
        from cryptography.hazmat.primitives.asymmetric import mldsa

        cls = getattr(mldsa, f"MLDSA{m.group(1)}PrivateKey")
        return Backend(
            "cryptography", ver,
            generate=cls.generate,
            sign=lambda k, d: k.sign(d),
            verify=lambda k, s, d: _verify_pub(k.public_key(), s, d),
            public_bytes=lambda k: k.public_key().public_bytes_raw(),
            verify_spki=_verify_spki, load_private_pem=_load_pem, x509_native=True,
        )
    if alg.upper().startswith("SLH-DSA-"):
        try:
            from cryptography.hazmat.primitives.asymmetric import slhdsa  # type: ignore[attr-defined]
        except ImportError as exc:
            raise NotImplementedError(
                f"cryptography {ver} tidak menyediakan API SLH-DSA "
                "(hanya RSA/EC/EdDSA/ML-DSA/ML-KEM)") from exc
        cls_name = "SLHDSA" + alg[len("SLH-DSA-"):].replace("-", "").upper() + "PrivateKey"
        cls = getattr(slhdsa, cls_name, None)
        if cls is None:
            raise NotImplementedError(f"cryptography.slhdsa tidak punya {cls_name}")
        return Backend(
            "cryptography", ver, generate=cls.generate, sign=lambda k, d: k.sign(d),
            verify=lambda k, s, d: _verify_pub(k.public_key(), s, d),
            public_bytes=lambda k: k.public_key().public_bytes_raw(),
            verify_spki=_verify_spki, load_private_pem=_load_pem, x509_native=True,
        )
    raise NotImplementedError(f"algoritma tidak dikenal: {alg}")


def openssl_ctypes_backend(alg: str, lc_info: dict[str, Any]) -> Backend:
    """Backend calling libcrypto (OpenSSL >= 3.5) directly through ctypes."""
    if not lc_info.get("usable"):
        raise NotImplementedError(lc_info.get("error") or
                                  f"libcrypto {lc_info.get('version_text')} di bawah versi minimum")
    lib = lc_info["_lib"]
    return Backend(
        "openssl-ctypes", lib.version(),
        generate=lambda: lib.generate(alg),
        sign=lib.sign,
        verify=lib.verify,
        public_bytes=lib.public_raw,
        verify_spki=lambda spki, s, d: lib.verify(lib.load_spki(spki, alg), s, d),
        load_private_pem=lambda pem: lib.load_private_pem(pem, alg),
        x509_native=False,
    )


def liboqs_backend(alg: str, oqs_info: dict[str, Any]) -> Backend:
    """Backend on top of liboqs-python (only when the native library is present)."""
    if not oqs_info.get("usable"):
        raise NotImplementedError(oqs_info.get("note") or oqs_info.get("error") or "liboqs tidak tersedia")
    name = liboqs_name(alg, oqs_info["enabled_sigs"])
    if not name:
        raise NotImplementedError(f"{alg} tidak ada di daftar mekanisme liboqs")
    import oqs  # safe: native library was found above

    def gen() -> tuple[Any, bytes]:
        s = oqs.Signature(name)
        return s, s.generate_keypair()

    return Backend(
        "liboqs-python", f"{pkg_version('liboqs-python')} / liboqs {oqs_info.get('liboqs_version')}",
        generate=gen,
        sign=lambda k, d: k[0].sign(d),
        verify=lambda k, s, d: oqs.Signature(name).verify(d, s, k[1]),
        public_bytes=lambda k: k[1],
        verify_spki=None, load_private_pem=None, x509_native=False,
    )


def make_backend(label: str, alg: str, ctx: dict[str, Any]) -> Backend:
    """Instantiate backend `label` for `alg`; `ctx` holds 'libcrypto' / 'liboqs' discovery info."""
    if label == "cryptography":
        return cryptography_backend(alg)
    if label == "openssl-ctypes":
        return openssl_ctypes_backend(alg, ctx["libcrypto"])
    if label == "liboqs-python":
        return liboqs_backend(alg, ctx["liboqs"])
    raise ValueError(f"backend tidak dikenal: {label}")


# --------------------------------------------------------------------------- config-driven access
@lru_cache(maxsize=4)
def _libcrypto_cached(cfg_path: str | None, openssl_bin: str | None, min_ver: tuple[int, ...]) -> dict[str, Any]:
    return libcrypto_info(cfg_path, openssl_bin, min_ver)


def backend_context(cfg: dict[str, Any]) -> dict[str, Any]:
    """Discovery context for `make_backend`, built from config (libcrypto cached per process)."""
    tools = cfg.get("tools", {})
    min_ver = parse_version(str(cfg.get("env_check", {}).get("min_openssl", "3.5.0")))
    ctx: dict[str, Any] = {"libcrypto": _libcrypto_cached(tools.get("libcrypto_path"),
                                                          tools.get("openssl_bin"), min_ver)}
    if cfg.get("crypto_backend") == "liboqs-python":
        ctx["liboqs"] = liboqs_info(tools.get("liboqs_install_path"),
                                    int(tools.get("subprocess_timeout_s", 120)))
    else:
        ctx["liboqs"] = {"usable": False, "note": "tidak dipakai"}
    return ctx


def get_backend(cfg: dict[str, Any], alg: str) -> Backend:
    """The configured measurement backend (`crypto_backend`) for algorithm `alg`."""
    return make_backend(cfg.get("crypto_backend", "openssl-ctypes"), alg, backend_context(cfg))
