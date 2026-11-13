"""Smoke tests for Stage 0 (env_check) and the ctypes libcrypto backend."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from src.common import env_check
from src.common.backend import libcrypto_info, openssl_ctypes_backend
from src.common.opensslcli import openssl_cli_info
from src.common.pki import build_chain
from src.common.x509util import read_der, verify_issued_by
from src.common.config import load_config


@pytest.fixture(scope="module")
def cfg() -> dict:
    return load_config("config.yaml")


@pytest.fixture(scope="module")
def ctx(cfg: dict) -> dict:
    min_ver = env_check.parse_version(cfg["env_check"]["min_openssl"])
    names = ["RSA-2048", "ML-DSA-44", "ML-DSA-87", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s"]
    cli = openssl_cli_info(cfg["tools"]["openssl_bin"], names, min_ver, 60)
    lc = libcrypto_info(cfg["tools"].get("libcrypto_path"), cli.get("path"), min_ver)
    return {"cli": cli, "libcrypto": lc, "liboqs": {"usable": False}}




def test_parse_version() -> None:
    assert env_check.parse_version("OpenSSL 3.2.4 11 Feb 2025") == (3, 2, 4)
    assert env_check.parse_version("OpenSSL 4.0.3") >= (3, 5, 0)


def test_cryptography_backend_rsa_mldsa() -> None:
    for alg in ("RSA-2048", "ML-DSA-44"):
        be = env_check.cryptography_backend(alg)
        k = be.generate()
        sig = be.sign(k, b"x" * 32)
        assert be.verify(k, sig, b"x" * 32) and not be.verify(k, sig, b"y" * 32)


@pytest.mark.parametrize("alg", ["RSA-2048", "ML-DSA-44", "SLH-DSA-SHA2-128f"])
def test_openssl_ctypes_backend(alg: str, ctx: dict) -> None:
    if not ctx["libcrypto"].get("usable"):
        pytest.skip("libcrypto >= 3.5 tidak tersedia")
    rec, be = env_check.probe_algorithm(alg, ctx, "openssl-ctypes")
    assert be is not None and rec["selected_backend"] == "openssl-ctypes", rec


def test_asn1crypto_cms_fallback_cryptography(cfg: dict) -> None:
    from cryptography.hazmat.primitives.serialization import Encoding

    be_ca = env_check.cryptography_backend("ML-DSA-87")
    be = env_check.cryptography_backend("ML-DSA-44")
    ca_key, key = be_ca.generate(), be.generate()
    ca = env_check.make_cert("CA", ca_key.public_key(), "CA", ca_key, True, cfg)
    user = env_check.make_cert("U", key.public_key(), "CA", ca_key, False, cfg)
    data = os.urandom(1000)
    der = env_check.build_cms_asn1(data, "ML-DSA-44", be, key,
                                   user.public_bytes(Encoding.DER), [ca.public_bytes(Encoding.DER)])
    ok = env_check.verify_cms_asn1(der, data, env_check.cert_verifier(be))
    assert ok["valid"] and ok["signature_ok"]
    assert ok["signature_alg"] == "2.16.840.1.101.3.4.3.17"
    bad = env_check.verify_cms_asn1(der, data[:-1] + bytes([data[-1] ^ 1]), env_check.cert_verifier(be))
    assert not bad["valid"]


def test_asn1crypto_cms_fallback_slhdsa_ctypes(cfg: dict, ctx: dict) -> None:
    if not (ctx["libcrypto"].get("usable") and ctx["cli"].get("meets_min")):
        pytest.skip("OpenSSL >= 3.5 tidak tersedia")
    sub, ca = "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s"
    be = openssl_ctypes_backend(sub, ctx["libcrypto"])
    be_ca = openssl_ctypes_backend(ca, ctx["libcrypto"])
    with tempfile.TemporaryDirectory() as tmp:
        ch = build_chain(ctx["cli"]["path"], sub, ca, cfg, Path(tmp), 60, "CA", "U", 1, 1)
        key = be.load_private_pem(ch["user.key"].read_bytes())
        ca_der, user_der = read_der(ch["ca.crt"]), read_der(ch["user.crt"])
    assert verify_issued_by(user_der, ca_der, be_ca.verify_spki)
    data = os.urandom(1000)
    der = env_check.build_cms_asn1(data, sub, be, key, user_der, [ca_der])
    ok = env_check.verify_cms_asn1(der, data, env_check.cert_verifier(be))
    assert ok["valid"] and ok["signature_bytes"] == 17088
    assert not env_check.verify_cms_asn1(der, data + b"!", env_check.cert_verifier(be))["valid"]


def test_run_produces_report(cfg: dict) -> None:
    report, code = env_check.run(cfg)
    assert set(report["per_algorithm"]) == set(cfg["algorithms"])
    assert code == (0 if not report["blockers"] else 2)
