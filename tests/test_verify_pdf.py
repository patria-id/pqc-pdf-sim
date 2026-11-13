"""Smoke and negative tests for verify_pdf (SPEC 4.5, scenario S3)."""
from __future__ import annotations

import csv
import json

import pytest

from asn1crypto import x509 as ax509

from src import build_pki, generate_pdfs, sign_pdf, verify_pdf
from src.common import pki
from src.common.cms import cms_certificates, der_length
from src.common.opensslcli import resolve_openssl_bin
from src.common.x509util import read_der
from src.common.config import load_config, pdf_name_for

ALGS = ["rsa2048", "mldsa44", "slhdsa128f"]


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    base = tmp_path_factory.mktemp("s3")
    cfg = load_config("config.yaml")
    cfg["paths"] = {k: str(base / k) for k in cfg["paths"]}
    cfg["smoke_iterations"] = 2
    cfg["bench"] = {**cfg["bench"], "smoke_warmup": 1, "rounds": 2}
    kb = min(cfg["pdf_sizes_kb"])
    for d in ("pdf", "certs", "signed", "results"):
        (base / d).mkdir()
    generate_pdfs.generate(cfg, [kb], base / "pdf", base / "results")
    build_pki.build_all(cfg, ALGS, base / "certs", base / "results")
    sign_pdf.run(cfg, ALGS, [kb], base / "results", base / "signed", smoke=True)
    rows = verify_pdf.run(cfg, ALGS, [kb], base / "results", base / "signed", smoke=True)
    return cfg, base, kb, rows


def _signed(base, alg: str) -> bytes:
    return (base / "signed" / f"{alg}_100kb.pdf").read_bytes()


def _trust(cfg, base, alg: str) -> verify_pdf.Trust:
    return verify_pdf.load_trust(cfg, alg, base / "certs")


def _byte_range(data: bytes) -> list[int]:
    i = data.rindex(b"/ByteRange")
    inner = data[data.index(b"[", i) + 1:data.index(b"]", i)]
    return [int(x) for x in inner.split()]


def test_csv_schema_counts_and_valid(env) -> None:
    cfg, base, kb, rows = env
    with (base / "results" / "s3_verify.csv").open(encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        assert reader.fieldnames == verify_pdf.S3_COLUMNS
        data = list(reader)
    assert len(data) == len(rows) == len(ALGS) * cfg["smoke_iterations"]
    for r in data:
        assert r["pdf_name"] == pdf_name_for(kb) and r["valid"] == "True"
        assert int(r["time_ns"]) > 0 and int(r["rss_peak_bytes"]) > 0


@pytest.mark.parametrize("alg", ALGS)
def test_one_byte_change_in_document_is_invalid(env, alg: str) -> None:
    cfg, base, _, _ = env
    data = bytearray(_signed(base, alg))
    br = _byte_range(bytes(data))
    for pos in (10, br[1] // 2):  # binary comment after the header (parser-neutral), middle of the PDF
        tampered = bytearray(data)
        tampered[pos] ^= 0x01
        res = verify_pdf.verify_pdf_bytes(bytes(tampered), _trust(cfg, base, alg))
        assert res["valid"] is False, (alg, pos)
        if pos == 10:
            assert "messageDigest" in res["reason"]


@pytest.mark.parametrize("alg", ALGS)
def test_one_byte_change_in_signature_is_invalid(env, alg: str) -> None:
    cfg, base, _, _ = env
    data = bytearray(_signed(base, alg))
    br = _byte_range(bytes(data))
    cms_der = bytes.fromhex(data[br[1] + 1:br[2] - 1].decode("ascii"))
    pos = br[1] + 1 + 2 * (der_length(cms_der) - 1)  # hex of the last signature byte (last DER field)
    data[pos] = ord("0") if data[pos] != ord("0") else ord("1")
    res = verify_pdf.verify_pdf_bytes(bytes(data), _trust(cfg, base, alg))
    assert res["valid"] is False and res["reason"] == "tanda tangan CMS tidak valid"


def test_cms_embeds_full_chain(env) -> None:
    cfg, base, _, _ = env
    data = _signed(base, "mldsa44")
    br = _byte_range(data)
    _, certs = cms_certificates(bytes.fromhex(data[br[1] + 1:br[2] - 1].decode("ascii")))
    p = base / "certs" / "mldsa44"
    assert sorted(certs) == sorted(read_der(p / f) for f in ("user.crt", "ca.crt", "root.crt"))  # DER SET OF order


def test_appended_bytes_are_invalid(env) -> None:
    cfg, base, _, _ = env
    res = verify_pdf.verify_pdf_bytes(_signed(base, "mldsa44") + b"\n%x\n", _trust(cfg, base, "mldsa44"))
    assert res["valid"] is False


def test_wrong_trust_anchor_is_invalid(env, tmp_path) -> None:
    cfg, base, _, _ = env
    exe = resolve_openssl_bin(cfg["tools"]["openssl_bin"])
    other = pki.build_root(exe, cfg["pki"]["root_alg"], cfg, tmp_path, 60, "Root Lain", days=1)
    good = _trust(cfg, base, "mldsa44")
    wrong = verify_pdf.Trust(good.sub_alg, read_der(other["root.crt"]), good.verify_sub, good.verify_ca,
                             good.verify_root)
    res = verify_pdf.verify_pdf_bytes(_signed(base, "mldsa44"), wrong)
    assert res["valid"] is False and "Root CA simulasi" in res["reason"]


def test_signer_path_checks(env) -> None:
    cfg, base, _, _ = env
    t = _trust(cfg, base, "mldsa44")
    p = base / "certs" / "mldsa44"
    user, psre = read_der(p / "user.crt"), read_der(p / "ca.crt")
    when = ax509.Certificate.load(user)["tbs_certificate"]["validity"]["not_before"].native
    assert verify_pdf.check_signer_cert(user, [user, psre, t.root_der], when, t) is None
    assert verify_pdf.check_signer_cert(user, [user, psre], when, t) is None  # root is never taken from the CMS
    assert "tidak ada di CMS" in verify_pdf.check_signer_cert(user, [user, t.root_der], when, t)
    other_psre = read_der(base / "certs" / "slhdsa128f" / "ca.crt")  # same root, different PSrE
    assert "tidak ada di CMS" in verify_pdf.check_signer_cert(user, [user, other_psre], when, t)
    assert "Root" in verify_pdf.check_signer_cert(psre, [psre, t.root_der], when, t)  # CA cert as signer
    later = when.replace(year=when.year + 5)
    assert "signingTime" in verify_pdf.check_signer_cert(user, [user, psre], later, t)


def test_unexpected_algorithm_is_invalid(env) -> None:
    cfg, base, _, _ = env
    t = _trust(cfg, base, "rsa2048")
    res = verify_pdf.verify_pdf_bytes(_signed(base, "rsa2048"),
                                      verify_pdf.Trust("ML-DSA-44", t.root_der, t.verify_sub, t.verify_ca,
                                                       t.verify_root))
    assert res["valid"] is False and "algoritma" in res["reason"]


def test_garbage_input_does_not_raise(env) -> None:
    cfg, base, _, _ = env
    res = verify_pdf.verify_pdf_bytes(b"bukan pdf", _trust(cfg, base, "rsa2048"))
    assert res["valid"] is False and res["reason"]


def test_check_byte_range() -> None:
    data = b"aaaa<00>bbbb"
    assert verify_pdf.check_byte_range(data, [0, 4, 8, 4]) is None
    assert verify_pdf.check_byte_range(data, [0, 4, 8, 3]) is not None   # does not reach EOF
    assert verify_pdf.check_byte_range(data, [1, 3, 8, 4]) is not None   # does not start at 0
    assert verify_pdf.check_byte_range(data, [0, 3, 8, 4]) is not None   # gap is not the hex string


def test_der_length() -> None:
    assert der_length(b"\x30\x03abc\x00\x00") == 5
    assert der_length(b"\x30\x82\x01\x00" + b"\x00" * 300) == 4 + 256


def test_meta_skip_and_check_all(env) -> None:
    cfg, base, kb, _ = env
    meta = json.loads((base / "results" / "s3_verify_meta.json").read_text(encoding="utf-8"))
    summary = meta["runs"][0]["combinations_summary"]
    assert set(summary) == {f"{a}/{pdf_name_for(kb)}" for a in ALGS}
    assert all(v["invalid_iterations"] == 0 for v in summary.values())
    before = (base / "results" / "s3_verify.csv").read_bytes()
    verify_pdf.run(cfg, ["rsa2048"], [kb], base / "results", base / "signed", smoke=True)
    assert (base / "results" / "s3_verify.csv").read_bytes() == before
    results = verify_pdf.check_all(cfg, base / "signed")
    assert len(results) == len(ALGS) and all(r["valid"] for _, r in results)
