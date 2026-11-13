"""Smoke tests for sign_pdf (SPEC 4.4, scenario S2)."""
from __future__ import annotations

import csv
import hashlib
import json

import pytest

from src import build_pki, generate_pdfs, sign_pdf
from src.common.backend import get_backend
from src.common.cms import verify_cms_digest
from src.common.config import load_config, pdf_name_for
from src.common.x509util import read_der, spki_of

ALGS = ["rsa2048", "mldsa44", "slhdsa128f"]


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    base = tmp_path_factory.mktemp("s2")
    cfg = load_config("config.yaml")
    cfg["paths"] = {k: str(base / k) for k in cfg["paths"]}
    cfg["smoke_iterations"] = 2
    cfg["bench"] = {**cfg["bench"], "smoke_warmup": 1, "rounds": 2}
    kb = min(cfg["pdf_sizes_kb"])
    for d in ("pdf", "certs", "signed", "results"):
        (base / d).mkdir()
    generate_pdfs.generate(cfg, [kb], base / "pdf", base / "results")
    build_pki.build_all(cfg, ALGS, base / "certs", base / "results")
    rows = sign_pdf.run(cfg, ALGS, [kb], base / "results", base / "signed", smoke=True)
    return cfg, base, kb, rows


def test_csv_schema_and_counts(env) -> None:
    cfg, base, kb, rows = env
    with (base / "results" / "s2_sign.csv").open(encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        assert reader.fieldnames == sign_pdf.S2_COLUMNS
        data = list(reader)
    assert len(data) == len(rows) == len(ALGS) * cfg["smoke_iterations"]
    for r in data:
        assert r["pdf_name"] == pdf_name_for(kb)
        assert int(r["time_ns"]) > 0 and int(r["rss_peak_bytes"]) > 0
        assert float(r["cpu_percent_peak"]) >= 0
    for a in ALGS:
        assert sorted(int(r["iteration"]) for r in data if r["alg"] == a) == list(range(cfg["smoke_iterations"]))


def _signature_parts(path):
    from pyhanko.pdf_utils.reader import PdfFileReader

    with path.open("rb") as fh:
        r = PdfFileReader(fh)
        sig = r.embedded_signatures[0]
        br = [int(x) for x in sig.sig_object["/ByteRange"]]
        cms_der = sig.pkcs7_content
        subfilter = str(sig.sig_object["/SubFilter"])
    data = path.read_bytes()
    digest = hashlib.sha256(data[br[0]:br[0] + br[1]] + data[br[2]:br[2] + br[3]]).digest()
    return br, cms_der, digest, subfilter


def test_signed_examples_valid(env) -> None:
    cfg, base, _, _ = env
    for a in ALGS:
        path = base / "signed" / f"{a}_100kb.pdf"
        assert path.exists()
        br, cms_der, digest, subfilter = _signature_parts(path)
        assert subfilter == "/adbe.pkcs7.detached"
        assert br[0] == 0 and br[2] + br[3] == path.stat().st_size  # ByteRange covers the whole file
        be = get_backend(cfg, cfg["algorithms"][a]["subscriber"])
        res = verify_cms_digest(cms_der, digest, lambda c, s, m: be.verify_spki(spki_of(c), s, m))
        assert res["valid"] and res["signed_attrs"] == ["content_type", "message_digest", "signing_time"]


def test_rsa_signature_valid_in_pyhanko(env) -> None:
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext
    from asn1crypto import x509 as ax509

    cfg, base, _, _ = env
    root = ax509.Certificate.load(read_der(base / "certs" / cfg["pki"]["root_dir"] / "root.crt"))
    with (base / "signed" / "rsa2048_100kb.pdf").open("rb") as fh:
        sig = PdfFileReader(fh).embedded_signatures[0]
        status = validate_pdf_signature(sig, ValidationContext(trust_roots=[root]))  # path via the PSrE in the CMS
    assert status.intact and status.valid and status.trusted, status.pretty_print_details()


def test_meta_and_skip(env) -> None:
    cfg, base, kb, _ = env
    meta = json.loads((base / "results" / "s2_sign_meta.json").read_text(encoding="utf-8"))
    run0 = meta["runs"][0]
    assert run0["placeholder_hex_chars"] == cfg["signature_placeholder_bytes"]
    assert set(run0["examples"]) == {f"{a}/{pdf_name_for(kb)}" for a in ALGS}
    before = (base / "results" / "s2_sign.csv").read_bytes()
    sign_pdf.run(cfg, ["rsa2048"], [kb], base / "results", base / "signed", smoke=True)
    assert (base / "results" / "s2_sign.csv").read_bytes() == before


def test_sampler_reports_values() -> None:
    from src.common.monitor import ResourceSampler

    with ResourceSampler(0.002, 0.01) as s:
        s.begin()
        x = sum(i * i for i in range(300_000))
        cpu, rss = s.end()
    assert x > 0 and cpu >= 0 and rss > 0
