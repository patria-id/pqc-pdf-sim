"""Smoke tests for measure_size (SPEC 4.6, scenario S4)."""
from __future__ import annotations

import csv

import pytest

from src import build_pki, generate_pdfs, measure_size, verify_pdf
from src.common.config import load_config, pdf_name_for

ALGS = ["rsa2048", "mldsa44", "slhdsa128f"]


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    base = tmp_path_factory.mktemp("s4")
    cfg = load_config("config.yaml")
    cfg["paths"] = {k: str(base / k) for k in cfg["paths"]}
    kb = min(cfg["pdf_sizes_kb"])
    for d in ("pdf", "certs", "signed", "results"):
        (base / d).mkdir()
    generate_pdfs.generate(cfg, [kb], base / "pdf", base / "results")
    build_pki.build_all(cfg, ALGS, base / "certs", base / "results")
    rows = measure_size.run(cfg, ALGS, [kb], base / "results", base / "signed", smoke=True)
    return cfg, base, kb, rows


def test_csv_schema_and_consistency(env) -> None:
    cfg, base, kb, _ = env
    with (base / "results" / "s4_size.csv").open(encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        assert reader.fieldnames == measure_size.S4_COLUMNS
        rows = {r["alg"]: r for r in reader}
    assert set(rows) == set(ALGS)
    margin = cfg["measure_size"]["placeholder_margin_bytes"]
    for r in rows.values():
        v = {k: float(x) for k, x in r.items() if k not in ("alg", "pdf_name")}
        assert r["pdf_name"] == pdf_name_for(kb)
        assert v["delta_bytes"] == v["signed_bytes"] - v["original_bytes"] > 2 * v["placeholder_bytes"]
        assert v["placeholder_bytes"] == v["cms_bytes"] + margin
        assert v["cms_bytes"] > v["chain_bytes"] + v["signature_bytes"]
        assert 0 < v["placeholder_used_percent"] <= 100
    assert int(rows["rsa2048"]["signature_bytes"]) == 256
    assert int(rows["mldsa44"]["signature_bytes"]) == 2420
    assert int(rows["slhdsa128f"]["signature_bytes"]) == 17088
    # the file-size overhead now follows the algorithm
    assert int(rows["rsa2048"]["delta_bytes"]) < int(rows["mldsa44"]["delta_bytes"]) < int(rows["slhdsa128f"]["delta_bytes"])


def test_chain_bytes_match_cert_sizes(env) -> None:
    _, base, _, rows = env
    with (base / "results" / "cert_sizes.csv").open(encoding="utf-8") as fh:
        chain = {r["alg"]: int(r["chain_der_bytes"]) for r in csv.DictReader(fh)}
    for r in rows:
        assert int(r["chain_bytes"]) == chain[r["alg"]]


def test_signed_files_valid_and_skip(env) -> None:
    cfg, base, kb, _ = env
    fit = base / "signed" / cfg["measure_size"]["signed_subdir"]
    results = verify_pdf.check_all(cfg, fit)
    assert len(results) == len(ALGS) and all(r["valid"] for _, r in results)
    before = (base / "results" / "s4_size.csv").read_bytes()
    measure_size.run(cfg, ["rsa2048"], [kb], base / "results", base / "signed", smoke=True)
    assert (base / "results" / "s4_size.csv").read_bytes() == before


def test_placeholder_capacity_modes() -> None:
    cfg = {"signature_placeholder_bytes": 131072,
           "measure_size": {"placeholder_mode": "fit", "placeholder_margin_bytes": 100}}
    assert measure_size.placeholder_capacity(cfg, 5000) == 5100
    cfg["measure_size"]["placeholder_mode"] = "fixed"
    assert measure_size.placeholder_capacity(cfg, 5000) == 65536
    cfg["measure_size"]["placeholder_mode"] = "x"
    with pytest.raises(ValueError):
        measure_size.placeholder_capacity(cfg, 5000)
