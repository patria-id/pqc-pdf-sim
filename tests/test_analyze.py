"""Tests for analyze (SPEC 4.8) on small synthetic results."""
from __future__ import annotations

import csv
import random

import pytest

from src import analyze
from src.common.config import load_config, pdf_name_for

ALGS = ["rsa2048", "mldsa44", "slhdsa128f"]
SCALE = {"rsa2048": 1.0, "mldsa44": 1.1, "slhdsa128f": 10.0}


def _write(path, header, rows) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    base = tmp_path_factory.mktemp("an")
    cfg = load_config("config.yaml")
    cfg["paths"] = {k: str(base / k) for k in cfg["paths"]}
    res = base / "results"
    res.mkdir()
    rng = random.Random(1)
    n = 40
    sizes = sorted(cfg["pdf_sizes_kb"])
    _write(res / "s1_crypto.csv", ["alg", "operation", "iteration", "time_ns", "signature_bytes"],
           [[a, op, i, int(1e6 * SCALE[a] * rng.uniform(0.9, 1.1)), "" if op == "keygen" else 100 * (j + 1)]
            for j, a in enumerate(ALGS) for op in ("keygen", "sign", "verify") for i in range(n)])
    for name, extra in (("s2_sign.csv", []), ("s3_verify.csv", ["valid"])):
        _write(res / name, ["alg", "pdf_name", "iteration", "time_ns", "cpu_percent_peak", "rss_peak_bytes"] + extra,
               [[a, pdf_name_for(kb), i, int(1e6 * SCALE[a] * (1 + k) * rng.uniform(0.9, 1.1)), 99.0, 10_000_000]
                + (["True"] if extra else [])
                for a in ALGS for k, kb in enumerate(sizes) for i in range(n)])
    _write(res / "s4_size.csv", ["alg", "pdf_name", "original_bytes", "signed_bytes", "delta_bytes", "delta_percent",
                                 "cms_bytes", "signature_bytes", "chain_bytes", "placeholder_bytes",
                                 "placeholder_used_percent"],
           [[a, pdf_name_for(kb), kb * 1024, kb * 1024 + 1000 * (j + 1), 1000 * (j + 1),
             100 * 1000 * (j + 1) / (kb * 1024), 500, 100, 300, 600, 83.3]
            for j, a in enumerate(ALGS) for kb in sizes])
    _write(res / "cert_sizes.csv", ["alg", "ca_alg", "ca_cert_der_bytes", "user_cert_der_bytes", "chain_der_bytes",
                                    "user_pubkey_bytes", "ca_pubkey_bytes"],
           [[a, cfg["algorithms"][a]["ca"], 1000, 900, 1900, 300, 500] for a in ALGS])
    report = analyze.analyze(cfg, res, base / "figures")
    return cfg, base, res, report


def _read(path):
    with path.open(encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        return reader.fieldnames, list(reader)


def test_summary(env) -> None:
    cfg, _, res, _ = env
    header, rows = _read(res / "summary.csv")
    assert header == analyze.SUMMARY_COLUMNS
    assert len(rows) == len(ALGS) * (3 + 2 * len(cfg["pdf_sizes_kb"]))
    for r in rows:
        assert int(r["n"]) == 40
        assert float(r["p25_ms"]) <= float(r["median_ms"]) <= float(r["p75_ms"]) <= float(r["p95_ms"])
        if r["alg"] == "rsa2048":
            assert float(r["ratio_median_vs_ref"]) == 1.0
    slh = [r for r in rows if r["alg"] == "slhdsa128f" and r["scenario"] == "S1"]
    assert all(8 < float(r["ratio_median_vs_ref"]) < 12 for r in slh)
    assert all(r["valid_percent"] == "100.0" for r in rows if r["scenario"] == "S3")


def test_significance(env) -> None:
    cfg, _, res, _ = env
    header, rows = _read(res / "significance.csv")
    assert header == analyze.SIGNIFICANCE_COLUMNS
    kw = [r for r in rows if r["test"] == "kruskal_wallis"]
    mw = [r for r in rows if r["test"] == "mann_whitney"]
    assert len(kw) == 3 + 2 * len(cfg["pdf_sizes_kb"])
    assert len(mw) == len(kw) * (len(ALGS) - 1)
    for r in mw:
        assert float(r["p_holm"]) >= float(r["p_value"])
        assert -1 <= float(r["effect_size"]) <= 1
    big = [r for r in mw if r["alg"] == "slhdsa128f"]
    assert all(r["significant"] == "True" and float(r["effect_size"]) == 1.0 for r in big)


def test_tables_and_figures(env) -> None:
    _, base, res, report = env
    md = (res / "tables_for_paper.md").read_text(encoding="utf-8")
    for title in ("Tabel 1.", "Tabel 2.", "Tabel 3.", "Tabel 4.", "Tabel 5.", "Tabel 6."):
        assert title in md
    assert "SLH-DSA-128f" in md and "RSA-2048" in md
    names = {p.name for p in report["figures"]}
    assert names == {"s1_sign_verify.png", "s2_sign_by_size.png", "s3_verify_by_size.png",
                     "s4_size_overhead.png", "sizes_keys_signatures.png"}
    for p in report["figures"]:
        assert p.stat().st_size > 10_000


def test_missing_scenarios_are_skipped(tmp_path) -> None:
    cfg = load_config("config.yaml")
    cfg["paths"] = {k: str(tmp_path / k) for k in cfg["paths"]}
    report = analyze.analyze(cfg, tmp_path, tmp_path / "fig")
    assert report["summary_rows"] == 0 and report["figures"] == []


def test_holm_and_formatting() -> None:
    assert analyze.holm([0.01, 0.04, 0.03]) == pytest.approx([0.03, 0.06, 0.06])
    assert analyze.holm([0.5, 0.9]) == pytest.approx([1.0, 1.0])
    assert analyze.fmt_id(1234.5, 1) == "1.234,5"
    assert analyze.fmt_ratio(0.00326) == "0,0033×"
    assert analyze.fmt_p(0.0) == "< 1e-300"
    assert analyze.size_text(100) == "100 KB" and analyze.size_text(10240) == "10 MB"
