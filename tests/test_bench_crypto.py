"""Smoke tests for bench_crypto (SPEC 4.3, scenario S1)."""
from __future__ import annotations

import csv
import json

import pytest

from src import bench_crypto
from src.common.config import load_config

# one algorithm per family; SLH-DSA-128f is the fast SLH-DSA variant
ALGS = ["rsa2048", "mldsa44", "slhdsa128f"]
EXPECTED_SIG = {"rsa2048": 256, "mldsa44": 2420, "slhdsa128f": 17088}


@pytest.fixture(scope="module")
def cfg() -> dict:
    c = load_config("config.yaml")
    c["smoke_iterations"] = 3
    c["bench"] = {**c.get("bench", {}), "smoke_warmup": 1, "rounds": 2}
    return c


@pytest.fixture(scope="module")
def result(cfg, tmp_path_factory):
    out = tmp_path_factory.mktemp("s1")
    rows = bench_crypto.run(cfg, ALGS, out, smoke=True)
    return out, rows


def test_schema_and_counts(cfg, result) -> None:
    out, _ = result
    with (out / "s1_crypto.csv").open(encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        assert reader.fieldnames == bench_crypto.S1_COLUMNS
        rows = list(reader)
    n = cfg["smoke_iterations"]
    assert len(rows) == len(ALGS) * len(bench_crypto.OPERATIONS) * n
    for a in ALGS:
        for op in bench_crypto.OPERATIONS:
            its = [int(r["iteration"]) for r in rows if r["alg"] == a and r["operation"] == op]
            assert its == list(range(n)), (a, op)  # warm-up not recorded


def test_values(result) -> None:
    out, _ = result
    with (out / "s1_crypto.csv").open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    for r in rows:
        assert int(r["time_ns"]) > 0
        if r["operation"] == "keygen":
            assert r["signature_bytes"] == ""
        else:
            assert int(r["signature_bytes"]) == EXPECTED_SIG[r["alg"]]


def test_meta_and_skip(cfg, result) -> None:
    out, _ = result
    meta = json.loads((out / "s1_crypto_meta.json").read_text(encoding="utf-8"))
    assert set(meta["algorithms"]) == set(ALGS)
    assert meta["algorithms"]["mldsa44"]["backend"] == cfg["crypto_backend"]
    before = (out / "s1_crypto.csv").read_bytes()
    bench_crypto.run(cfg, ["rsa2048"], out, smoke=True)  # already present -> skipped
    assert (out / "s1_crypto.csv").read_bytes() == before


def test_force_only_replaces_one_alg(cfg, result) -> None:
    out, _ = result
    rows = bench_crypto.run(cfg, ["rsa2048"], out, smoke=True, force=True)
    assert {r["alg"] for r in rows} == set(ALGS)
    assert len(rows) == len(ALGS) * len(bench_crypto.OPERATIONS) * cfg["smoke_iterations"]


def test_messages_deterministic() -> None:
    assert bench_crypto.messages(42, "x", 3, 32) == bench_crypto.messages(42, "x", 3, 32)
    assert bench_crypto.messages(42, "x", 1, 32) != bench_crypto.messages(42, "y", 1, 32)


def test_chunking_and_round_order() -> None:
    assert bench_crypto.chunk_sizes(1000, 10) == [100] * 10
    assert bench_crypto.chunk_sizes(5, 10) == [1] * 5
    assert sum(bench_crypto.chunk_sizes(1003, 10)) == 1003
    algs = ["a", "b", "c", "d"]
    assert bench_crypto.round_order(42, algs, 0) == bench_crypto.round_order(42, algs, 0)
    assert sorted(bench_crypto.round_order(42, algs, 3)) == algs


def test_chunk_log_in_meta(cfg, result) -> None:
    out, _ = result
    meta = json.loads((out / "s1_crypto_meta.json").read_text(encoding="utf-8"))
    run0 = meta["runs"][0]
    n_rounds = len(bench_crypto.chunk_sizes(cfg["smoke_iterations"], cfg["bench"]["rounds"]))
    assert len(run0["chunks"]) == n_rounds * len(ALGS) * len(bench_crypto.OPERATIONS)
    assert run0["environment_before"]["cpu_logical"] >= 1
    # every (alg, op) gets warm-up only in round 0, chunk_warmup afterwards
    assert {c["warmup"] for c in run0["chunks"] if c["round"] == 0} == {cfg["bench"]["smoke_warmup"]}


def test_full_run_blocked_by_preflight(cfg, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(bench_crypto, "preflight_issues", lambda snap, lim: ["mode daya salah"])
    monkeypatch.setattr(bench_crypto, "snapshot", lambda s: {})
    with pytest.raises(bench_crypto.NoisyEnvironment):
        bench_crypto.run(cfg, ["rsa2048"], tmp_path, smoke=False)
    assert not (tmp_path / "s1_crypto.csv").exists()
