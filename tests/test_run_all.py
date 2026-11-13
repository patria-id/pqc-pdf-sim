"""Smoke test for run_all (SPEC 4.7) with one algorithm in a temporary tree."""
from __future__ import annotations

import json
import logging

from src import run_all
from src.common.config import load_config


def test_run_all_smoke_one_alg(tmp_path) -> None:
    cfg = load_config("config.yaml")
    cfg["paths"] = {k: str(tmp_path / k) for k in cfg["paths"]}
    cfg["smoke_iterations"] = 2
    cfg["bench"] = {**cfg["bench"], "smoke_warmup": 1, "rounds": 2}
    assert run_all.run_all(cfg, smoke=True, only="rsa2048") == 0

    smoke = tmp_path / "results" / cfg["smoke_results_subdir"]
    for name in ("s1_crypto.csv", "s2_sign.csv", "s3_verify.csv", "s4_size.csv", "system_info.json"):
        assert (smoke / name).exists(), name
    assert (tmp_path / "results" / "env_report.json").exists()
    info = json.loads((smoke / "system_info.json").read_text(encoding="utf-8"))
    assert info["mode"] == "smoke" and info["algorithms"] == ["rsa2048"]
    assert info["cpu"]["logical_cores"] >= 1 and info["ram_total_bytes"] > 0
    assert info["python"]["version"] and info["libraries"]["pyhanko"]
    assert info["openssl"]["libcrypto_ctypes"]["version_text"]
    assert (tmp_path / "signed" / cfg["smoke_results_subdir"] / "rsa2048_100kb.pdf").exists()

    # second run: everything already present -> skipped, still OK
    assert run_all.run_all(cfg, smoke=True, only="rsa2048") == 0


def test_setup_logging_writes_file(tmp_path) -> None:
    path = tmp_path / "run_test.log"
    fh = run_all.setup_logging(path)
    try:
        logging.getLogger("run_all").info("halo")
    finally:
        logging.getLogger().removeHandler(fh)
        fh.close()
    assert "halo" in path.read_text(encoding="utf-8")
