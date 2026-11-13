"""Smoke tests for generate_pdfs (SPEC 4.1)."""
from __future__ import annotations

import csv
import hashlib

from src import generate_pdfs
from src.common.config import load_config, pdf_name_for, size_label


def test_size_label() -> None:
    assert size_label(100) == "100kb"
    assert size_label(1024) == "1mb"
    assert size_label(10240) == "10mb"
    assert pdf_name_for(1024) == "sample_1mb.pdf"


def test_generate_smallest_pdf(tmp_path) -> None:
    cfg = load_config("config.yaml")
    kb = min(cfg["pdf_sizes_kb"])
    pdf_dir, res_dir = tmp_path / "pdf", tmp_path / "results"
    pdf_dir.mkdir()
    rows = generate_pdfs.generate(cfg, [kb], pdf_dir, res_dir)
    path = pdf_dir / pdf_name_for(kb)
    assert path.exists()

    # size within tolerance, multi-page, inventory matches the file
    tol = cfg["pdf"]["size_tolerance_pct"] / 100
    size = path.stat().st_size
    assert abs(size - kb * 1024) <= kb * 1024 * tol
    with (res_dir / "pdf_inventory.csv").open(encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        assert reader.fieldnames == generate_pdfs.INVENTORY_COLUMNS
        inv = list(reader)
    assert len(inv) == len(rows) == 1
    assert int(inv[0]["actual_bytes"]) == size
    assert int(inv[0]["pages"]) >= 2
    assert inv[0]["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()

    # idempotent: existing file is not rewritten without force
    mtime = path.stat().st_mtime_ns
    generate_pdfs.generate(cfg, [kb], pdf_dir, res_dir)
    assert path.stat().st_mtime_ns == mtime

    # deterministic: forced regeneration gives the same bytes
    first = path.read_bytes()
    generate_pdfs.generate(cfg, [kb], pdf_dir, res_dir, force=True)
    assert path.read_bytes() == first
