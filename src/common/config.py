"""Configuration loading helpers shared by all scripts."""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def load_config(path: str | Path = "config.yaml") -> dict[str, Any]:
    """Load the YAML config; relative paths resolve against the project root."""
    p = Path(path)
    if not p.is_absolute() and not p.exists():
        p = PROJECT_ROOT / p
    with p.open("r", encoding="utf-8") as fh:
        cfg: dict[str, Any] = yaml.safe_load(fh)
    cfg["_config_path"] = str(p.resolve())
    return cfg


def resolve_path(cfg: dict[str, Any], key: str) -> Path:
    """Return the absolute directory for `paths.<key>` (created if missing)."""
    d = Path(cfg["paths"][key])
    if not d.is_absolute():
        d = PROJECT_ROOT / d
    d.mkdir(parents=True, exist_ok=True)
    return d


def base_arg_parser(description: str) -> argparse.ArgumentParser:
    """Argument parser with the common `--config` option."""
    ap = argparse.ArgumentParser(description=description)
    ap.add_argument("--config", default="config.yaml", help="path ke config.yaml")
    return ap


def size_label(kb: int) -> str:
    """Human label for a PDF size in KB: 100 -> '100kb', 1024 -> '1mb', 10240 -> '10mb'."""
    return f"{kb // 1024}mb" if kb >= 1024 and kb % 1024 == 0 else f"{kb}kb"


def pdf_name_for(kb: int) -> str:
    """File name of the sample PDF for a target size in KB."""
    return f"sample_{size_label(kb)}.pdf"


def results_dir(cfg: dict[str, Any], smoke: bool) -> Path:
    """Results directory; smoke runs go to a separate sub-directory."""
    d = resolve_path(cfg, "results")
    if smoke:
        d = d / str(cfg.get("smoke_results_subdir", "smoke"))
        d.mkdir(parents=True, exist_ok=True)
    return d


def run_counts(cfg: dict[str, Any], smoke: bool) -> tuple[int, int]:
    """(iterations, warmup) for a full or smoke run."""
    if smoke:
        return int(cfg["smoke_iterations"]), int(cfg.get("bench", {}).get("smoke_warmup", 1))
    return int(cfg["iterations"]), int(cfg["warmup"])
