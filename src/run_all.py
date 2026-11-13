"""Run the whole pipeline (SPEC 4.7).

Order: env_check -> generate_pdfs (existing PDFs are kept) -> build_pki (existing
chains are kept) -> S1 -> S2 -> S3 -> S4. ``--force`` re-measures S1–S4 only; PDFs
and certificates are never rebuilt here (use the scripts' own ``--force``), so the
signed files and measurements always refer to the same keys.

Writes ``logs/run_<YYYYMMDD_HHMM>.log`` and ``system_info.json`` (in the results
folder of the mode: ``results/`` or ``results/<smoke_results_subdir>/``).

Exit codes: 0 OK, 2 env_check blocked, 3 pre-flight failed (noisy environment),
4 a signature did not verify in S3.

Run: ``python -m src.run_all --config config.yaml [--smoke] [--only <alg>] [--force] [--allow-noisy]``
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import platform
import sys
import time
from pathlib import Path
from typing import Any, Callable

from src import bench_crypto, build_pki, generate_pdfs, measure_size, sign_pdf, verify_pdf
from src.common import env_check
from src.common.config import base_arg_parser, load_config, resolve_path, results_dir
from src.common.monitor import NoisyEnvironment, snapshot

log = logging.getLogger("run_all")


def system_info(cfg: dict[str, Any], env_report: dict[str, Any], smoke: bool, alg_ids: list[str]) -> dict[str, Any]:
    """Machine, OS, Python, OpenSSL, liboqs and library versions, plus the power mode."""
    snap = snapshot(float(cfg.get("bench", {}).get("preflight_load_window_s", 3)))
    return {
        "generated_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "mode": "smoke" if smoke else "full",
        "algorithms": alg_ids,
        "os": {"system": platform.system(), "release": platform.release(), "version": platform.version(),
               "machine": platform.machine()},
        "cpu": {"model": snap["cpu_model"], "physical_cores": snap["cpu_physical"],
                "logical_cores": snap["cpu_logical"], "freq_mhz": snap["cpu_freq_mhz"]},
        "ram_total_bytes": snap["ram_total_bytes"],
        "power": {"mode": snap["power_mode"], "battery": snap["battery"]},
        "background_load": snap["load"],
        "python": env_report.get("python"),
        "openssl": env_report.get("openssl"),
        "liboqs": env_report.get("liboqs"),
        "crypto_backend": cfg.get("crypto_backend"),
        "backend_uniform": env_report.get("backend_uniform"),
        "libraries": env_report.get("libraries"),
        "config": cfg.get("_config_path"),
    }


def setup_logging(log_path: Path) -> logging.Handler:
    """Console + file logging; returns the file handler so it can be removed afterwards."""
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    if not any(isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)
               for h in root.handlers):
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        root.addHandler(sh)
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(fh)
    return fh


def _step(name: str, fn: Callable[[], Any]) -> Any:
    log.info("=== %s ===", name)
    t0 = time.perf_counter()
    out = fn()
    log.info("=== %s selesai (%.1f s) ===", name, time.perf_counter() - t0)
    return out


def run_all(cfg: dict[str, Any], smoke: bool = False, only: str | None = None, force: bool = False,
            allow_noisy: bool = False) -> int:
    """Execute every stage in order; returns the exit code."""
    alg_ids = [only] if only else list(cfg["algorithms"])
    sizes = sorted(cfg["pdf_sizes_kb"])[:1] if smoke else list(cfg["pdf_sizes_kb"])
    results_root = resolve_path(cfg, "results")
    out_dir = results_dir(cfg, smoke)
    signed = resolve_path(cfg, "signed")
    if smoke:
        signed = signed / str(cfg.get("smoke_results_subdir", "smoke"))
    log.info("Mode %s; algoritma: %s; ukuran PDF: %s KB; force=%s", "smoke" if smoke else "penuh",
             ", ".join(alg_ids), sizes, force)

    report, code = _step("Tahap 0: env_check", lambda: env_check.run(cfg))
    (results_root / "env_report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    if code != 0:
        log.error("env_check BLOCKED: %s", "; ".join(report.get("blockers", [])))
        return 2
    info = system_info(cfg, report, smoke, alg_ids)
    (out_dir / "system_info.json").write_text(json.dumps(info, indent=2, ensure_ascii=False, default=str),
                                              encoding="utf-8")
    log.info("system_info.json ditulis ke %s", out_dir)

    _step("generate_pdfs", lambda: generate_pdfs.generate(cfg, sizes, resolve_path(cfg, "pdf"), results_root))
    _step("build_pki", lambda: build_pki.build_all(cfg, alg_ids, resolve_path(cfg, "certs"), results_root))
    try:
        _step("S1 bench_crypto", lambda: bench_crypto.run(cfg, alg_ids, out_dir, smoke, force, allow_noisy))
        _step("S2 sign_pdf", lambda: sign_pdf.run(cfg, alg_ids, sizes, out_dir, signed, smoke, force, allow_noisy))
        s3 = _step("S3 verify_pdf",
                   lambda: verify_pdf.run(cfg, alg_ids, sizes, out_dir, signed, smoke, force, allow_noisy))
    except NoisyEnvironment as exc:
        log.error("%s", exc)
        return 3
    _step("S4 measure_size", lambda: measure_size.run(cfg, alg_ids, sizes, out_dir, signed, smoke, force))
    invalid = sum(str(r["valid"]) != "True" for r in s3)
    if invalid:
        log.error("S3: %d verifikasi tidak valid", invalid)
        return 4
    log.info("Selesai tanpa galat. Hasil di %s", out_dir)
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    ap = base_arg_parser("Menjalankan seluruh tahap: env_check, PDF, PKI, S1–S4 (SPEC 4.7)")
    ap.add_argument("--smoke", action="store_true", help="uji cepat: iterasi smoke, PDF terkecil saja")
    ap.add_argument("--only", help="hanya satu ID algoritma dari config")
    ap.add_argument("--force", action="store_true", help="ukur ulang S1–S4 walau hasil sudah ada")
    ap.add_argument("--allow-noisy", action="store_true", help="tetap jalan walau pemeriksaan pra-run gagal")
    args = ap.parse_args(argv)
    cfg = load_config(args.config)
    if args.only and args.only not in cfg["algorithms"]:
        ap.error(f"--only harus salah satu dari: {', '.join(cfg['algorithms'])}")
    log_path = resolve_path(cfg, "logs") / f"run_{dt.datetime.now():%Y%m%d_%H%M}.log"
    fh = setup_logging(log_path)
    try:
        code = run_all(cfg, args.smoke, args.only, args.force, args.allow_noisy)
    except Exception:
        log.exception("run_all gagal")
        code = 1
    finally:
        log.info("Log: %s", log_path)
        logging.getLogger().removeHandler(fh)
        fh.close()
    return code


if __name__ == "__main__":
    sys.exit(main())
