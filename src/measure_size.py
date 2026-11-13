"""Scenario S4: file-size overhead of signing a PDF (SPEC 4.6).

For every (algorithm, PDF size) the original PDF is signed once more, with the
same code path as S2 (pyHanko interrupted signing + asn1crypto CMS), but with a
``/Contents`` placeholder sized for that algorithm (``measure_size.placeholder_mode``):

* ``fit``   – capacity = CMS size of a dry-run signature + ``placeholder_margin_bytes``
              (like pyHanko's default of estimating the signature size first), so the
              file growth reflects the algorithm;
* ``fixed`` – capacity = ``signature_placeholder_bytes`` / 2 (as in S2).

Nothing is timed. Each produced PDF is verified with S3's full verification and
saved to ``signed/<measure_size.signed_subdir>/``.

Columns: ``placeholder_bytes`` is the DER capacity of ``/Contents`` (the hex string
in the file is twice as long), ``placeholder_used_percent`` = cms_bytes / placeholder_bytes,
``chain_bytes`` = DER size of all certificates embedded in the CMS (subscriber + PSrE [+ Root]).

Run: ``python -m src.measure_size --config config.yaml [--smoke] [--only <alg>] [--force]``
"""
from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging
import sys
from pathlib import Path
from typing import Any

from src.common.cms import cms_certificates
from src.common.config import base_arg_parser, load_config, pdf_name_for, resolve_path, results_dir, size_label
from src.common.csvio import read_csv, write_csv
from src.sign_pdf import prepare_combo, sign_once
from src.verify_pdf import load_trust, verify_pdf_bytes

log = logging.getLogger("measure_size")

S4_COLUMNS = ["alg", "pdf_name", "original_bytes", "signed_bytes", "delta_bytes", "delta_percent", "cms_bytes",
              "signature_bytes", "chain_bytes", "placeholder_bytes", "placeholder_used_percent"]


def placeholder_capacity(cfg: dict[str, Any], cms_len: int) -> int:
    """DER capacity of /Contents for a CMS of `cms_len` bytes, per `measure_size.placeholder_mode`."""
    mcfg = cfg["measure_size"]
    mode = mcfg["placeholder_mode"]
    if mode == "fit":
        return cms_len + int(mcfg["placeholder_margin_bytes"])
    if mode == "fixed":
        return int(cfg["signature_placeholder_bytes"]) // 2
    raise ValueError(f"measure_size.placeholder_mode tidak dikenal: {mode!r} (fit/fixed)")


def measure_one(cfg: dict[str, Any], loop: asyncio.AbstractEventLoop, alg_id: str, kb: int,
                pdf_dir: Path, certs_dir: Path, out_dir: Path) -> dict[str, Any]:
    """Sign one PDF with an algorithm-sized placeholder, verify it, save it and return the S4 row."""
    combo = prepare_combo(cfg, alg_id, kb, pdf_dir, certs_dir)
    _, _, probe_cms = sign_once(loop, combo, int(cfg["signature_placeholder_bytes"]))  # dry run: CMS size
    capacity = placeholder_capacity(cfg, len(probe_cms))
    out, _digest, cms_der = sign_once(loop, combo, 2 * capacity)
    signed = out.getvalue()
    res = verify_pdf_bytes(signed, load_trust(cfg, alg_id, certs_dir))
    if not res["valid"]:
        raise RuntimeError(f"{alg_id}/{combo.pdf_name}: PDF hasil S4 tidak valid: {res['reason']}")
    name = f"{alg_id}_{size_label(kb)}.pdf"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / name).write_bytes(signed)
    original = len(combo.pdf_bytes)
    delta = len(signed) - original
    chain_bytes = sum(len(c) for c in cms_certificates(cms_der)[1])
    return {"alg": alg_id, "pdf_name": combo.pdf_name, "original_bytes": original, "signed_bytes": len(signed),
            "delta_bytes": delta, "delta_percent": round(100.0 * delta / original, 4),
            "cms_bytes": len(cms_der), "signature_bytes": res["signature_bytes"], "chain_bytes": chain_bytes,
            "placeholder_bytes": capacity, "placeholder_used_percent": round(100.0 * len(cms_der) / capacity, 2)}


def run(cfg: dict[str, Any], alg_ids: list[str], sizes_kb: list[int], out_dir: Path, signed_dir: Path,
        smoke: bool = False, force: bool = False) -> list[dict[str, Any]]:
    """Compute S4 rows for all (alg, size) combinations; merge with existing results unless `force`."""
    out_csv = out_dir / "s4_size.csv"
    existing = read_csv(out_csv, S4_COLUMNS)
    done = {(r["alg"], r["pdf_name"]) for r in existing}
    todo = [(a, kb) for a in alg_ids for kb in sizes_kb if force or (a, pdf_name_for(kb)) not in done]
    if not todo:
        log.info("Semua kombinasi sudah ada di %s, dilewati (pakai --force)", out_csv.name)
        return existing

    mcfg = cfg["measure_size"]
    pdf_dir, certs_dir = resolve_path(cfg, "pdf"), resolve_path(cfg, "certs")
    fit_dir = signed_dir / str(mcfg["signed_subdir"])
    loop = asyncio.new_event_loop()
    rows: list[dict[str, Any]] = []
    try:
        for a, kb in todo:
            row = measure_one(cfg, loop, a, kb, pdf_dir, certs_dir, fit_dir)
            rows.append(row)
            log.info("%-11s %-17s +%9d B (%7.2f%%), CMS %6d B, placeholder %6d B (%.1f%% terpakai)", a,
                     row["pdf_name"], row["delta_bytes"], row["delta_percent"], row["cms_bytes"],
                     row["placeholder_bytes"], row["placeholder_used_percent"])
    finally:
        loop.close()

    keys_now = {(a, pdf_name_for(kb)) for a, kb in todo}
    kept = [r for r in existing if (r["alg"], r["pdf_name"]) not in keys_now]
    a_order = {a: i for i, a in enumerate(cfg["algorithms"])}
    s_order = {pdf_name_for(kb): i for i, kb in enumerate(cfg["pdf_sizes_kb"])}
    merged = sorted(kept + rows, key=lambda x: (a_order[x["alg"]], s_order[x["pdf_name"]]))
    write_csv(out_csv, S4_COLUMNS, merged)

    # reference: size of the S2 examples (fixed placeholder), when present
    s2_sizes = {f"{a}/{pdf_name_for(kb)}": (signed_dir / f"{a}_{size_label(kb)}.pdf").stat().st_size
                for a, kb in todo if (signed_dir / f"{a}_{size_label(kb)}.pdf").exists()}
    meta_path = out_dir / "s4_size_meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    meta.setdefault("runs", [])
    meta["runs"].append({
        "time": dt.datetime.now().astimezone().isoformat(timespec="seconds"), "smoke": smoke,
        "combinations": sorted(keys_now), "settings": mcfg,
        "s2_fixed_placeholder_hex_chars": int(cfg["signature_placeholder_bytes"]),
        "s2_signed_bytes_fixed_placeholder": s2_sizes, "signed_dir": str(fit_dir),
    })
    meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("Hasil ditulis ke %s (%d baris)", out_csv, len(merged))
    return merged


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    ap = base_arg_parser("S4: overhead ukuran berkas PDF bertanda tangan (SPEC 4.6)")
    ap.add_argument("--smoke", action="store_true", help="PDF terkecil saja, hasil terpisah")
    ap.add_argument("--only", help="hanya satu ID algoritma dari config")
    ap.add_argument("--force", action="store_true", help="hitung ulang walau hasil sudah ada")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config(args.config)
    if args.only and args.only not in cfg["algorithms"]:
        ap.error(f"--only harus salah satu dari: {', '.join(cfg['algorithms'])}")
    alg_ids = [args.only] if args.only else list(cfg["algorithms"])
    sizes = sorted(cfg["pdf_sizes_kb"])[:1] if args.smoke else list(cfg["pdf_sizes_kb"])
    signed = resolve_path(cfg, "signed")
    if args.smoke:
        signed = signed / str(cfg.get("smoke_results_subdir", "smoke"))
    run(cfg, alg_ids, sizes, results_dir(cfg, args.smoke), signed, args.smoke, args.force)
    return 0


if __name__ == "__main__":
    sys.exit(main())
