"""Scenario S2: end-to-end PDF signing time, CPU% and peak RSS (SPEC 4.4).

One signing iteration (all timed together):
  1. open the original PDF (already in memory) with pyHanko's IncrementalPdfFileWriter;
  2. add an invisible signature field and a signature dictionary with a
     ``/Contents`` placeholder of ``signature_placeholder_bytes`` (hex chars),
     compute ``/ByteRange`` and its SHA-256 digest (pyHanko interrupted signing);
  3. build detached CMS SignedData (signedAttrs: contentType, messageDigest,
     signingTime; certificates: subscriber + PSrE [+ Root]) with asn1crypto, signing
     DER(signedAttrs) through the configured backend (`crypto_backend`);
  4. write the CMS into the placeholder (incremental update, in memory).

The same path is used for RSA and PQC so timings are comparable (CLAUDE.md
rule 4); pyHanko only prepares the PDF. Private keys and certificates are
loaded once per algorithm outside the timed region (like an open HSM session).
Measurements are interleaved over rounds like S1; CPU% / RSS are sampled by a
background thread (``ResourceSampler``). One signed example per (alg, size) is
saved to ``signed/<alg>_<size>.pdf`` and sanity-checked (not timed).

Run: ``python -m src.sign_pdf --config config.yaml [--smoke] [--only <alg>] [--force] [--allow-noisy]``
"""
from __future__ import annotations

import asyncio
import datetime as dt
import io
import json
import logging
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from asn1crypto import algos
from asn1crypto import x509 as ax509

from src.common.backend import get_backend
from src.common.cms import SignerContext, build_signed_data_from_digest, verify_cms_digest
from src.common.config import (base_arg_parser, load_config, pdf_name_for, resolve_path, results_dir,
                               run_counts, size_label)
from src.common.csvio import read_csv, write_csv
from src.common.monitor import (ChunkProbe, NoisyEnvironment, ResourceSampler, preflight, process_tuning,
                                resolve_affinity, snapshot)
from src.common.oids import sig_oid
from src.common.pki import ChainPaths, embedded_certs
from src.common.schedule import chunk_sizes, round_order
from src.common.timer import gc_paused
from src.common.util import pkg_version
from src.common.x509util import read_der, spki_of

log = logging.getLogger("sign_pdf")

S2_COLUMNS = ["alg", "pdf_name", "iteration", "time_ns", "cpu_percent_peak", "rss_peak_bytes"]


@dataclass
class Combo:
    """One (algorithm, PDF size) combination and its prepared signing state."""

    alg_id: str
    kb: int
    pdf_name: str
    pdf_bytes: bytes
    pdf_signer: Any                 # pyhanko PdfSigner
    ctx: SignerContext
    verify_spki: Any
    user_der: bytes
    recorded: int = 0
    last_output: bytes | None = None
    last_digest_cms: tuple[bytes, bytes] | None = None  # (ByteRange digest, CMS) of the last signing

    @property
    def signed_name(self) -> str:
        return f"{self.alg_id}_{size_label(self.kb)}.pdf"


def make_pdf_signer(field_name: str, alg: str, user_der: bytes, chain_der: list[bytes]) -> Any:
    """pyHanko PdfSigner used only to prepare the PDF (placeholder, ByteRange, digest)."""
    from pyhanko.sign import fields, signers
    from pyhanko_certvalidator.registry import SimpleCertificateStore

    ext = signers.ExternalSigner(
        signing_cert=ax509.Certificate.load(user_der),
        cert_registry=SimpleCertificateStore.from_certs([ax509.Certificate.load(d) for d in chain_der]),
        signature_value=b"",
        signature_mechanism=algos.SignedDigestAlgorithm({"algorithm": sig_oid(alg)}),
    )
    meta = signers.PdfSignatureMetadata(field_name=field_name, md_algorithm="sha256",
                                        subfilter=fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED)
    return signers.PdfSigner(meta, signer=ext)


def prepare_combo(cfg: dict[str, Any], alg_id: str, kb: int, pdf_dir: Path, certs_dir: Path) -> Combo:
    """Load PDF, keys and certificates for one combination (outside timing)."""
    spec = cfg["algorithms"][alg_id]
    pdf_path = pdf_dir / pdf_name_for(kb)
    chain = ChainPaths(certs_dir / alg_id)
    if not pdf_path.exists():
        raise FileNotFoundError(f"{pdf_path} tidak ada; jalankan dulu: python -m src.generate_pdfs")
    if not chain.complete():
        raise FileNotFoundError(f"sertifikat {alg_id} tidak lengkap; jalankan dulu: python -m src.build_pki")
    be = get_backend(cfg, spec["subscriber"])
    if be.load_private_pem is None or be.verify_spki is None:
        raise RuntimeError(f"backend {be.name} tidak mendukung kunci PEM / verifikasi SPKI")
    key = be.load_private_pem(chain["user.key"].read_bytes())
    user_der, extra = read_der(chain["user.crt"]), embedded_certs(cfg, chain)  # PSrE (+ Root)
    ctx = SignerContext.from_der(spec["subscriber"], lambda m, _k=key, _b=be: _b.sign(_k, m), user_der, extra)
    signer = make_pdf_signer(cfg["sign_pdf"]["field_name"], spec["subscriber"], user_der, extra)
    return Combo(alg_id, kb, pdf_path.name, pdf_path.read_bytes(), signer, ctx, be.verify_spki, user_der)


def sign_once(loop: asyncio.AbstractEventLoop, combo: Combo, placeholder: int) -> tuple[io.BytesIO, bytes, bytes]:
    """One complete signing of `combo`'s PDF. Returns (output stream, ByteRange digest, CMS DER)."""
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

    writer = IncrementalPdfFileWriter(io.BytesIO(combo.pdf_bytes))
    prep, _tbs, out = loop.run_until_complete(
        combo.pdf_signer.async_digest_doc_for_signing(writer, bytes_reserved=placeholder))
    cms_der = build_signed_data_from_digest(prep.document_digest, combo.ctx)
    if 2 * len(cms_der) > placeholder:
        raise ValueError(f"CMS {len(cms_der)} B tidak muat di placeholder {placeholder} karakter heks")
    prep.fill_with_cms(out, cms_der)
    return out, prep.document_digest, cms_der


def check_example(combo: Combo, digest: bytes, cms_der: bytes) -> dict[str, Any]:
    """Untimed sanity check of a produced signature (full verification is S3)."""
    res = verify_cms_digest(cms_der, digest,
                            lambda cert, sig, msg: combo.verify_spki(spki_of(cert), sig, msg))
    if not res["valid"]:
        raise RuntimeError(f"{combo.alg_id}/{combo.pdf_name}: tanda tangan hasil S2 tidak valid: {res}")
    return {"cms_bytes": len(cms_der), "signature_bytes": res["signature_bytes"],
            "signature_alg": res["signature_alg"]}


def run_chunk(loop: asyncio.AbstractEventLoop, combo: Combo, warm: int, n: int, placeholder: int,
              sampler: ResourceSampler, no_gc: bool, rows: list[dict[str, Any]]) -> None:
    """`warm` unrecorded + `n` recorded signings of one combination."""
    for i in range(warm + n):
        with gc_paused(no_gc):  # collects before, so garbage of earlier iterations is not in the window
            sampler.begin()
            t0 = time.perf_counter_ns()
            out, digest, cms_der = sign_once(loop, combo, placeholder)
            t1 = time.perf_counter_ns()
            cpu, rss = sampler.end()
        if i >= warm:
            rows.append({"alg": combo.alg_id, "pdf_name": combo.pdf_name, "iteration": combo.recorded,
                         "time_ns": t1 - t0, "cpu_percent_peak": cpu, "rss_peak_bytes": rss})
            combo.recorded += 1
        combo.last_output = out.getvalue()
        combo.last_digest_cms = (digest, cms_der)
        del out


def run(cfg: dict[str, Any], alg_ids: list[str], sizes_kb: list[int], out_dir: Path, signed_dir: Path,
        smoke: bool = False, force: bool = False, allow_noisy: bool = False) -> list[dict[str, Any]]:
    """Measure S2 for all (alg, size) combinations; merge with existing results unless `force`."""
    bcfg, scfg = cfg.get("bench", {}), cfg["sign_pdf"]
    out_csv = out_dir / "s2_sign.csv"
    existing = read_csv(out_csv, S2_COLUMNS)
    done = {(r["alg"], r["pdf_name"]) for r in existing}
    todo = [(a, kb) for a in alg_ids for kb in sizes_kb if force or (a, pdf_name_for(kb)) not in done]
    if not todo:
        log.info("Semua kombinasi sudah ada di %s, dilewati (pakai --force)", out_csv.name)
        return existing

    env_before, issues = preflight(bcfg, smoke, allow_noisy, log)
    iterations, warmup = run_counts(cfg, smoke)
    placeholder = int(cfg["signature_placeholder_bytes"])
    pdf_dir, certs_dir = resolve_path(cfg, "pdf"), resolve_path(cfg, "certs")
    combos = {(a, kb): prepare_combo(cfg, a, kb, pdf_dir, certs_dir) for a, kb in todo}
    sizes = chunk_sizes(iterations, int(bcfg.get("rounds", 1)))
    cw = int(bcfg.get("chunk_warmup", 0))
    no_gc = bool(bcfg.get("disable_gc", True))
    rows: list[dict[str, Any]] = []
    chunk_log: list[dict[str, Any]] = []
    probe = ChunkProbe()
    loop = asyncio.new_event_loop()
    started = dt.datetime.now().astimezone()
    try:
        with process_tuning(bcfg.get("process_priority"), resolve_affinity(bcfg.get("cpu_affinity"))) as tuning, \
                ResourceSampler(float(scfg["sample_interval_ms"]) / 1000,
                                float(scfg["cpu_min_window_ms"]) / 1000) as sampler:
            log.info("Proses: prioritas=%s, affinity=%s; %d kombinasi, %d iterasi + %d warm-up",
                     tuning["priority"], tuning["affinity"], len(combos), iterations, warmup)
            for r, n in enumerate(sizes):
                order = round_order(int(cfg["seed"]), "s2", list(combos), r)
                log.info("Ronde %d/%d (%d iterasi per kombinasi)", r + 1, len(sizes), n)
                for key in order:
                    c = combos[key]
                    warm = warmup if r == 0 else cw
                    first = c.recorded
                    probe.start()
                    run_chunk(loop, c, warm, n, placeholder, sampler, no_gc, rows)
                    chunk_log.append({"round": r, "alg": c.alg_id, "pdf_name": c.pdf_name, "warmup": warm,
                                      "first_iteration": first, "n": n, **probe.stop()})
    finally:
        loop.close()
    finished = dt.datetime.now().astimezone()

    examples: dict[str, Any] = {}
    signed_dir.mkdir(parents=True, exist_ok=True)
    for (a, kb), c in combos.items():
        assert c.last_output is not None and c.last_digest_cms is not None
        info = check_example(c, *c.last_digest_cms)
        (signed_dir / c.signed_name).write_bytes(c.last_output)
        t = [x["time_ns"] for x in rows if x["alg"] == a and x["pdf_name"] == c.pdf_name]
        examples[f"{a}/{c.pdf_name}"] = {"signed_file": c.signed_name, "signed_bytes": len(c.last_output), **info}
        log.info("%-11s %-17s median %9.3f ms, CMS %6d B -> %s", a, c.pdf_name,
                 statistics.median(t) / 1e6, info["cms_bytes"], c.signed_name)

    keys_now = {(a, pdf_name_for(kb)) for a, kb in todo}
    kept = [r for r in existing if (r["alg"], r["pdf_name"]) not in keys_now]
    a_order = {a: i for i, a in enumerate(cfg["algorithms"])}
    s_order = {pdf_name_for(kb): i for i, kb in enumerate(cfg["pdf_sizes_kb"])}
    merged = sorted(kept + rows, key=lambda x: (a_order[x["alg"]], s_order[x["pdf_name"]], int(x["iteration"])))
    write_csv(out_csv, S2_COLUMNS, merged)

    meta_path = out_dir / "s2_sign_meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    meta.setdefault("runs", [])
    be = get_backend(cfg, cfg["algorithms"][todo[0][0]]["subscriber"])
    meta["runs"].append({
        "run_id": started.strftime("%Y%m%d_%H%M%S"), "combinations": [f"{a}/{pdf_name_for(kb)}" for a, kb in todo],
        "started": started.isoformat(timespec="seconds"), "finished": finished.isoformat(timespec="seconds"),
        "smoke": smoke, "iterations": iterations, "warmup": warmup, "chunk_warmup": cw, "rounds": len(sizes),
        "placeholder_hex_chars": placeholder, "backend": be.name, "backend_version": be.version,
        "pyhanko_version": pkg_version("pyhanko"), "settings": {**scfg, "disable_gc": no_gc},
        "process_tuning": tuning, "preflight_issues": issues, "allow_noisy": allow_noisy,
        "environment_before": env_before, "environment_after": snapshot(1.0),
        "examples": examples, "chunks": chunk_log,
    })
    meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("Hasil ditulis ke %s (%d baris)", out_csv, len(merged))
    return merged


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    ap = base_arg_parser("S2: waktu tanda tangan PDF end-to-end (SPEC 4.4)")
    ap.add_argument("--smoke", action="store_true", help="iterasi smoke, PDF terkecil saja, hasil terpisah")
    ap.add_argument("--only", help="hanya satu ID algoritma dari config")
    ap.add_argument("--force", action="store_true", help="ukur ulang walau hasil sudah ada")
    ap.add_argument("--allow-noisy", action="store_true", help="tetap jalan walau pemeriksaan pra-run gagal")
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
    try:
        run(cfg, alg_ids, sizes, results_dir(cfg, args.smoke), signed, args.smoke, args.force, args.allow_noisy)
    except NoisyEnvironment as exc:
        log.error("%s", exc)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
