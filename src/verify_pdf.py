"""Scenario S3: end-to-end PDF signature verification time, CPU% and peak RSS (SPEC 4.5).

One verification iteration (all timed together), on the signed PDF already in memory:
  1. parse the PDF with pyHanko's PdfFileReader and take the first signature
     dictionary; read ``/ByteRange`` and the CMS in ``/Contents``;
  2. check ``/ByteRange``: starts at 0, covers the whole file (no later
     incremental update), and its gap is exactly the ``/Contents`` hex string;
  3. SHA-256 over the two ByteRange segments, compare with the CMS
     ``messageDigest``, check ``contentType`` and the signature algorithm OID;
  4. validate the path Root -> PSrE -> signer. The trust anchor is the simulated
     Root CA (``certs/<pki.root_dir>/root.crt``, loaded once); the PSrE certificate
     is taken from the CMS. PSrE: issued by the Root (signature over the
     TBSCertificate), valid at ``signingTime``, CA:TRUE, keyCertSign. Signer:
     issued by the PSrE, valid at ``signingTime``, CA:FALSE, keyUsage
     digitalSignature/nonRepudiation;
  5. verify the CMS signature over DER(signedAttrs) with the signer's public key.

All public-key operations go through the configured backend (``crypto_backend``),
the same for every algorithm. Measurement scheduling (interleaved rounds, warm-up,
priority/affinity, GC pause, CPU/RSS sampler) is identical to S2.

Run: ``python -m src.verify_pdf --config config.yaml [--smoke] [--only <alg>] [--force] [--allow-noisy]``
     ``python -m src.verify_pdf --config config.yaml --check``  (verify every PDF under signed/ once, untimed)
"""
from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import logging
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from asn1crypto import x509 as ax509

from src.common.backend import get_backend
from src.common.cms import der_length, verify_cms_digest
from src.common.config import (base_arg_parser, load_config, pdf_name_for, resolve_path, results_dir,
                               run_counts, size_label)
from src.common.csvio import read_csv, write_csv
from src.common.monitor import (ChunkProbe, NoisyEnvironment, ResourceSampler, preflight, process_tuning,
                                resolve_affinity, snapshot)
from src.common.oids import sig_oid
from src.common.pki import root_paths
from src.common.schedule import chunk_sizes, round_order
from src.common.timer import gc_paused
from src.common.util import pkg_version, short_err
from src.common.x509util import read_der, same_name, spki_of, verify_issued_by

log = logging.getLogger("verify_pdf")

S3_COLUMNS = ["alg", "pdf_name", "iteration", "time_ns", "cpu_percent_peak", "rss_peak_bytes", "valid"]
SIGNER_KEY_USAGES = {"digital_signature", "non_repudiation"}


@dataclass
class Trust:
    """Verification state for one algorithm, prepared once (outside timing)."""

    sub_alg: str                                    # expected subscriber algorithm, e.g. 'ML-DSA-44'
    root_der: bytes                                 # trust anchor (simulated Root CA certificate)
    verify_sub: Callable[[bytes, bytes, bytes], bool]   # (spki, signature, message) -> bool
    verify_ca: Callable[[bytes, bytes, bytes], bool]    # PSrE algorithm
    verify_root: Callable[[bytes, bytes, bytes], bool]  # Root algorithm

    @property
    def expected_oid(self) -> str:
        return sig_oid(self.sub_alg)


def load_trust(cfg: dict[str, Any], alg_id: str, certs_dir: Path) -> Trust:
    """Trust anchor (shared Root CA) and verification backends for `alg_id`."""
    spec = cfg["algorithms"][alg_id]
    root_crt = root_paths(cfg, certs_dir)["root.crt"]
    if not root_crt.exists():
        raise FileNotFoundError(f"{root_crt} tidak ada; jalankan dulu: python -m src.build_pki")
    bes = [get_backend(cfg, a) for a in (spec["subscriber"], spec["ca"], cfg["pki"]["root_alg"])]
    if any(b.verify_spki is None for b in bes):
        raise RuntimeError("backend tidak mendukung verifikasi dari SPKI")
    return Trust(spec["subscriber"], read_der(root_crt), *(b.verify_spki for b in bes))


def check_byte_range(data: bytes, br: list[int]) -> str | None:
    """None if /ByteRange is well-formed and covers the whole file except the /Contents hex string."""
    if len(br) != 4:
        return "ByteRange tidak berisi 4 angka"
    a, b, c, d = br
    if a != 0 or b <= 0 or c <= b or d < 0 or c + d != len(data):
        return "ByteRange tidak mencakup seluruh berkas"
    if data[b:b + 1] != b"<" or data[c - 1:c] != b">":
        return "celah ByteRange bukan string heks /Contents"
    return None


def _valid_at(cert: ax509.Certificate, when: dt.datetime | None) -> bool:
    validity = cert["tbs_certificate"]["validity"]
    return when is not None and validity["not_before"].native <= when <= validity["not_after"].native


def check_signer_cert(cert_der: bytes, certs_der: list[bytes], signing_time: dt.datetime | None,
                      trust: Trust) -> str | None:
    """None if the path Root -> PSrE -> signer is valid and the signer fits a signing certificate profile.

    The PSrE certificate is looked up among `certs_der` (the certificates embedded in the CMS);
    the Root is the trust anchor, never taken from the CMS.
    """
    cert = ax509.Certificate.load(cert_der)
    psre_der = next((d for d in certs_der
                     if d != cert_der and same_name(ax509.Certificate.load(d).subject, cert.issuer)), None)
    if psre_der is None:
        return "sertifikat PSrE penerbit tidak ada di CMS"
    if psre_der == trust.root_der:
        return "sertifikat penanda tangan diterbitkan langsung oleh Root (tanpa PSrE)"
    if not verify_issued_by(psre_der, trust.root_der, trust.verify_root):
        return "sertifikat PSrE tidak diterbitkan oleh Root CA simulasi"
    psre = ax509.Certificate.load(psre_der)
    if not _valid_at(psre, signing_time):
        return "sertifikat PSrE tidak berlaku pada signingTime"
    if not psre.ca or psre.key_usage_value is None or "key_cert_sign" not in psre.key_usage_value.native:
        return "sertifikat PSrE bukan CA penerbit (basicConstraints/keyUsage)"
    if not verify_issued_by(cert_der, psre_der, trust.verify_ca):
        return "sertifikat penanda tangan tidak diterbitkan oleh PSrE"
    if not _valid_at(cert, signing_time):
        return "sertifikat tidak berlaku pada signingTime"
    if cert.ca:
        return "sertifikat penanda tangan adalah sertifikat CA"
    ku = cert.key_usage_value
    if ku is None or not (SIGNER_KEY_USAGES & set(ku.native)):
        return "keyUsage sertifikat tidak mengizinkan tanda tangan"
    return None


def verify_pdf_bytes(data: bytes, trust: Trust) -> dict[str, Any]:
    """Full verification of the first signature in `data`; never raises (errors -> valid=False)."""
    from pyhanko.pdf_utils.reader import PdfFileReader

    out: dict[str, Any] = {"valid": False, "reason": None}
    try:
        sigs = PdfFileReader(io.BytesIO(data), strict=False).embedded_signatures
        if not sigs:
            out["reason"] = "tidak ada tanda tangan"
            return out
        sig = sigs[0]
        br = [int(x) for x in sig.sig_object["/ByteRange"]]
        cms_der = sig.pkcs7_content
        reason = check_byte_range(data, br)
        if reason is None and bytes.fromhex(data[br[1] + 1:br[2] - 1].decode("ascii")) != cms_der:
            reason = "isi celah ByteRange berbeda dengan /Contents"
        if reason:
            out["reason"] = reason
            return out
        view = memoryview(data)
        h = hashlib.sha256(view[br[0]:br[0] + br[1]])
        h.update(view[br[2]:br[2] + br[3]])
        res = verify_cms_digest(cms_der, h.digest(),
                                lambda cert, s, m: trust.verify_sub(spki_of(cert), s, m))
        out.update(digest_ok=res["digest_ok"], signature_ok=res["signature_ok"],
                   cms_bytes=der_length(cms_der), signature_bytes=res["signature_bytes"])
        if not res["digest_ok"]:
            out["reason"] = "messageDigest tidak cocok dengan isi ByteRange"
        elif not res["content_type_ok"]:
            out["reason"] = "contentType bukan data"
        elif res["signature_alg"] != trust.expected_oid:
            out["reason"] = f"algoritma tanda tangan {res['signature_alg']} != {trust.expected_oid}"
        elif (reason := check_signer_cert(res["signer_cert_der"], res["certs_der"], res["signing_time"], trust)) is not None:
            out["reason"] = reason
        elif not res["signature_ok"]:
            out["reason"] = "tanda tangan CMS tidak valid"
        else:
            out["valid"] = True
    except Exception as exc:  # malformed / tampered input must yield valid=False, not abort the run
        out["reason"] = f"galat: {short_err(exc)}"
    return out


@dataclass
class Combo:
    """One (algorithm, PDF size) combination: the signed PDF and its trust state."""

    alg_id: str
    pdf_name: str
    signed_name: str
    data: bytes
    trust: Trust
    recorded: int = 0
    invalid: int = 0
    last_result: dict[str, Any] | None = None


def signed_name_for(alg_id: str, kb: int) -> str:
    """File name used by sign_pdf for the signed example of (alg, size)."""
    return f"{alg_id}_{size_label(kb)}.pdf"


def prepare_combo(cfg: dict[str, Any], alg_id: str, kb: int, signed_dir: Path, certs_dir: Path) -> Combo:
    """Load the signed PDF produced by S2 and the trust anchor (outside timing)."""
    name = signed_name_for(alg_id, kb)
    path = signed_dir / name
    if not path.exists():
        raise FileNotFoundError(f"{path} tidak ada; jalankan dulu: python -m src.sign_pdf")
    return Combo(alg_id, pdf_name_for(kb), name, path.read_bytes(), load_trust(cfg, alg_id, certs_dir))


def run_chunk(combo: Combo, warm: int, n: int, sampler: ResourceSampler, no_gc: bool,
              rows: list[dict[str, Any]]) -> None:
    """`warm` unrecorded + `n` recorded verifications of one combination."""
    for i in range(warm + n):
        with gc_paused(no_gc):
            sampler.begin()
            t0 = time.perf_counter_ns()
            res = verify_pdf_bytes(combo.data, combo.trust)
            t1 = time.perf_counter_ns()
            cpu, rss = sampler.end()
        if i >= warm:
            rows.append({"alg": combo.alg_id, "pdf_name": combo.pdf_name, "iteration": combo.recorded,
                         "time_ns": t1 - t0, "cpu_percent_peak": cpu, "rss_peak_bytes": rss,
                         "valid": res["valid"]})
            combo.recorded += 1
            combo.invalid += not res["valid"]
        combo.last_result = res


def run(cfg: dict[str, Any], alg_ids: list[str], sizes_kb: list[int], out_dir: Path, signed_dir: Path,
        smoke: bool = False, force: bool = False, allow_noisy: bool = False) -> list[dict[str, Any]]:
    """Measure S3 for all (alg, size) combinations; merge with existing results unless `force`."""
    bcfg, vcfg = cfg.get("bench", {}), cfg["verify_pdf"]
    out_csv = out_dir / "s3_verify.csv"
    existing = read_csv(out_csv, S3_COLUMNS)
    done = {(r["alg"], r["pdf_name"]) for r in existing}
    todo = [(a, kb) for a in alg_ids for kb in sizes_kb if force or (a, pdf_name_for(kb)) not in done]
    if not todo:
        log.info("Semua kombinasi sudah ada di %s, dilewati (pakai --force)", out_csv.name)
        return existing

    certs_dir = resolve_path(cfg, "certs")
    combos = {(a, kb): prepare_combo(cfg, a, kb, signed_dir, certs_dir) for a, kb in todo}
    for c in combos.values():  # untimed sanity check before spending time on measurements
        res = verify_pdf_bytes(c.data, c.trust)
        if not res["valid"]:
            raise RuntimeError(f"{c.signed_name} tidak valid sebelum pengukuran: {res['reason']}")
    env_before, issues = preflight(bcfg, smoke, allow_noisy, log)
    iterations, warmup = run_counts(cfg, smoke)
    sizes = chunk_sizes(iterations, int(bcfg.get("rounds", 1)))
    cw = int(bcfg.get("chunk_warmup", 0))
    no_gc = bool(bcfg.get("disable_gc", True))
    rows: list[dict[str, Any]] = []
    chunk_log: list[dict[str, Any]] = []
    probe = ChunkProbe()
    started = dt.datetime.now().astimezone()
    with process_tuning(bcfg.get("process_priority"), resolve_affinity(bcfg.get("cpu_affinity"))) as tuning, \
            ResourceSampler(float(vcfg["sample_interval_ms"]) / 1000,
                            float(vcfg["cpu_min_window_ms"]) / 1000) as sampler:
        log.info("Proses: prioritas=%s, affinity=%s; %d kombinasi, %d iterasi + %d warm-up",
                 tuning["priority"], tuning["affinity"], len(combos), iterations, warmup)
        for r, n in enumerate(sizes):
            order = round_order(int(cfg["seed"]), "s3", list(combos), r)
            log.info("Ronde %d/%d (%d iterasi per kombinasi)", r + 1, len(sizes), n)
            for key in order:
                c = combos[key]
                warm = warmup if r == 0 else cw
                first = c.recorded
                probe.start()
                run_chunk(c, warm, n, sampler, no_gc, rows)
                chunk_log.append({"round": r, "alg": c.alg_id, "pdf_name": c.pdf_name, "warmup": warm,
                                  "first_iteration": first, "n": n, **probe.stop()})
    finished = dt.datetime.now().astimezone()

    summary: dict[str, Any] = {}
    for (a, kb), c in combos.items():
        t = [x["time_ns"] for x in rows if x["alg"] == a and x["pdf_name"] == c.pdf_name]
        last = c.last_result or {}
        summary[f"{a}/{c.pdf_name}"] = {"signed_file": c.signed_name, "signed_bytes": len(c.data),
                                        "invalid_iterations": c.invalid, "cms_bytes": last.get("cms_bytes"),
                                        "signature_bytes": last.get("signature_bytes")}
        level = logging.INFO if c.invalid == 0 else logging.ERROR
        log.log(level, "%-11s %-17s median %9.3f ms, tidak valid %d/%d", a, c.pdf_name,
                statistics.median(t) / 1e6, c.invalid, c.recorded)

    keys_now = {(a, pdf_name_for(kb)) for a, kb in todo}
    kept = [r for r in existing if (r["alg"], r["pdf_name"]) not in keys_now]
    a_order = {a: i for i, a in enumerate(cfg["algorithms"])}
    s_order = {pdf_name_for(kb): i for i, kb in enumerate(cfg["pdf_sizes_kb"])}
    merged = sorted(kept + rows, key=lambda x: (a_order[x["alg"]], s_order[x["pdf_name"]], int(x["iteration"])))
    write_csv(out_csv, S3_COLUMNS, merged)

    meta_path = out_dir / "s3_verify_meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    meta.setdefault("runs", [])
    be = get_backend(cfg, cfg["algorithms"][todo[0][0]]["subscriber"])
    meta["runs"].append({
        "run_id": started.strftime("%Y%m%d_%H%M%S"), "combinations": [f"{a}/{pdf_name_for(kb)}" for a, kb in todo],
        "started": started.isoformat(timespec="seconds"), "finished": finished.isoformat(timespec="seconds"),
        "smoke": smoke, "iterations": iterations, "warmup": warmup, "chunk_warmup": cw, "rounds": len(sizes),
        "backend": be.name, "backend_version": be.version, "pyhanko_version": pkg_version("pyhanko"),
        "settings": {**vcfg, "disable_gc": no_gc}, "process_tuning": tuning, "preflight_issues": issues,
        "allow_noisy": allow_noisy, "environment_before": env_before, "environment_after": snapshot(1.0),
        "combinations_summary": summary, "chunks": chunk_log,
    })
    meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("Hasil ditulis ke %s (%d baris)", out_csv, len(merged))
    return merged


def check_all(cfg: dict[str, Any], signed_root: Path) -> list[tuple[Path, dict[str, Any]]]:
    """Verify every ``<alg>_<size>.pdf`` under `signed_root` once (untimed)."""
    certs_dir = resolve_path(cfg, "certs")
    trusts: dict[str, Trust] = {}
    results = []
    for path in sorted(signed_root.rglob("*.pdf")):
        alg_id = path.stem.rsplit("_", 1)[0]
        if alg_id not in cfg["algorithms"]:
            results.append((path, {"valid": False, "reason": f"algoritma '{alg_id}' tidak dikenal"}))
            continue
        if alg_id not in trusts:
            trusts[alg_id] = load_trust(cfg, alg_id, certs_dir)
        results.append((path, verify_pdf_bytes(path.read_bytes(), trusts[alg_id])))
    return results


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Exit codes: 0 OK, 3 pre-flight failed, 4 a signature was not valid."""
    ap = base_arg_parser("S3: waktu verifikasi tanda tangan PDF end-to-end (SPEC 4.5)")
    ap.add_argument("--smoke", action="store_true", help="iterasi smoke, PDF terkecil saja, hasil terpisah")
    ap.add_argument("--only", help="hanya satu ID algoritma dari config")
    ap.add_argument("--force", action="store_true", help="ukur ulang walau hasil sudah ada")
    ap.add_argument("--allow-noisy", action="store_true", help="tetap jalan walau pemeriksaan pra-run gagal")
    ap.add_argument("--check", action="store_true", help="verifikasi sekali semua PDF di folder signed/ (tanpa ukur)")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config(args.config)
    signed = resolve_path(cfg, "signed")
    if args.check:
        results = check_all(cfg, signed)
        for path, res in results:
            log.info("%-45s %s%s", path.relative_to(signed), "valid" if res["valid"] else "TIDAK VALID",
                     "" if res["valid"] else f" ({res['reason']})")
        bad = sum(not r["valid"] for _, r in results)
        log.info("%d berkas diperiksa, %d tidak valid", len(results), bad)
        return 4 if bad or not results else 0
    if args.only and args.only not in cfg["algorithms"]:
        ap.error(f"--only harus salah satu dari: {', '.join(cfg['algorithms'])}")
    alg_ids = [args.only] if args.only else list(cfg["algorithms"])
    sizes = sorted(cfg["pdf_sizes_kb"])[:1] if args.smoke else list(cfg["pdf_sizes_kb"])
    if args.smoke:
        signed = signed / str(cfg.get("smoke_results_subdir", "smoke"))
    try:
        rows = run(cfg, alg_ids, sizes, results_dir(cfg, args.smoke), signed, args.smoke, args.force,
                   args.allow_noisy)
    except NoisyEnvironment as exc:
        log.error("%s", exc)
        return 3
    return 4 if any(str(r["valid"]) != "True" for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
