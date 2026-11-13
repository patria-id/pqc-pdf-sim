"""Scenario S1: raw keygen / sign / verify timing per algorithm (SPEC 4.3).

All algorithms run through the configured backend (`crypto_backend`), in
process, timed with ``time.perf_counter_ns`` around the backend call only.

Stabilisation (config ``bench``):
* pre-flight check of power source, Windows power mode and background load
  (a full run stops on problems unless ``--allow-noisy``);
* raised process priority and optional CPU pinning;
* interleaving: the iterations are split into ``rounds``; each round visits
  every algorithm in a seeded random order and runs a chunk of keygen, sign,
  verify. Slow drifts (thermal, frequency, background load) are thereby spread
  over all algorithms instead of hitting one of them;
* ``warmup`` unrecorded iterations before the first chunk of every (alg, op),
  ``chunk_warmup`` before each later chunk; Python GC paused inside chunks;
* per-chunk CPU load is recorded in ``s1_crypto_meta.json``.

Run: ``python -m src.bench_crypto --config config.yaml [--smoke] [--only <alg>] [--force] [--allow-noisy]``
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import random
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.common.backend import Backend, get_backend
from src.common.config import base_arg_parser, load_config, results_dir, run_counts
from src.common.csvio import read_csv, write_csv
from src.common.monitor import (ChunkProbe, NoisyEnvironment, preflight_issues, process_tuning, resolve_affinity,
                                snapshot)
from src.common.timer import gc_paused, time_call

log = logging.getLogger("bench_crypto")

S1_COLUMNS = ["alg", "operation", "iteration", "time_ns", "signature_bytes"]
OPERATIONS = ("keygen", "sign", "verify")


def messages(seed: int, alg_id: str, n: int, size: int) -> list[bytes]:
    """Deterministic random messages for one algorithm (stream independent of round order)."""
    rng = random.Random(f"{seed}:s1:{alg_id}")
    return [rng.randbytes(size) for _ in range(n)]


def chunk_sizes(iterations: int, rounds: int) -> list[int]:
    """Split `iterations` into at most `rounds` nearly equal positive chunks."""
    r = max(1, min(rounds, iterations))
    q, rem = divmod(iterations, r)
    return [q + (1 if i < rem else 0) for i in range(r)]


def round_order(seed: int, alg_ids: list[str], r: int) -> list[str]:
    """Seeded random algorithm order for round `r`."""
    order = list(alg_ids)
    random.Random(f"{seed}:s1:round:{r}").shuffle(order)
    return order


@dataclass
class AlgState:
    """Per-algorithm state carried across rounds."""

    alg_id: str
    backend: Backend
    key: Any
    msgs: list[bytes]
    next_msg: int = 0
    recorded: dict[str, int] = field(default_factory=lambda: {op: 0 for op in OPERATIONS})
    last_msgs: list[bytes] = field(default_factory=list)  # messages of the latest sign chunk

    def take(self, n: int) -> list[bytes]:
        out = self.msgs[self.next_msg:self.next_msg + n]
        self.next_msg += n
        return out


def run_chunk(st: AlgState, op: str, warm: int, n: int, no_gc: bool, rows: list[dict[str, Any]],
              sigs: list[bytes]) -> list[bytes]:
    """Run `warm` unrecorded + `n` recorded calls of `op`; returns signatures produced by `sign`."""
    be = st.backend

    def rec(ns: int, sig_len: int | str) -> None:
        rows.append({"alg": st.alg_id, "operation": op, "iteration": st.recorded[op],
                     "time_ns": ns, "signature_bytes": sig_len})
        st.recorded[op] += 1

    with gc_paused(no_gc):
        if op == "keygen":
            for i in range(warm + n):
                ns, _ = time_call(be.generate)
                if i >= warm:
                    rec(ns, "")
            return []
        if op == "sign":
            msgs = st.take(warm + n)
            out = []
            for i, m in enumerate(msgs):
                ns, sig = time_call(be.sign, st.key, m)
                out.append(sig)
                if i >= warm:
                    rec(ns, len(sig))
            st.last_msgs = msgs
            return out
        # verify: the signatures (and messages) of this chunk's sign phase
        for i, (m, s) in enumerate(zip(st.last_msgs, sigs, strict=True)):
            ns, ok = time_call(be.verify, st.key, s, m)
            if not ok:
                raise RuntimeError(f"{st.alg_id}: verifikasi gagal (verify #{st.recorded[op]})")
            if i >= warm:
                rec(ns, len(s))
        return []


def bench(cfg: dict[str, Any], alg_ids: list[str], iterations: int, warmup: int,
          chunk_log: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Interleaved benchmark of `alg_ids`; returns CSV rows (iteration numbers per alg/op)."""
    bcfg = cfg.get("bench", {})
    seed = int(cfg["seed"])
    no_gc = bool(bcfg.get("disable_gc", True))
    sizes = chunk_sizes(iterations, int(bcfg.get("rounds", 1)))
    cw = int(bcfg.get("chunk_warmup", 0))
    n_msgs = warmup + iterations + cw * (len(sizes) - 1)
    states = {}
    for a in alg_ids:
        be = get_backend(cfg, cfg["algorithms"][a]["subscriber"])
        states[a] = AlgState(a, be, be.generate(),
                             messages(seed, a, n_msgs, int(bcfg.get("s1_message_bytes", 32))))
    rows: list[dict[str, Any]] = []
    probe = ChunkProbe()
    for r, n in enumerate(sizes):
        order = round_order(seed, alg_ids, r)
        log.info("Ronde %d/%d (%d iterasi): %s", r + 1, len(sizes), n, " -> ".join(order))
        for a in order:
            st = states[a]
            warm = warmup if r == 0 else cw
            sigs: list[bytes] = []
            for op in OPERATIONS:
                start_it = st.recorded[op]
                probe.start()
                out = run_chunk(st, op, warm, n, no_gc, rows, sigs)
                info = probe.stop()
                if op == "sign":
                    sigs = out
                if chunk_log is not None:
                    chunk_log.append({"round": r, "alg": a, "operation": op, "warmup": warm,
                                      "first_iteration": start_it, "n": n, **info})
    return rows


def summarize(rows: list[dict[str, Any]], alg_id: str) -> str:
    """One-line median summary for logging."""
    parts = []
    for op in OPERATIONS:
        t = [int(r["time_ns"]) for r in rows if r["alg"] == alg_id and r["operation"] == op]
        if t:
            parts.append(f"{op} {statistics.median(t) / 1e6:.3f} ms")
    return ", ".join(parts)


def run(cfg: dict[str, Any], alg_ids: list[str], out_dir: Path, smoke: bool = False,
        force: bool = False, allow_noisy: bool = False) -> list[dict[str, Any]]:
    """Benchmark `alg_ids`; merge with existing results (existing algs are kept unless `force`)."""
    bcfg = cfg.get("bench", {})
    out = out_dir / "s1_crypto.csv"
    existing = read_csv(out, S1_COLUMNS)
    done = {r["alg"] for r in existing}
    todo = [a for a in alg_ids if force or a not in done]
    for a in alg_ids:
        if a not in todo:
            log.info("%s: sudah ada di %s, dilewati (pakai --force untuk mengukur ulang)", a, out.name)
    if not todo:
        return existing

    log.info("Pemeriksaan pra-run (beban CPU %ss) ...", bcfg.get("preflight_load_window_s", 5))
    env_before = snapshot(float(bcfg.get("preflight_load_window_s", 5)))
    issues = preflight_issues(env_before, float(bcfg.get("max_background_load_pct", 20)))
    for i in issues:
        log.warning("Pra-run: %s", i)
    if issues and not smoke and not allow_noisy:
        raise NoisyEnvironment("lingkungan belum siap untuk run penuh: " + "; ".join(issues)
                               + " (perbaiki, atau jalankan dengan --allow-noisy)")

    iterations, warmup = run_counts(cfg, smoke)
    chunk_log: list[dict[str, Any]] = []
    started = dt.datetime.now().astimezone()
    with process_tuning(bcfg.get("process_priority"), resolve_affinity(bcfg.get("cpu_affinity"))) as tuning:
        log.info("Proses: prioritas=%s, affinity=%s%s", tuning["priority"], tuning["affinity"],
                 f", galat={tuning['errors']}" if tuning["errors"] else "")
        new_rows = bench(cfg, todo, iterations, warmup, chunk_log)
    finished = dt.datetime.now().astimezone()
    env_after = snapshot(1.0)
    for a in todo:
        log.info("%s median: %s", a, summarize(new_rows, a))

    kept = [r for r in existing if r["alg"] not in todo]
    order = {a: i for i, a in enumerate(cfg["algorithms"])}
    merged = sorted(kept + new_rows, key=lambda r: (order[r["alg"]], OPERATIONS.index(r["operation"]),
                                                    int(r["iteration"])))
    write_csv(out, S1_COLUMNS, merged)

    meta_path = out_dir / "s1_crypto_meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    meta.setdefault("algorithms", {})
    meta.setdefault("runs", [])
    run_id = started.strftime("%Y%m%d_%H%M%S")
    for a in todo:
        be = get_backend(cfg, cfg["algorithms"][a]["subscriber"])
        meta["algorithms"][a] = {
            "run_id": run_id, "backend": be.name, "backend_version": be.version,
            "subscriber": cfg["algorithms"][a]["subscriber"], "iterations": iterations, "warmup": warmup,
            "smoke": smoke, "seed": int(cfg["seed"]),
        }
    meta["runs"].append({
        "run_id": run_id, "algorithms": todo, "started": started.isoformat(timespec="seconds"),
        "finished": finished.isoformat(timespec="seconds"), "smoke": smoke,
        "settings": {k: bcfg.get(k) for k in ("rounds", "chunk_warmup", "disable_gc", "s1_message_bytes",
                                              "process_priority", "cpu_affinity", "max_background_load_pct")},
        "process_tuning": tuning, "preflight_issues": issues, "allow_noisy": allow_noisy,
        "environment_before": env_before, "environment_after": env_after, "chunks": chunk_log,
    })
    meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("Hasil ditulis ke %s (%d baris)", out, len(merged))
    return merged


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    ap = base_arg_parser("S1: benchmark keygen/sign/verify (SPEC 4.3)")
    ap.add_argument("--smoke", action="store_true", help="iterasi smoke, hasil ke folder terpisah")
    ap.add_argument("--only", help="hanya satu ID algoritma dari config")
    ap.add_argument("--force", action="store_true", help="ukur ulang walau hasil sudah ada")
    ap.add_argument("--allow-noisy", action="store_true", help="tetap jalan walau pemeriksaan pra-run gagal")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config(args.config)
    if args.only and args.only not in cfg["algorithms"]:
        ap.error(f"--only harus salah satu dari: {', '.join(cfg['algorithms'])}")
    alg_ids = [args.only] if args.only else list(cfg["algorithms"])
    try:
        run(cfg, alg_ids, results_dir(cfg, args.smoke), args.smoke, args.force, args.allow_noisy)
    except NoisyEnvironment as exc:
        log.error("%s", exc)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
