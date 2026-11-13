"""Statistics, significance tests, paper tables and figures (SPEC 4.8).

Inputs (results folder of the mode): s1_crypto.csv, s2_sign.csv, s3_verify.csv,
s4_size.csv, plus cert_sizes.csv from results/. Missing scenarios are skipped.

Outputs:
* ``summary.csv``       – per (scenario, alg, group): n, median/mean/std/p25/p75/p95 (ms),
                          ratio of medians vs ``analyze.reference_alg``; CPU%/RSS for S2/S3;
* ``significance.csv``  – Kruskal–Wallis across algorithms per (scenario, group) with
                          epsilon², then Mann–Whitney (two-sided) of every algorithm vs the
                          reference with rank-biserial r and Holm correction per family;
* ``tables_for_paper.md``;
* figures (``figures/``, ``analyze.dpi``, Indonesian labels).

Run: ``python -m src.analyze --config config.yaml [--smoke]``
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

import pandas as pd

from src.common.config import base_arg_parser, load_config, pdf_name_for, resolve_path, results_dir
from src.common.csvio import write_csv

log = logging.getLogger("analyze")

SUMMARY_COLUMNS = ["scenario", "alg", "group", "n", "median_ms", "mean_ms", "std_ms", "p25_ms", "p75_ms",
                   "p95_ms", "ratio_median_vs_ref", "cpu_percent_mean", "rss_peak_median_bytes", "valid_percent"]
SIGNIFICANCE_COLUMNS = ["scenario", "group", "test", "alg", "reference", "n_alg", "n_ref", "statistic", "p_value",
                        "p_holm", "significant", "effect_size", "effect_measure", "ratio_median_vs_ref"]
SCENARIOS = {"S1": ("s1_crypto.csv", "operation"), "S2": ("s2_sign.csv", "pdf_name"),
             "S3": ("s3_verify.csv", "pdf_name")}
OPERATION_LABELS = {"keygen": "Pembangkitan kunci", "sign": "Tanda tangan", "verify": "Verifikasi"}


# --------------------------------------------------------------------------- helpers
def alg_label(cfg: dict[str, Any], alg_id: str) -> str:
    """Short display name of an algorithm (e.g. 'SLH-DSA-128s')."""
    return str(cfg["algorithms"][alg_id]["subscriber"]).replace("SHA2-", "")


def size_text(kb: int) -> str:
    """'100 KB', '1 MB', '10 MB'."""
    return f"{kb // 1024} MB" if kb >= 1024 and kb % 1024 == 0 else f"{kb} KB"


def fmt_id(x: float | None, nd: int = 2) -> str:
    """Indonesian number format: '.' thousands, ',' decimals."""
    if x is None or pd.isna(x):
        return "–"
    s = f"{x:,.{nd}f}"
    return s.replace(",", "_").replace(".", ",").replace("_", ".")


def fmt_ratio(r: float | None) -> str:
    """Ratio with enough decimals to stay non-zero (e.g. '0,0033×')."""
    if r is None or pd.isna(r):
        return "–"
    nd = 2 if abs(r) >= 0.1 else (3 if abs(r) >= 0.01 else 4)
    return fmt_id(r, nd) + "×"


def fmt_p(p: float) -> str:
    """p-value for tables (scientific, Indonesian decimal comma)."""
    if p == 0:
        return "< 1e-300"
    return f"{p:.2e}".replace(".", ",") if p < 0.001 else fmt_id(p, 3)


def ordered_groups(cfg: dict[str, Any], scenario: str, groups: list[str]) -> list[str]:
    """Operations in SPEC order, PDF names by size."""
    if scenario == "S1":
        order = ["keygen", "sign", "verify"]
    else:
        order = [pdf_name_for(kb) for kb in sorted(cfg["pdf_sizes_kb"])]
    return [g for g in order if g in groups] + sorted(g for g in groups if g not in order)


def ordered_algs(cfg: dict[str, Any], algs: Any) -> list[str]:
    """Algorithms in config order."""
    present = set(algs)
    return [a for a in cfg["algorithms"] if a in present]


def holm(pvalues: list[float]) -> list[float]:
    """Holm–Bonferroni adjusted p-values (same order as input)."""
    m = len(pvalues)
    order = sorted(range(m), key=lambda i: pvalues[i])
    adj = [0.0] * m
    running = 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (m - rank) * pvalues[i]))
        adj[i] = running
    return adj


def load_scenarios(out_dir: Path) -> dict[str, pd.DataFrame]:
    """Read the S1–S3 CSVs that exist."""
    data = {}
    for sc, (name, _) in SCENARIOS.items():
        path = out_dir / name
        if path.exists():
            data[sc] = pd.read_csv(path)
        else:
            log.warning("%s tidak ada, %s dilewati", path.name, sc)
    return data


# --------------------------------------------------------------------------- statistics
def summarize(cfg: dict[str, Any], data: dict[str, pd.DataFrame]) -> list[dict[str, Any]]:
    """Descriptive statistics per (scenario, alg, group)."""
    ref = cfg["analyze"]["reference_alg"]
    rows: list[dict[str, Any]] = []
    for sc, df in data.items():
        gcol = SCENARIOS[sc][1]
        for g in ordered_groups(cfg, sc, list(df[gcol].unique())):
            sub = df[df[gcol] == g]
            ref_t = sub[sub["alg"] == ref]["time_ns"]
            ref_med = float(ref_t.median()) if len(ref_t) else None
            for a in ordered_algs(cfg, sub["alg"].unique()):
                x = sub[sub["alg"] == a]
                t = x["time_ns"] / 1e6
                rows.append({
                    "scenario": sc, "alg": a, "group": g, "n": len(t),
                    "median_ms": round(t.median(), 6), "mean_ms": round(t.mean(), 6),
                    "std_ms": round(t.std(ddof=1), 6) if len(t) > 1 else 0.0,
                    "p25_ms": round(t.quantile(0.25), 6), "p75_ms": round(t.quantile(0.75), 6),
                    "p95_ms": round(t.quantile(0.95), 6),
                    "ratio_median_vs_ref": round(x["time_ns"].median() / ref_med, 4) if ref_med else "",
                    "cpu_percent_mean": round(x["cpu_percent_peak"].mean(), 2) if "cpu_percent_peak" in x else "",
                    "rss_peak_median_bytes": int(x["rss_peak_bytes"].median()) if "rss_peak_bytes" in x else "",
                    "valid_percent": (round(100 * x["valid"].astype(str).eq("True").mean(), 2)
                                      if "valid" in x else ""),
                })
    return rows


def significance(cfg: dict[str, Any], data: dict[str, pd.DataFrame]) -> list[dict[str, Any]]:
    """Kruskal–Wallis per (scenario, group), then Mann–Whitney vs the reference with Holm correction."""
    from scipy.stats import kruskal, mannwhitneyu

    acfg = cfg["analyze"]
    ref, alpha = acfg["reference_alg"], float(acfg["alpha"])
    rows: list[dict[str, Any]] = []
    for sc, df in data.items():
        gcol = SCENARIOS[sc][1]
        for g in ordered_groups(cfg, sc, list(df[gcol].unique())):
            sub = df[df[gcol] == g]
            algs = ordered_algs(cfg, sub["alg"].unique())
            samples = {a: sub[sub["alg"] == a]["time_ns"].to_numpy() for a in algs}
            if len(algs) < 2:
                continue
            h, p = kruskal(*samples.values())
            n_total = sum(len(s) for s in samples.values())
            rows.append({"scenario": sc, "group": g, "test": "kruskal_wallis", "alg": "semua", "reference": "",
                         "n_alg": n_total, "n_ref": "", "statistic": round(float(h), 4), "p_value": float(p),
                         "p_holm": "", "significant": bool(p < alpha),
                         "effect_size": round(float(h) / (n_total - 1), 4), "effect_measure": "epsilon_squared",
                         "ratio_median_vs_ref": ""})
            if ref not in samples:
                continue
            fam = []
            for a in algs:
                if a == ref:
                    continue
                x, y = samples[a], samples[ref]
                u, pu = mannwhitneyu(x, y, alternative="two-sided")
                fam.append({"scenario": sc, "group": g, "test": "mann_whitney", "alg": a, "reference": ref,
                            "n_alg": len(x), "n_ref": len(y), "statistic": float(u), "p_value": float(pu),
                            "effect_size": round(2 * float(u) / (len(x) * len(y)) - 1, 4),
                            "effect_measure": "rank_biserial_r",
                            "ratio_median_vs_ref": round(float(pd.Series(x).median() / pd.Series(y).median()), 4)})
            for row, padj in zip(fam, holm([r["p_value"] for r in fam])):
                row["p_holm"] = padj
                row["significant"] = bool(padj < alpha)
                rows.append(row)
    return rows


# --------------------------------------------------------------------------- tables
def md_table(header: list[str], rows: list[list[str]], align: str | None = None) -> str:
    """Markdown table; first column left, the rest right-aligned unless `align` is given."""
    align = align or ("l" + "r" * (len(header) - 1))
    sep = ["---" if c == "l" else "---:" for c in align]
    lines = ["| " + " | ".join(header) + " |", "| " + " | ".join(sep) + " |"]
    lines += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(lines)


def tables_markdown(cfg: dict[str, Any], summary: pd.DataFrame, sig: pd.DataFrame, s4: pd.DataFrame | None,
                    cert_sizes: pd.DataFrame | None, sigbytes: dict[str, int], sysinfo: dict[str, Any] | None,
                    smoke: bool) -> str:
    """All paper tables as Markdown (Indonesian)."""
    ref = cfg["analyze"]["reference_alg"]
    ref_label = alg_label(cfg, ref)
    parts = ["# Tabel untuk Paper", ""]
    if smoke:
        parts += ["> **Mode smoke**: jumlah iterasi kecil, hanya untuk uji alur. Jangan dipakai di paper.", ""]
    if sysinfo:
        cpu = sysinfo.get("cpu", {})
        lc = (sysinfo.get("openssl") or {}).get("libcrypto_ctypes", {}) or {}
        parts += [f"Lingkungan: {cpu.get('model', '?')} ({cpu.get('physical_cores', '?')} inti / "
                  f"{cpu.get('logical_cores', '?')} utas), {(sysinfo.get('os') or {}).get('system', '')} "
                  f"{(sysinfo.get('os') or {}).get('release', '')}, Python "
                  f"{(sysinfo.get('python') or {}).get('version', '?')}, backend {sysinfo.get('crypto_backend')} "
                  f"({lc.get('version_text', '?')}).", ""]
    n_note = ""
    if not summary.empty:
        n_note = f" n = {int(summary['n'].median())} per sel."
    num = 1

    def median_of(sc: str, a: str, g: str) -> float | None:
        x = summary[(summary.scenario == sc) & (summary.alg == a) & (summary.group == g)]
        return float(x["median_ms"].iloc[0]) if len(x) else None

    def ratio_of(sc: str, a: str, g: str) -> float | None:
        x = summary[(summary.scenario == sc) & (summary.alg == a) & (summary.group == g)]
        v = x["ratio_median_vs_ref"].iloc[0] if len(x) else None
        return None if v in ("", None) or pd.isna(v) else float(v)

    if "S1" in set(summary.scenario):
        s = summary[summary.scenario == "S1"]
        ops = ordered_groups(cfg, "S1", list(s.group.unique()))
        header = ["Algoritma"] + [f"{OPERATION_LABELS.get(o, o)} (ms)" for o in ops] + \
                 [f"{OPERATION_LABELS.get(o, o)} vs {ref_label}" for o in ops if o != "keygen"]
        rows = []
        for a in ordered_algs(cfg, s.alg.unique()):
            rows.append([alg_label(cfg, a)] + [fmt_id(median_of("S1", a, o), 3) for o in ops] +
                        [fmt_ratio(ratio_of("S1", a, o)) for o in ops if o != "keygen"])
        parts += [f"## Tabel {num}. Waktu operasi kriptografi murni (S1, median)", "", md_table(header, rows), "",
                  f"Pesan 32 byte; RSA memakai PKCS#1 v1.5 + SHA-256, ML-DSA/SLH-DSA mode murni.{n_note}", ""]
        num += 1

    for sc, title in (("S2", "Waktu tanda tangan PDF end-to-end (S2, median)"),
                      ("S3", "Waktu verifikasi PDF end-to-end (S3, median)")):
        if sc not in set(summary.scenario):
            continue
        s = summary[summary.scenario == sc]
        groups = ordered_groups(cfg, sc, list(s.group.unique()))
        kb_of = {pdf_name_for(kb): kb for kb in cfg["pdf_sizes_kb"]}
        header = ["Algoritma"] + [f"{size_text(kb_of[g])} (ms)" for g in groups] + \
                 [f"{size_text(kb_of[g])} vs {ref_label}" for g in groups]
        rows = []
        for a in ordered_algs(cfg, s.alg.unique()):
            rows.append([alg_label(cfg, a)] + [fmt_id(median_of(sc, a, g), 2) for g in groups] +
                        [fmt_ratio(ratio_of(sc, a, g)) for g in groups])
        note = ("Mencakup persiapan PDF (pyHanko), pembuatan CMS, dan tanda tangan." if sc == "S2" else
                "Mencakup parsing PDF, cek ByteRange, hash, validasi rantai pemilik → PSrE → Root CA, dan verifikasi CMS.")
        parts += [f"## Tabel {num}. {title}", "", md_table(header, rows), "", note + n_note, ""]
        num += 1

    if s4 is not None and len(s4):
        groups = ordered_groups(cfg, "S4", list(s4.pdf_name.unique()))
        kb_of = {pdf_name_for(kb): kb for kb in cfg["pdf_sizes_kb"]}
        header = ["Algoritma", "Δ ukuran (B)"] + [f"Δ {size_text(kb_of[g])} (%)" for g in groups] + \
                 ["CMS (B)", "Signature (B)", "Sertifikat di CMS (B)"]
        rows = []
        for a in ordered_algs(cfg, s4.alg.unique()):
            x = s4[s4.alg == a].set_index("pdf_name")
            first = x.loc[groups[0]]
            rows.append([alg_label(cfg, a), fmt_id(float(x["delta_bytes"].median()), 0)] +
                        [fmt_id(float(x.loc[g, "delta_percent"]), 2) for g in groups] +
                        [fmt_id(float(first["cms_bytes"]), 0), fmt_id(float(first["signature_bytes"]), 0),
                         fmt_id(float(first["chain_bytes"]), 0)])
        parts += [f"## Tabel {num}. Pertambahan ukuran berkas PDF (S4)", "", md_table(header, rows), "",
                  "Placeholder `/Contents` seukuran CMS + margin (lihat README). Δ ukuran = median antar ukuran PDF.",
                  ""]
        num += 1

    if cert_sizes is not None and len(cert_sizes):
        header = ["Algoritma", "Kunci publik pemilik (B, SPKI)", "Signature (B)", "Sertifikat pemilik (B)",
                  "Algoritma PSrE", "Sertifikat PSrE (B)", "Rantai di CMS (B)"]
        rows = []
        for a in ordered_algs(cfg, cert_sizes.alg.unique()):
            r = cert_sizes[cert_sizes.alg == a].iloc[0]
            rows.append([alg_label(cfg, a), fmt_id(float(r.user_pubkey_bytes), 0),
                         fmt_id(float(sigbytes[a]), 0) if a in sigbytes else "–",
                         fmt_id(float(r.user_cert_der_bytes), 0), str(r.ca_alg).replace("SHA2-", ""),
                         fmt_id(float(r.ca_cert_der_bytes), 0), fmt_id(float(r.chain_der_bytes), 0)])
        parts += [f"## Tabel {num}. Ukuran kunci publik, signature, dan sertifikat", "",
                  md_table(header, rows, "lrrrlrr"), ""]
        if "root_alg" in cert_sizes.columns:
            r0 = cert_sizes.iloc[0]
            embedded = "pemilik + PSrE + Root" if cfg.get("pki", {}).get("embed_root") else "pemilik + PSrE"
            parts += [f"Hierarki: Root CA {r0.root_alg} (sertifikat {fmt_id(float(r0.root_cert_der_bytes), 0)} B, "
                      f"sama untuk semua algoritma) → PSrE → pemilik. Rantai di CMS = {embedded}.", ""]
        num += 1

    if not sig.empty:
        kw = sig[sig.test == "kruskal_wallis"]
        mw = sig[sig.test == "mann_whitney"]
        kb_of = {pdf_name_for(kb): kb for kb in cfg["pdf_sizes_kb"]}

        def glabel(sc: str, g: str) -> str:
            return OPERATION_LABELS.get(g, g) if sc == "S1" else size_text(kb_of.get(g, 0))

        rows = []
        for _, k in kw.iterrows():
            fam = mw[(mw.scenario == k.scenario) & (mw.group == k.group)]
            for _, m in fam.iterrows():
                rows.append([k.scenario, glabel(k.scenario, k.group), alg_label(cfg, m.alg),
                             fmt_ratio(float(m.ratio_median_vs_ref)), fmt_id(float(m.effect_size), 3),
                             fmt_p(float(m.p_holm)), "ya" if m.significant else "tidak"])
        alpha = cfg["analyze"]["alpha"]
        parts += [f"## Tabel {num}. Uji signifikansi terhadap {ref_label}", "",
                  md_table(["Skenario", "Kelompok", "Algoritma", "Rasio median", "r (rank-biserial)",
                            "p (Holm)", f"Signifikan (α = {fmt_id(float(alpha), 2)})"], rows, "lllrrrl"), "",
                  "Kruskal–Wallis antar semua algoritma per kelompok: "
                  + "; ".join(f"{k.scenario}/{glabel(k.scenario, k.group)} H = {fmt_id(float(k.statistic), 1)}, "
                              f"p = {fmt_p(float(k.p_value))}, ε² = {fmt_id(float(k.effect_size), 3)}"
                              for _, k in kw.iterrows()) + ".",
                  "",
                  "r > 0 berarti algoritma cenderung lebih lambat dari pembanding (r = ±1: tidak ada tumpang-tindih). "
                  "Dengan n besar, selisih kecil pun signifikan; rasio median dan r menunjukkan besarnya efek.",
                  ""]
    return "\n".join(parts)


# --------------------------------------------------------------------------- figures
def _style() -> dict[str, str]:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    ink = {"text": "#0b0b0b", "muted": "#52514e", "grid": "#e4e3df", "surface": "#ffffff"}
    plt.rcParams.update({
        "font.family": "DejaVu Sans", "font.size": 9, "axes.edgecolor": ink["muted"], "axes.labelcolor": ink["text"],
        "axes.linewidth": 0.6, "xtick.color": ink["muted"], "ytick.color": ink["muted"], "text.color": ink["text"],
        "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True, "axes.grid.axis": "y",
        "grid.color": ink["grid"], "grid.linewidth": 0.6, "axes.axisbelow": True, "legend.frameon": False,
        "figure.facecolor": ink["surface"], "axes.facecolor": ink["surface"], "savefig.facecolor": ink["surface"],
    })
    return ink


def _id_formatter(log: bool):
    from matplotlib.ticker import FuncFormatter

    def f(v: float, _pos: int) -> str:
        if v <= 0:
            return "0"
        nd = 0 if v >= 1 or not log else max(0, -int(f"{v:e}".split("e")[1]))
        return fmt_id(v, nd if v < 1 else (0 if float(v).is_integer() else 1))
    return FuncFormatter(f)


def grouped_bars(path: Path, cfg: dict[str, Any], algs: list[str], series: list[tuple[str, list[float],
                 list[tuple[float, float]] | None]], ylabel: str, title: str, log_y: bool) -> None:
    """Grouped chart, x = algorithm, one mark per series, optional IQR whiskers.

    Linear axis: bars (length from zero is meaningful). Log axis: dots, because a
    bar's length from an arbitrary log floor would misrepresent the ratio.
    """
    import matplotlib.pyplot as plt

    ink = _style()
    colors = cfg["analyze"]["colors"]
    if len(series) > len(colors):
        raise ValueError(f"{len(series)} seri melebihi {len(colors)} warna kategorikal")
    fig, ax = plt.subplots(figsize=(7.0, 3.6))
    n = len(series)
    width = 0.8 / n
    xs = range(len(algs))
    for i, (name, values, iqr) in enumerate(series):
        pos = [x - 0.4 + width * (i + 0.5) for x in xs]
        yerr = None
        if iqr:
            yerr = [[max(v - a, 0) for v, (a, _b) in zip(values, iqr)],
                    [max(b - v, 0) for v, (_a, b) in zip(values, iqr)]]
        if log_y:
            ax.errorbar(pos, values, yerr=yerr, fmt="o", color=colors[i], markersize=6, markeredgecolor=ink["surface"],
                        markeredgewidth=0.8, ecolor=colors[i], elinewidth=1.0, capsize=2, label=name, zorder=3)
        else:
            ax.bar(pos, values, width=width, color=colors[i], edgecolor=ink["surface"], linewidth=1.0, label=name,
                   zorder=2)
            if yerr:
                ax.errorbar(pos, values, yerr=yerr, fmt="none", ecolor=ink["text"], elinewidth=0.7, capsize=1.5,
                            zorder=3)
    if log_y:
        for x in list(xs)[1:]:  # faint separators between algorithm groups
            ax.axvline(x - 0.5, color=ink["grid"], linewidth=0.6, zorder=1)
    ax.set_xticks(list(xs), [alg_label(cfg, a) for a in algs])
    ax.set_ylabel(ylabel)
    ax.set_title(title, loc="left", fontsize=10, color=ink["text"], pad=22 if n > 1 else 6)
    if log_y:
        ax.set_yscale("log")
    ax.yaxis.set_major_formatter(_id_formatter(log_y))
    if n > 1:
        ax.legend(loc="lower left", bbox_to_anchor=(0, 1.0), ncols=n, fontsize=8, handlelength=1.0,
                  columnspacing=1.2, borderaxespad=0.2)
    ax.tick_params(axis="x", length=0)
    fig.tight_layout()
    fig.savefig(path, dpi=int(cfg["analyze"]["dpi"]))
    plt.close(fig)


def make_figures(cfg: dict[str, Any], summary: pd.DataFrame, s4: pd.DataFrame | None,
                 cert_sizes: pd.DataFrame | None, sigbytes: dict[str, int], fig_dir: Path) -> list[Path]:
    """Write the five SPEC figures that have data; return their paths."""
    out: list[Path] = []
    kb_of = {pdf_name_for(kb): kb for kb in cfg["pdf_sizes_kb"]}

    def stats(sc: str, a: str, g: str) -> tuple[float, tuple[float, float]]:
        x = summary[(summary.scenario == sc) & (summary.alg == a) & (summary.group == g)].iloc[0]
        return float(x.median_ms), (float(x.p25_ms), float(x.p75_ms))

    s1 = summary[summary.scenario == "S1"]
    if len(s1) and {"sign", "verify"} <= set(s1.group):
        algs = ordered_algs(cfg, s1.alg.unique())
        series = []
        for op in ("sign", "verify"):
            st = [stats("S1", a, op) for a in algs]
            series.append((OPERATION_LABELS[op], [m for m, _ in st], [q for _, q in st]))
        p = fig_dir / "s1_sign_verify.png"
        grouped_bars(p, cfg, algs, series, "Waktu median (ms, skala log)",
                     "Waktu tanda tangan dan verifikasi (S1, operasi kriptografi murni)", True)
        out.append(p)

    for sc, fname, title, log_y in (
            ("S2", "s2_sign_by_size.png", "Waktu tanda tangan PDF per ukuran dokumen (S2)", True),
            ("S3", "s3_verify_by_size.png", "Waktu verifikasi PDF per ukuran dokumen (S3)", False)):
        s = summary[summary.scenario == sc]
        if not len(s):
            continue
        algs = ordered_algs(cfg, s.alg.unique())
        series = []
        for g in ordered_groups(cfg, sc, list(s.group.unique())):
            st = [stats(sc, a, g) for a in algs]
            series.append((f"PDF {size_text(kb_of[g])}", [m for m, _ in st], [q for _, q in st]))
        p = fig_dir / fname
        grouped_bars(p, cfg, algs, series, "Waktu median (ms" + (", skala log)" if log_y else ")"), title, log_y)
        out.append(p)

    if s4 is not None and len(s4):
        algs = ordered_algs(cfg, s4.alg.unique())
        series = []
        for g in ordered_groups(cfg, "S4", list(s4.pdf_name.unique())):
            x = s4[s4.pdf_name == g].set_index("alg")
            series.append((f"PDF {size_text(kb_of[g])}", [float(x.loc[a, "delta_percent"]) for a in algs], None))
        p = fig_dir / "s4_size_overhead.png"
        grouped_bars(p, cfg, algs, series, "Pertambahan ukuran berkas (%, skala log)",
                     "Pertambahan ukuran PDF setelah ditandatangani (S4)", True)
        out.append(p)

    if cert_sizes is not None and len(cert_sizes) and sigbytes:
        algs = [a for a in ordered_algs(cfg, cert_sizes.alg.unique()) if a in sigbytes]
        cs = cert_sizes.set_index("alg")
        series = [("Kunci publik (SPKI DER)", [float(cs.loc[a, "user_pubkey_bytes"]) for a in algs], None),
                  ("Signature", [float(sigbytes[a]) for a in algs], None)]
        p = fig_dir / "sizes_keys_signatures.png"
        grouped_bars(p, cfg, algs, series, "Ukuran (byte, skala log)", "Ukuran kunci publik dan signature", True)
        out.append(p)
    return out


# --------------------------------------------------------------------------- main flow
def analyze(cfg: dict[str, Any], out_dir: Path, fig_dir: Path, smoke: bool = False) -> dict[str, Any]:
    """Compute everything and write outputs; returns a small report."""
    data = load_scenarios(out_dir)
    summary_rows = summarize(cfg, data)
    write_csv(out_dir / "summary.csv", SUMMARY_COLUMNS, summary_rows)
    sig_rows = significance(cfg, data)
    write_csv(out_dir / "significance.csv", SIGNIFICANCE_COLUMNS, sig_rows)
    summary = pd.DataFrame(summary_rows, columns=SUMMARY_COLUMNS)
    sig = pd.DataFrame(sig_rows, columns=SIGNIFICANCE_COLUMNS)

    s4_path = out_dir / "s4_size.csv"
    s4 = pd.read_csv(s4_path) if s4_path.exists() else None
    cs_path = resolve_path(cfg, "results") / "cert_sizes.csv"
    cert_sizes = pd.read_csv(cs_path) if cs_path.exists() else None
    sigbytes: dict[str, int] = {}
    if "S1" in data:
        s = data["S1"][data["S1"]["operation"] == "sign"]
        sigbytes = {a: int(v) for a, v in s.groupby("alg")["signature_bytes"].median().items()}
    sys_path = out_dir / "system_info.json"
    sysinfo = json.loads(sys_path.read_text(encoding="utf-8")) if sys_path.exists() else None

    md = tables_markdown(cfg, summary, sig, s4, cert_sizes, sigbytes, sysinfo, smoke)
    (out_dir / "tables_for_paper.md").write_text(md, encoding="utf-8")
    fig_dir.mkdir(parents=True, exist_ok=True)
    figs = make_figures(cfg, summary, s4, cert_sizes, sigbytes, fig_dir)
    log.info("summary.csv (%d baris), significance.csv (%d baris), tables_for_paper.md, %d grafik di %s",
             len(summary_rows), len(sig_rows), len(figs), fig_dir)
    return {"summary_rows": len(summary_rows), "significance_rows": len(sig_rows), "figures": figs}


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    ap = base_arg_parser("Analisis statistik, tabel, dan grafik (SPEC 4.8)")
    ap.add_argument("--smoke", action="store_true", help="analisis hasil smoke (results/smoke, figures/smoke)")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config(args.config)
    fig_dir = resolve_path(cfg, "figures")
    if args.smoke:
        fig_dir = fig_dir / str(cfg.get("smoke_results_subdir", "smoke"))
    analyze(cfg, results_dir(cfg, args.smoke), fig_dir, args.smoke)
    return 0


if __name__ == "__main__":
    sys.exit(main())
