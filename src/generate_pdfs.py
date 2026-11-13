"""Generate synthetic academic PDFs of target sizes (SPEC 4.1).

Each PDF has a letterhead, lorem text, a grade table and random images, then
random JPEG "attachment" images are added until the file is within the size
tolerance of the target. Output is deterministic for a given seed (reportlab
``invariant`` mode fixes timestamps and document IDs).

Run: ``python -m src.generate_pdfs --config config.yaml [--force] [--smoke]``
"""
from __future__ import annotations

import hashlib
import io
import logging
import math
import random
import sys
from pathlib import Path
from typing import Any

from src.common.config import base_arg_parser, load_config, pdf_name_for, resolve_path
from src.common.csvio import write_csv

log = logging.getLogger("generate_pdfs")

INVENTORY_COLUMNS = ["pdf_name", "target_kb", "actual_bytes", "pages", "sha256"]
MAX_FIT_ITERATIONS = 10

LOREM = (
    "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore "
    "et dolore magna aliqua enim ad minim veniam quis nostrud exercitation ullamco laboris nisi aliquip "
    "ex ea commodo consequat duis aute irure in reprehenderit voluptate velit esse cillum fugiat nulla "
    "pariatur excepteur sint occaecat cupidatat non proident sunt culpa qui officia deserunt mollit anim "
    "id est laborum"
).split()
COURSES = [
    "Kalkulus", "Aljabar Linear", "Statistika", "Kriptografi", "Keamanan Jaringan", "Basis Data",
    "Struktur Data", "Algoritma", "Sistem Operasi", "Jaringan Komputer", "Rekayasa Perangkat Lunak",
    "Kecerdasan Buatan", "Pembelajaran Mesin", "Etika Profesi", "Bahasa Indonesia", "Pancasila",
    "Fisika Dasar", "Matematika Diskrit", "Teori Bilangan", "Komputasi Kuantum",
]
GRADES = [("A", 4.0), ("A-", 3.7), ("B+", 3.3), ("B", 3.0), ("B-", 2.7), ("C+", 2.3), ("C", 2.0)]


# --------------------------------------------------------------------------- content
def lorem_paragraph(rng: random.Random, n_words: int) -> str:
    """Pseudo-lorem paragraph."""
    words = [rng.choice(LOREM) for _ in range(n_words)]
    return (" ".join(words)).capitalize() + "."


def noise_image(rng: random.Random, w: int, h: int, fmt: str, quality: int) -> bytes:
    """Random RGB noise image encoded as JPEG or PNG."""
    from PIL import Image

    img = Image.frombytes("RGB", (w, h), rng.randbytes(w * h * 3))
    buf = io.BytesIO()
    if fmt == "JPEG":
        img.save(buf, "JPEG", quality=quality, optimize=False)
    else:
        img.save(buf, "PNG", compress_level=1)
    return buf.getvalue()


def jpeg_bytes_per_pixel(quality: int) -> float:
    """Empirical JPEG size per pixel for random noise at `quality`."""
    sample = noise_image(random.Random(0), 256, 256, "JPEG", quality)
    return len(sample) / (256 * 256)


def padding_images(rng: random.Random, total_bytes: int, quality: int, max_px: int) -> list[tuple[bytes, int, int]]:
    """Random JPEGs whose sizes add up to roughly `total_bytes`."""
    if total_bytes <= 2048:
        return []
    bpp = jpeg_bytes_per_pixel(quality)
    max_chunk = int(max_px * max_px * bpp)
    n = math.ceil(total_bytes / max_chunk)
    out = []
    for i in range(n):
        chunk = total_bytes // n + (1 if i < total_bytes % n else 0)
        side = max(16, int(math.sqrt(chunk / bpp)))
        h = max(16, int(chunk / bpp / side))
        out.append((noise_image(rng, side, h, "JPEG", quality), side, h))
    return out


def base_story(rng: random.Random, kb: int) -> list[Any]:
    """Letterhead, identity block, lorem text and grade table."""
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import Image, Paragraph, Spacer, Table, TableStyle

    ss = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=ss["BodyText"], fontSize=10, leading=13, alignment=4)
    head = ParagraphStyle("head", parent=ss["Title"], fontSize=14, leading=17, spaceAfter=2)
    sub = ParagraphStyle("sub", parent=ss["Normal"], fontSize=9, alignment=1)

    logo = Image(io.BytesIO(noise_image(rng, 64, 64, "PNG", 0)), width=2 * cm, height=2 * cm)
    kop = Table([[logo, [Paragraph("UNIVERSITAS SIMULASI PENELITIAN", head),
                         Paragraph("Fakultas Ilmu Komputer — Program Studi Keamanan Informasi", sub),
                         Paragraph("Jl. Contoh No. 1, Jakarta 10000 · Telp. (021) 000-0000", sub)]]],
                colWidths=[2.5 * cm, 14 * cm])
    kop.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                             ("LINEBELOW", (0, 0), (-1, 0), 1.5, colors.black)]))
    nim = f"{rng.randint(10**9, 10**10 - 1)}"
    ident = Table([["Nama", f": Mahasiswa Simulasi {rng.randint(1, 9999):04d}"], ["NIM", f": {nim}"],
                   ["Dokumen", f": Transkrip Nilai Akademik (sampel {kb} KB)"]],
                  colWidths=[3 * cm, 13 * cm])
    rows = [["No", "Kode MK", "Mata Kuliah", "SKS", "Nilai", "Bobot"]]
    total_sks = total_pts = 0.0
    for i in range(40):
        sks = rng.choice([2, 3, 4])
        g, w = rng.choice(GRADES)
        total_sks += sks
        total_pts += sks * w
        rows.append([str(i + 1), f"IK{rng.randint(1000, 4999)}", rng.choice(COURSES), str(sks), g, f"{w:.2f}"])
    rows.append(["", "", "Indeks Prestasi Kumulatif", f"{int(total_sks)}", "", f"{total_pts / total_sks:.2f}"])
    grade_tbl = Table(rows, repeatRows=1, colWidths=[1 * cm, 2.2 * cm, 7.5 * cm, 1.3 * cm, 1.5 * cm, 1.8 * cm])
    grade_tbl.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
    ]))
    story: list[Any] = [kop, Spacer(1, 0.4 * cm), Paragraph("TRANSKRIP NILAI AKADEMIK", ss["Heading2"]),
                        ident, Spacer(1, 0.3 * cm)]
    story += [Paragraph(lorem_paragraph(rng, rng.randint(60, 110)), body) for _ in range(5)]
    story += [Spacer(1, 0.3 * cm), grade_tbl, Spacer(1, 0.4 * cm)]
    story += [Paragraph(lorem_paragraph(rng, rng.randint(50, 90)), body) for _ in range(3)]
    story += [Spacer(1, 1 * cm), Paragraph("Jakarta, 1 Januari 2026<br/>Dekan,<br/><br/><br/>"
                                           "(ruang tanda tangan elektronik)", ss["Normal"])]
    return story


def render_pdf(kb: int, seed: int, padding_bytes: int, pcfg: dict[str, Any]) -> bytes:
    """Render the PDF for target `kb` with ~`padding_bytes` of random attachment images."""
    from reportlab import rl_config
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import Image, PageBreak, Paragraph, SimpleDocTemplate

    rl_config.useA85 = 0  # binary streams, like typical PDF producers
    rng = random.Random(f"{seed}:{kb}:content")
    pad_rng = random.Random(f"{seed}:{kb}:padding:{padding_bytes}")
    story = base_story(rng, kb)
    ss = getSampleStyleSheet()
    max_w, max_h = 16 * cm, 21 * cm
    for i, (jpg, w, h) in enumerate(padding_images(pad_rng, padding_bytes, int(pcfg["jpeg_quality"]),
                                                   int(pcfg["max_image_px"]))):
        scale = min(max_w / w, max_h / h)
        story += [PageBreak(), Paragraph(f"Lampiran Gambar {i + 1}", ss["Heading3"]),
                  Image(io.BytesIO(jpg), width=w * scale, height=h * scale)]
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, invariant=1, title=f"Sampel PDF {kb} KB",
                            author="pqc-pdf-sim", subject="Dokumen akademik sintetis",
                            creator="pqc-pdf-sim generate_pdfs", leftMargin=2 * cm, rightMargin=2 * cm,
                            topMargin=2 * cm, bottomMargin=2 * cm)
    doc.build(story)
    return buf.getvalue()


def fit_pdf(kb: int, seed: int, pcfg: dict[str, Any]) -> bytes:
    """Iteratively adjust padding until the PDF is within `fit_tolerance_pct` of the target size."""
    target = kb * 1024
    fit_tol = target * float(pcfg["fit_tolerance_pct"]) / 100
    hard_tol = target * float(pcfg["size_tolerance_pct"]) / 100
    base = render_pdf(kb, seed, 0, pcfg)
    if len(base) > target + hard_tol:
        raise ValueError(f"konten dasar ({len(base)} B) sudah melebihi target {target} B")
    pad = max(0, target - len(base))
    data = base
    for it in range(MAX_FIT_ITERATIONS):
        data = render_pdf(kb, seed, pad, pcfg)
        err = target - len(data)
        log.debug("  iterasi %d: padding=%d ukuran=%d selisih=%d", it, pad, len(data), err)
        if abs(err) <= fit_tol:
            break
        pad = max(0, pad + err)
    if abs(target - len(data)) > hard_tol:
        raise ValueError(f"gagal mencapai ukuran {target} B ±{pcfg['size_tolerance_pct']}% (dapat {len(data)} B)")
    return data


def page_count(path: Path) -> int:
    """Number of pages (pikepdf)."""
    import pikepdf

    with pikepdf.open(path) as pdf:
        return len(pdf.pages)


def inventory_row(path: Path, kb: int) -> dict[str, Any]:
    """Row of pdf_inventory.csv for an existing file."""
    data = path.read_bytes()
    return {"pdf_name": path.name, "target_kb": kb, "actual_bytes": len(data),
            "pages": page_count(path), "sha256": hashlib.sha256(data).hexdigest()}


def generate(cfg: dict[str, Any], sizes_kb: list[int], pdf_dir: Path, results_dir: Path,
             force: bool = False) -> list[dict[str, Any]]:
    """Create missing (or all, with `force`) PDFs and rewrite pdf_inventory.csv from the files on disk."""
    pcfg = cfg["pdf"]
    seed = int(cfg["seed"])
    for kb in sizes_kb:
        path = pdf_dir / pdf_name_for(kb)
        if path.exists() and not force:
            log.info("%s sudah ada, dilewati (pakai --force untuk membuat ulang)", path.name)
            continue
        log.info("Membuat %s (target %d KB) ...", path.name, kb)
        data = fit_pdf(kb, seed, pcfg)
        path.write_bytes(data)
        log.info("  -> %d B (%.2f%% dari target)", len(data), 100 * len(data) / (kb * 1024))
    rows = [inventory_row(pdf_dir / pdf_name_for(kb), kb) for kb in cfg["pdf_sizes_kb"]
            if (pdf_dir / pdf_name_for(kb)).exists()]
    write_csv(results_dir / "pdf_inventory.csv", INVENTORY_COLUMNS, rows)
    return rows


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    ap = base_arg_parser("Membuat PDF sampel (SPEC 4.1)")
    ap.add_argument("--force", action="store_true", help="buat ulang walau file sudah ada")
    ap.add_argument("--smoke", action="store_true", help="hanya ukuran terkecil")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config(args.config)
    sizes = sorted(cfg["pdf_sizes_kb"])[:1] if args.smoke else list(cfg["pdf_sizes_kb"])
    rows = generate(cfg, sizes, resolve_path(cfg, "pdf"), resolve_path(cfg, "results"), args.force)
    for r in rows:
        log.info("%s: %d B, %d halaman", r["pdf_name"], r["actual_bytes"], r["pages"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
