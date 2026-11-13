"""CSV writing with an exact, schema-checked column order."""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Iterable, Mapping


def write_csv(path: Path, columns: list[str], rows: Iterable[Mapping[str, Any]]) -> int:
    """Write rows with exactly `columns` (missing or extra keys raise). Returns row count."""
    n = 0
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=columns, extrasaction="raise")
        w.writeheader()
        for r in rows:
            missing = set(columns) - set(r)
            if missing:
                raise KeyError(f"kolom hilang: {sorted(missing)}")
            w.writerow(r)
            n += 1
    return n


def read_csv(path: Path, columns: list[str]) -> list[dict[str, str]]:
    """Read a CSV written by `write_csv`; the header must equal `columns`. Missing file -> []."""
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as fh:
        r = csv.DictReader(fh)
        if r.fieldnames != columns:
            raise ValueError(f"header {path.name} tidak sesuai skema: {r.fieldnames}")
        return list(r)
