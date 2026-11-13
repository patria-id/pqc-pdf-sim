"""Tests for the benchmark environment monitor."""
from __future__ import annotations

import psutil
import pytest

from src.common import monitor


def _snap(plugged: bool, overlay: str, load: float) -> dict:
    return {"battery": {"percent": 80, "power_plugged": plugged},
            "power_mode": {"overlay_ac": overlay},
            "load": {"system_cpu_pct": load, "top_processes": [{"name": "x.exe", "cpu_pct_of_system": 9.0}]}}


def test_preflight_ok() -> None:
    assert monitor.preflight_issues(_snap(True, "best_performance", 5), 20) == []


def test_preflight_issues() -> None:
    issues = monitor.preflight_issues(_snap(False, "best_power_efficiency", 50), 20)
    assert len(issues) == 3


def test_resolve_affinity() -> None:
    assert monitor.resolve_affinity(None) is None
    assert monitor.resolve_affinity([0]) == [0]
    auto = monitor.resolve_affinity("auto")
    assert auto is not None and 0 <= auto[0] < (psutil.cpu_count() or 1)
    with pytest.raises(ValueError):
        monitor.resolve_affinity([10_000])


def test_process_tuning_restores() -> None:
    p = psutil.Process()
    before = p.cpu_affinity()
    with monitor.process_tuning("normal", [0]) as applied:
        assert applied["affinity"] == [0]
    assert p.cpu_affinity() == before


def test_snapshot_fields() -> None:
    s = monitor.snapshot(0.2)
    assert s["cpu_logical"] >= 1 and "system_cpu_pct" in s["load"]
