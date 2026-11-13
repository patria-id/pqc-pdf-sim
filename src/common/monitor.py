"""Environment monitoring for benchmarks: power mode, load, process priority/affinity.

Nothing here changes system settings; it only reads them and adjusts the
priority/affinity of the current process (restored afterwards).
"""
from __future__ import annotations

import platform
import time
from contextlib import contextmanager
from typing import Any, Iterator

import psutil

# Windows 11 "Power mode" overlay GUIDs (Settings > System > Power)
WIN_POWER_OVERLAYS = {
    "961cc777-2547-4f9d-8174-7d86181b8a7a": "best_power_efficiency",
    "00000000-0000-0000-0000-000000000000": "balanced",
    "3af9b8d9-7c97-431d-ad78-34a8bfea439f": "better_performance",
    "ded574b5-45a0-4f42-8737-46345c09c238": "best_performance",
}


def cpu_model() -> str:
    """CPU brand string (registry on Windows, /proc/cpuinfo on Linux, fallback platform)."""
    if platform.system() == "Windows":
        try:
            import winreg

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as k:
                return str(winreg.QueryValueEx(k, "ProcessorNameString")[0]).strip()
        except OSError:
            pass
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor()


def power_mode() -> dict[str, Any]:
    """Active power plan and Windows power-mode overlay (read-only). Empty dict when unknown."""
    if platform.system() != "Windows":
        return {}
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes") as k:
            def val(name: str) -> str | None:
                try:
                    return str(winreg.QueryValueEx(k, name)[0]).lower()
                except OSError:
                    return None

            plan, ac, dc = val("ActivePowerScheme"), val("ActiveOverlayAcPowerScheme"), val("ActiveOverlayDcPowerScheme")
    except OSError:
        return {}
    return {"plan_guid": plan, "overlay_ac_guid": ac, "overlay_dc_guid": dc,
            "overlay_ac": WIN_POWER_OVERLAYS.get(ac or "", "unknown"),
            "overlay_dc": WIN_POWER_OVERLAYS.get(dc or "", "unknown")}


def battery() -> dict[str, Any]:
    """Battery state, or {} on desktops."""
    b = psutil.sensors_battery()
    return {"percent": b.percent, "power_plugged": b.power_plugged} if b else {}


def load_sample(seconds: float, top_n: int = 5) -> dict[str, Any]:
    """System CPU load over `seconds` and the busiest other processes in that window."""
    me = psutil.Process().pid
    procs = []
    for p in psutil.process_iter(["name"]):
        try:
            p.cpu_percent(None)
            procs.append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    total = psutil.cpu_percent(interval=seconds)
    busy = []
    for p in procs:
        try:
            if p.pid not in (0, me):
                busy.append((p.cpu_percent(None) / psutil.cpu_count(), p.info["name"]))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    busy.sort(reverse=True)
    return {"system_cpu_pct": total, "window_s": seconds,
            "top_processes": [{"name": n, "cpu_pct_of_system": round(c, 1)} for c, n in busy[:top_n]]}


def snapshot(load_window_s: float = 3.0) -> dict[str, Any]:
    """Environment snapshot for metadata."""
    freq = psutil.cpu_freq()
    return {
        "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "cpu_model": cpu_model(),
        "cpu_physical": psutil.cpu_count(logical=False),
        "cpu_logical": psutil.cpu_count(),
        "cpu_freq_mhz": {"current": freq.current, "max": freq.max} if freq else None,
        "ram_total_bytes": psutil.virtual_memory().total,
        "ram_available_bytes": psutil.virtual_memory().available,
        "battery": battery(),
        "power_mode": power_mode(),
        "load": load_sample(load_window_s),
    }


def preflight_issues(snap: dict[str, Any], max_load_pct: float) -> list[str]:
    """Conditions that make a full benchmark run unreliable (empty list = OK)."""
    issues = []
    bat = snap.get("battery") or {}
    if bat and not bat.get("power_plugged"):
        issues.append("laptop tidak dicolok ke listrik")
    pm = snap.get("power_mode") or {}
    if pm and pm.get("overlay_ac") not in ("best_performance", "unknown"):
        issues.append(f"mode daya Windows = {pm.get('overlay_ac')} (disarankan best_performance)")
    if snap["load"]["system_cpu_pct"] > max_load_pct:
        top = ", ".join(f"{p['name']} {p['cpu_pct_of_system']}%" for p in snap["load"]["top_processes"][:3])
        issues.append(f"beban CPU latar {snap['load']['system_cpu_pct']:.0f}% > {max_load_pct:.0f}% ({top})")
    return issues


def resolve_affinity(spec: Any) -> list[int] | None:
    """Config value -> list of logical CPUs (None = no pinning). 'auto' = first CPU of the 2nd core."""
    if spec in (None, False, "none"):
        return None
    n = psutil.cpu_count() or 1
    if spec == "auto":
        per_core = max(1, n // max(1, psutil.cpu_count(logical=False) or 1))
        return [per_core if n > per_core else 0]
    cpus = [int(c) for c in (spec if isinstance(spec, list) else [spec])]
    if any(c < 0 or c >= n for c in cpus):
        raise ValueError(f"cpu_affinity {cpus} di luar 0..{n - 1}")
    return cpus


@contextmanager
def process_tuning(priority: str | None, affinity: list[int] | None) -> Iterator[dict[str, Any]]:
    """Raise priority / pin CPUs for the current process; restore on exit. Yields what was applied."""
    p = psutil.Process()
    applied: dict[str, Any] = {"priority": None, "affinity": None, "errors": []}
    old_nice = p.nice()
    old_aff = p.cpu_affinity() if hasattr(p, "cpu_affinity") else None
    try:
        if priority == "high":
            try:
                p.nice(psutil.HIGH_PRIORITY_CLASS if platform.system() == "Windows" else -10)
                applied["priority"] = "high"
            except (psutil.AccessDenied, OSError) as exc:
                applied["errors"].append(f"prioritas: {exc}")
        if affinity is not None and old_aff is not None:
            try:
                p.cpu_affinity(affinity)
                applied["affinity"] = affinity
            except (psutil.AccessDenied, OSError, ValueError) as exc:
                applied["errors"].append(f"affinity: {exc}")
        yield applied
    finally:
        try:
            p.nice(old_nice)
        except (psutil.AccessDenied, OSError):
            pass
        if old_aff is not None:
            try:
                p.cpu_affinity(old_aff)
            except (psutil.AccessDenied, OSError, ValueError):
                pass


class ChunkProbe:
    """Cheap per-chunk load probe (called outside timed regions)."""

    def __init__(self) -> None:
        self._p = psutil.Process()

    def start(self) -> None:
        """Reset the CPU-percent counters."""
        psutil.cpu_percent(None)
        self._p.cpu_percent(None)
        self._t0 = time.perf_counter()

    def stop(self) -> dict[str, Any]:
        """System / process CPU% and wall time since `start`."""
        freq = psutil.cpu_freq()
        return {"system_cpu_pct": psutil.cpu_percent(None),
                "process_cpu_pct": round(self._p.cpu_percent(None) / (psutil.cpu_count() or 1), 1),
                "cpu_freq_mhz": freq.current if freq else None,
                "wall_s": round(time.perf_counter() - self._t0, 3)}


class NoisyEnvironment(RuntimeError):
    """Raised when the pre-flight check fails for a full (non-smoke) run."""


def preflight(bcfg: dict[str, Any], smoke: bool, allow_noisy: bool, logger: Any) -> tuple[dict[str, Any], list[str]]:
    """Snapshot + checks before a benchmark; raises NoisyEnvironment for full runs with issues."""
    window = float(bcfg.get("preflight_load_window_s", 5))
    logger.info("Pemeriksaan pra-run (beban CPU %ss) ...", window)
    snap = snapshot(window)
    issues = preflight_issues(snap, float(bcfg.get("max_background_load_pct", 20)))
    for i in issues:
        logger.warning("Pra-run: %s", i)
    if issues and not smoke and not allow_noisy:
        raise NoisyEnvironment("lingkungan belum siap untuk run penuh: " + "; ".join(issues)
                               + " (perbaiki, atau jalankan dengan --allow-noisy)")
    return snap, issues


class ResourceSampler:
    """Background thread sampling this process's CPU time and RSS while a window is open.

    `begin()` / `end()` are called by the measuring thread just outside the timed
    region. CPU% is relative to one logical CPU (can exceed 100 with several
    threads) and is the maximum over sub-windows of at least `min_window_s`,
    or over the whole window when it is shorter. Note: on Windows, process CPU
    time is accounted in ~15.6 ms ticks, so per-iteration CPU% of short
    operations is quantised (unbiased only on average over many iterations).
    """

    def __init__(self, interval_s: float, min_window_s: float) -> None:
        import threading

        self._p = psutil.Process()
        self.interval_s, self.min_window_s = interval_s, min_window_s
        self._lock = threading.Lock()
        self._active = False
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="resource-sampler", daemon=True)
        self._cpu_peak = 0.0
        self._rss_peak = 0

    def _cpu(self) -> float:
        t = self._p.cpu_times()
        return t.user + t.system

    def _loop(self) -> None:
        while not self._stop.wait(self.interval_s):
            with self._lock:
                if not self._active:
                    continue
                now, cpu = time.perf_counter(), self._cpu()
                self._rss_peak = max(self._rss_peak, self._p.memory_info().rss)
                dt = now - self._ref_t
                if dt >= self.min_window_s:
                    self._cpu_peak = max(self._cpu_peak, 100.0 * (cpu - self._ref_cpu) / dt)
                    self._ref_t, self._ref_cpu = now, cpu

    def __enter__(self) -> "ResourceSampler":
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._thread.join(timeout=2)

    def begin(self) -> None:
        """Open a measurement window."""
        with self._lock:
            self._t0 = self._ref_t = time.perf_counter()
            self._cpu0 = self._ref_cpu = self._cpu()
            self._cpu_peak = 0.0
            self._rss_peak = self._p.memory_info().rss
            self._active = True

    def end(self) -> tuple[float, int]:
        """Close the window; return (cpu_percent_peak, rss_peak_bytes)."""
        with self._lock:
            self._active = False
            now, cpu = time.perf_counter(), self._cpu()
            rss = self._p.memory_info().rss
            whole = 100.0 * (cpu - self._cpu0) / max(now - self._t0, 1e-9)
            peak = self._cpu_peak if self._cpu_peak > 0 else whole
            if now - self._ref_t >= self.min_window_s:
                peak = max(peak, 100.0 * (cpu - self._ref_cpu) / (now - self._ref_t))
            return round(peak, 1), max(self._rss_peak, rss)
