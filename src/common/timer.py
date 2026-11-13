"""In-process timing helpers (time.perf_counter_ns only)."""
from __future__ import annotations

import gc
import time
from contextlib import contextmanager
from typing import Any, Callable, Iterator


def time_call(fn: Callable[..., Any], *args: Any) -> tuple[int, Any]:
    """Call fn(*args) and return (elapsed_ns, result). Only the call itself is timed."""
    t0 = time.perf_counter_ns()
    out = fn(*args)
    t1 = time.perf_counter_ns()
    return t1 - t0, out


@contextmanager
def gc_paused(enabled: bool = True) -> Iterator[None]:
    """Collect once, then keep the cyclic GC off inside the block (restored afterwards)."""
    if not enabled:
        yield
        return
    was_enabled = gc.isenabled()
    gc.collect()
    gc.disable()
    try:
        yield
    finally:
        if was_enabled:
            gc.enable()
