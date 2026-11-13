"""Interleaved measurement schedule helpers (rounds with seeded random order)."""
from __future__ import annotations

import random
from typing import Sequence, TypeVar

T = TypeVar("T")


def chunk_sizes(iterations: int, rounds: int) -> list[int]:
    """Split `iterations` into at most `rounds` nearly equal positive chunks."""
    r = max(1, min(rounds, iterations))
    q, rem = divmod(iterations, r)
    return [q + (1 if i < rem else 0) for i in range(r)]


def round_order(seed: int, tag: str, items: Sequence[T], r: int) -> list[T]:
    """Seeded random order of `items` for round `r` of the schedule named `tag`."""
    order = list(items)
    random.Random(f"{seed}:{tag}:round:{r}").shuffle(order)
    return order
