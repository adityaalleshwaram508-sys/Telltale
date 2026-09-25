"""Request limits for the public demo.

Every analysis spends Token Factory and Tavily credits, and the demo has to stay up for the
whole judging period, so abuse protection is part of keeping it working. The state lives in
this process, which is right for the single-instance deployment in render.yaml; running more
than one instance would need a shared store.
"""

from __future__ import annotations

import datetime as dt
import time
from collections import deque


class RateLimiter:
    """Sliding window: at most `limit` hits per `window_s` seconds for each key."""

    def __init__(self, limit: int, window_s: int, max_keys: int = 10_000):
        self.limit, self.window_s, self.max_keys = limit, window_s, max_keys
        self._hits: dict[str, deque[float]] = {}

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        hits = self._hits.setdefault(key, deque())
        while hits and now - hits[0] >= self.window_s:
            hits.popleft()
        if len(hits) >= self.limit:
            return False
        hits.append(now)
        if len(self._hits) > self.max_keys:  # forget the quietest clients first
            for k in [k for k, v in self._hits.items() if not v][: len(self._hits) // 2]:
                del self._hits[k]
        return True

    def retry_after(self, key: str, now: float | None = None) -> int:
        now = time.monotonic() if now is None else now
        hits = self._hits.get(key)
        return max(1, int(self.window_s - (now - hits[0]))) if hits else 1


class DailyBudget:
    """Full model runs allowed per UTC day. Past it, analyses fall back to detectors only."""

    def __init__(self, per_day: int):
        self.per_day = per_day
        self.day = dt.datetime.now(dt.UTC).date()
        self.used = 0

    def take(self) -> bool:
        today = dt.datetime.now(dt.UTC).date()
        if today != self.day:
            self.day, self.used = today, 0
        if self.used >= self.per_day:
            return False
        self.used += 1
        return True
