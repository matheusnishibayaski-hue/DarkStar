"""Rate limiting in-memory por IP (rotas caras de IA)."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self.max_requests = max(1, max_requests)
        self.window_seconds = max(1, window_seconds)
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> tuple[bool, int]:
        now = time.time()
        cutoff = now - self.window_seconds

        with self._lock:
            bucket = self._hits[key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= self.max_requests:
                retry_after = max(1, int(self.window_seconds - (now - bucket[0])))
                return False, retry_after

            bucket.append(now)
            return True, 0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


_limiter: RateLimiter | None = None


def get_rate_limiter(max_requests: int, window_seconds: int) -> RateLimiter:
    global _limiter
    if _limiter is None:
        _limiter = RateLimiter(max_requests, window_seconds)
    return _limiter
