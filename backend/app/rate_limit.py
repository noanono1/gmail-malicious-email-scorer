from __future__ import annotations

import time
from fastapi import HTTPException, Request

from app.config import RATE_LIMIT_PER_WINDOW, RATE_LIMIT_WINDOW_SECONDS


class FixedWindowLimiter:
    """Counts requests per IP within a fixed time window (in-memory dict).

    Assumes a single uvicorn worker — multiple workers each keep a separate
    counter, so the effective limit multiplies by worker count.
    Does not block traffic before it reaches the server — it only rejects
    requests after they arrive. Stale IP entries are never evicted."""

    def __init__(self, *, limit: int, window_seconds: int) -> None:
        self._limit = limit
        self._window_seconds = window_seconds
        # {"192.168.1.1": (window_start_timestamp, request_count)}
        # e.g. {"34.90.0.5": (173204.7, 12), "91.2.3.4": (173210.1, 3)}
        self._hits_per_ip: dict[str, tuple[float, int]] = {}

    def hit(self, key: str) -> tuple[bool, int]:
        """Returns (allowed, retry_after_seconds) for the given IP."""
        now = time.monotonic()
        window_start, count = self._hits_per_ip.get(key, (now, 0))
        if now - window_start >= self._window_seconds:
            window_start, count = now, 0
        count += 1
        self._hits_per_ip[key] = (window_start, count)
        if count > self._limit:
            retry_after = self._window_seconds - (now - window_start)
            return False, max(int(retry_after), 1)
        return True, 0


_limiter = FixedWindowLimiter(
    limit=RATE_LIMIT_PER_WINDOW,
    window_seconds=RATE_LIMIT_WINDOW_SECONDS,
)


async def enforce_rate_limit(request: Request) -> None:
    """Per-IP fixed-window rate limit. Raises 429 when exceeded.

    ``X-Forwarded-For`` is ignored — without a known proxy it lets callers
    spoof their key."""
    client_ip = request.client.host if request.client else "unknown"
    allowed, retry_after = _limiter.hit(client_ip)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Too many requests",
            headers={"Retry-After": str(retry_after)},
        )
