from __future__ import annotations

import time
from threading import Lock

from fastapi import HTTPException, Request

from app.config import RATE_LIMIT_PER_WINDOW, RATE_LIMIT_WINDOW_SECONDS


class FixedWindowLimiter:
    """In-process per-key fixed-window counter.

    Sufficient for a single-uvicorn-worker deployment. A multi-worker or
    horizontally scaled deployment needs a shared store (Redis) — this
    limiter would silently undercount across processes. It is also not a
    substitute for an upstream WAF: memory grows with the number of unique
    keys observed within a window."""

    def __init__(self, *, limit: int, window_seconds: int) -> None:
        self._limit = limit
        self._window_seconds = window_seconds
        self._windows: dict[str, tuple[float, int]] = {}
        self._lock = Lock()

    def hit(self, key: str) -> tuple[bool, int]:
        """Record a hit for *key*. Returns (allowed, retry_after_seconds)."""
        now = time.monotonic()
        with self._lock:
            window_start, count = self._windows.get(key, (now, 0))
            if now - window_start >= self._window_seconds:
                window_start, count = now, 0
            count += 1
            self._windows[key] = (window_start, count)
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

    Keyed on ``request.client.host`` directly — ``X-Forwarded-For`` is
    intentionally ignored because trusting it without a known proxy lets
    callers spoof their key and bypass the limit."""
    client_ip = request.client.host if request.client else "unknown"
    allowed, retry_after = _limiter.hit(client_ip)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Too many requests",
            headers={"Retry-After": str(retry_after)},
        )
