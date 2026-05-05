"""Tests for the per-IP fixed-window rate limiter.

Two layers:
  1. Unit tests on FixedWindowLimiter — pure logic, no HTTP.
  2. One HTTP-boundary test that monkeypatches the module-level limiter
     with a tiny budget and confirms /analyze returns 429 + Retry-After
     when the budget is exhausted."""

from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest
from fastapi.testclient import TestClient

from app import rate_limit
from app.rate_limit import FixedWindowLimiter


# ---------------------------------------------------------------------------
# Unit: FixedWindowLimiter
# ---------------------------------------------------------------------------


class TestFixedWindowLimiterUnit:
    def test_under_limit_is_allowed(self):
        limiter = FixedWindowLimiter(limit=3, window_seconds=60)
        for _ in range(3):
            allowed, retry_after = limiter.hit("ip-a")
            assert allowed is True
            assert retry_after == 0

    def test_over_limit_is_blocked(self):
        limiter = FixedWindowLimiter(limit=2, window_seconds=60)
        limiter.hit("ip-a")
        limiter.hit("ip-a")
        allowed, retry_after = limiter.hit("ip-a")
        assert allowed is False
        assert retry_after >= 1

    def test_keys_are_isolated(self):
        # One IP exhausting its budget must not affect another IP.
        limiter = FixedWindowLimiter(limit=1, window_seconds=60)
        assert limiter.hit("ip-a") == (True, 0)
        assert limiter.hit("ip-a")[0] is False
        assert limiter.hit("ip-b") == (True, 0)

    def test_window_resets_after_elapsed(self, monkeypatch: pytest.MonkeyPatch):
        # Drive time forward via a fake monotonic clock instead of sleeping.
        fake_now = [1000.0]
        monkeypatch.setattr(rate_limit.time, "monotonic", lambda: fake_now[0])

        limiter = FixedWindowLimiter(limit=1, window_seconds=10)
        assert limiter.hit("ip-a") == (True, 0)
        assert limiter.hit("ip-a")[0] is False

        fake_now[0] += 11  # past the window
        assert limiter.hit("ip-a") == (True, 0)

    def test_retry_after_decreases_within_window(self, monkeypatch: pytest.MonkeyPatch):
        fake_now = [1000.0]
        monkeypatch.setattr(rate_limit.time, "monotonic", lambda: fake_now[0])

        limiter = FixedWindowLimiter(limit=1, window_seconds=10)
        limiter.hit("ip-a")  # consumes the budget at t=0

        fake_now[0] += 3
        _, retry_after_at_t3 = limiter.hit("ip-a")
        fake_now[0] += 4
        _, retry_after_at_t7 = limiter.hit("ip-a")
        assert retry_after_at_t3 > retry_after_at_t7 >= 1


# ---------------------------------------------------------------------------
# HTTP boundary: /analyze returns 429 when the limiter rejects a request
# ---------------------------------------------------------------------------


def _sign(secret: str, timestamp: str, body: bytes) -> str:
    return hmac.new(
        secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256
    ).hexdigest()


def _minimal_payload() -> dict:
    return {
        "message_id": "rate-limit-test",
        "sender_address": "user@example.com",
        "sender_display_name": "",
        "recipient": "victim@example.com",
        "subject": "Hello",
        "body_text": "Hello",
        "body_html": "",
    }


class TestRateLimitHttpBoundary:
    def test_429_with_retry_after_when_budget_exhausted(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        # Swap the module-level limiter with one that allows exactly 2 calls
        # so a third signed request trips it deterministically. monkeypatch
        # auto-restores the real limiter after the test.
        tiny_limiter = FixedWindowLimiter(limit=2, window_seconds=60)
        monkeypatch.setattr(rate_limit, "_limiter", tiny_limiter)

        from app.config import HMAC_SECRET
        from app.main import create_app

        body = json.dumps(_minimal_payload()).encode("utf-8")

        with TestClient(create_app()) as client:
            for _ in range(2):
                ts = str(int(time.time()))
                ok = client.post(
                    "/analyze",
                    content=body,
                    headers={
                        "Content-Type": "application/json",
                        "X-Timestamp": ts,
                        "X-Signature": _sign(HMAC_SECRET, ts, body),
                    },
                )
                assert ok.status_code == 200

            ts = str(int(time.time()))
            blocked = client.post(
                "/analyze",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Timestamp": ts,
                    "X-Signature": _sign(HMAC_SECRET, ts, body),
                },
            )

        assert blocked.status_code == 429
        assert blocked.json()["detail"] == "Too many requests"
        # Retry-After is informational for clients; must be a positive int.
        assert int(blocked.headers["retry-after"]) >= 1

    def test_health_endpoint_is_not_rate_limited(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        # Limiter is wired only on the analyze router. Confirm /healthz keeps
        # answering even when the analyze budget is exhausted.
        tiny_limiter = FixedWindowLimiter(limit=1, window_seconds=60)
        monkeypatch.setattr(rate_limit, "_limiter", tiny_limiter)
        tiny_limiter.hit("testclient")  # pre-exhaust the budget for this key

        from app.main import create_app

        with TestClient(create_app()) as client:
            for _ in range(5):
                assert client.get("/healthz").status_code == 200
