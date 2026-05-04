"""HTTP-boundary tests for /analyze.

Covers the request authentication contract (HMAC + timestamp drift), the
required-header contract enforced by FastAPI, and the response shape the
Gmail Add-on relies on. These are the only tests that exercise the
FastAPI adapter end-to-end via a real HTTP client."""

from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def secret() -> str:
    # Read from the live config so test signing always matches what auth.py
    # validates against, regardless of whether the value came from conftest's
    # setdefault, the shell environment, or .env.
    from app.config import HMAC_SECRET

    return HMAC_SECRET


@pytest.fixture(scope="module")
def client() -> TestClient:
    from app.main import app

    return TestClient(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sign(secret: str, timestamp: str, body: bytes) -> str:
    return hmac.new(
        secret.encode(),
        timestamp.encode() + b"." + body,
        hashlib.sha256,
    ).hexdigest()


def _minimal_payload() -> dict:
    """Smallest valid AnalyzeRequest the engine will accept."""
    return {
        "message_id": "api-test-001",
        "sender_address": "user@example.com",
        "sender_display_name": "",
        "recipient": "victim@example.com",
        "subject": "Hello",
        "body_text": "Hello",
        "body_html": "",
    }


def _post_signed(
    client: TestClient,
    secret: str,
    *,
    payload: dict | None = None,
    timestamp: str | None = None,
    signature: str | None = None,
    body_override: bytes | None = None,
) -> "TestClient.response_class":  # pragma: no cover - type-only annotation
    payload = payload if payload is not None else _minimal_payload()
    body_for_signing = body_override if body_override is not None else json.dumps(payload).encode("utf-8")
    body_for_sending = body_override if body_override is not None else body_for_signing

    ts = timestamp if timestamp is not None else str(int(time.time()))
    sig = signature if signature is not None else _sign(secret, ts, body_for_signing)

    return client.post(
        "/analyze",
        content=body_for_sending,
        headers={
            "Content-Type": "application/json",
            "X-Timestamp": ts,
            "X-Signature": sig,
        },
    )


# ---------------------------------------------------------------------------
# Valid signed request
# ---------------------------------------------------------------------------


class TestValidSignedRequest:
    def test_returns_200(self, client: TestClient, secret: str):
        response = _post_signed(client, secret)
        assert response.status_code == 200

    def test_response_shape(self, client: TestClient, secret: str):
        response = _post_signed(client, secret)
        body = response.json()

        # Top-level fields the Gmail Add-on consumes.
        assert set(body.keys()) >= {
            "verdict",
            "score",
            "explanation",
            "signals",
            "top_signals",
            "active_categories",
            "blind_spots",
            "scope",
        }

        assert body["verdict"] in {"safe", "suspicious", "likely_malicious", "malicious"}
        assert isinstance(body["score"], (int, float))
        assert 0.0 <= body["score"] <= 100.0
        assert isinstance(body["explanation"], str) and body["explanation"]
        assert isinstance(body["signals"], list)
        assert isinstance(body["top_signals"], list)
        assert isinstance(body["active_categories"], list)
        assert isinstance(body["blind_spots"], list)

        scope = body["scope"]
        assert isinstance(scope, dict)
        assert set(scope.keys()) >= {
            "analyzers_run",
            "intel_sources_run",
            "has_html",
            "has_attachments",
            "has_auth_headers",
        }
        # All five analyzers should run on every request, including the minimal one.
        assert {
            "authentication_analyzer",
            "sender_analyzer",
            "body_content_analyzer",
            "url_structure_analyzer",
            "attachment_analyzer",
        } <= set(scope["analyzers_run"])

    def test_minimal_email_is_safe(self, client: TestClient, secret: str):
        # Behavioural anchor: an empty-ish email must never come back malicious.
        response = _post_signed(client, secret)
        body = response.json()
        assert body["verdict"] == "safe"
        assert body["score"] == 0.0

    def test_minimal_email_reports_blind_spots(self, client: TestClient, secret: str):
        # Even a SAFE verdict must declare what could not be inspected.
        response = _post_signed(client, secret)
        blind_spot_areas = {bs["area"] for bs in response.json()["blind_spots"]}
        assert "thread_history" in blind_spot_areas
        assert "authentication_headers" in blind_spot_areas


# ---------------------------------------------------------------------------
# Missing required headers — FastAPI returns 422 before auth runs
# ---------------------------------------------------------------------------


class TestMissingRequiredHeaders:
    def test_missing_signature_returns_422(self, client: TestClient):
        body = json.dumps(_minimal_payload()).encode("utf-8")
        response = client.post(
            "/analyze",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Timestamp": str(int(time.time())),
            },
        )
        assert response.status_code == 422

    def test_missing_timestamp_returns_422(self, client: TestClient):
        body = json.dumps(_minimal_payload()).encode("utf-8")
        response = client.post(
            "/analyze",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Signature": "0" * 64,
            },
        )
        assert response.status_code == 422

    def test_no_auth_headers_returns_422(self, client: TestClient):
        body = json.dumps(_minimal_payload()).encode("utf-8")
        response = client.post(
            "/analyze",
            content=body,
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 422


# ---------------------------------------------------------------------------
# Timestamp validation — handled by verify_hmac, returns 401
# ---------------------------------------------------------------------------


class TestTimestampValidation:
    def test_non_numeric_timestamp_rejected(self, client: TestClient, secret: str):
        response = _post_signed(
            client,
            secret,
            timestamp="not-a-number",
            signature="0" * 64,
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid timestamp"

    def test_expired_timestamp_rejected(self, client: TestClient, secret: str):
        # 10 minutes in the past — well outside the 5-minute drift window.
        old_timestamp = str(int(time.time()) - 600)
        response = _post_signed(client, secret, timestamp=old_timestamp)
        assert response.status_code == 401
        assert response.json()["detail"] == "Request expired"

    def test_future_timestamp_beyond_drift_rejected(self, client: TestClient, secret: str):
        # 10 minutes in the future — also outside the drift window.
        future_timestamp = str(int(time.time()) + 600)
        response = _post_signed(client, secret, timestamp=future_timestamp)
        assert response.status_code == 401
        assert response.json()["detail"] == "Request expired"

    def test_timestamp_inside_drift_window_accepted(self, client: TestClient, secret: str):
        # 60 seconds in the past — well inside the 5-minute drift window.
        recent_timestamp = str(int(time.time()) - 60)
        response = _post_signed(client, secret, timestamp=recent_timestamp)
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# Signature validation — wrong secret, wrong digest, tampered body
# ---------------------------------------------------------------------------


class TestSignatureValidation:
    def test_invalid_signature_rejected(self, client: TestClient, secret: str):
        response = _post_signed(client, secret, signature="0" * 64)
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid signature"

    def test_signature_signed_with_wrong_secret_rejected(self, client: TestClient, secret: str):
        body = json.dumps(_minimal_payload()).encode("utf-8")
        ts = str(int(time.time()))
        wrong_signature = _sign("a-different-secret", ts, body)
        response = _post_signed(client, secret, timestamp=ts, signature=wrong_signature)
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid signature"

    def test_tampered_body_rejected(self, client: TestClient, secret: str):
        # Sign over the original body, then mutate the body before sending.
        original_body = json.dumps(_minimal_payload()).encode("utf-8")
        ts = str(int(time.time()))
        signature = _sign(secret, ts, original_body)

        tampered_body = json.dumps(
            {**_minimal_payload(), "subject": "tampered after signing"}
        ).encode("utf-8")

        response = client.post(
            "/analyze",
            content=tampered_body,
            headers={
                "Content-Type": "application/json",
                "X-Timestamp": ts,
                "X-Signature": signature,
            },
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid signature"


# ---------------------------------------------------------------------------
# Health endpoint is deliberately unauthenticated — sanity check
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    def test_healthz_unauthenticated(self, client: TestClient):
        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}
