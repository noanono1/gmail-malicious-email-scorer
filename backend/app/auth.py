from __future__ import annotations

import hashlib
import hmac
import time

from fastapi import Header, HTTPException, Request

from app.config import HMAC_SECRET

# 5 minutes — if the request is older than this, reject it (prevents replay attacks)
MAX_TIMESTAMP_DRIFT_SECONDS = 300


async def verify_hmac(
    request: Request,
    # FastAPI auto-extracts these from HTTP headers (X-Signature, X-Timestamp).
    # The underscore in the param name becomes a hyphen in the header name.
    x_signature: str = Header(),
    x_timestamp: str = Header(),
) -> None:
    """FastAPI dependency — add to a route with Depends(verify_hmac).
    The route handler doesn't call this directly; FastAPI injects it."""

    try:
        timestamp = int(x_timestamp)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid timestamp")

    if abs(time.time() - timestamp) > MAX_TIMESTAMP_DRIFT_SECONDS:
        raise HTTPException(status_code=401, detail="Request expired")

    body = await request.body()

    # HMAC = keyed hash. Same secret + same message = same hash.
    # We hash (timestamp + body) so the signature is bound to both.
    expected = hmac.new(
        HMAC_SECRET.encode(),
        f"{x_timestamp}".encode() + body,
        hashlib.sha256,
    ).hexdigest()

    # compare_digest prevents timing attacks — constant-time comparison
    # so an attacker can't guess the signature byte-by-byte by measuring response time
    if not hmac.compare_digest(expected, x_signature):
        raise HTTPException(status_code=401, detail="Invalid signature")
