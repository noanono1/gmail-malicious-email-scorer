from __future__ import annotations

import hashlib
import hmac
import time

from fastapi import Header, HTTPException, Request

from app.config import HMAC_SECRET

MAX_TIMESTAMP_DRIFT_SECONDS = 300


async def verify_hmac(
    request: Request,
    x_signature: str = Header(),
    x_timestamp: str = Header(),
) -> None:
    try:
        request_timestamp = int(x_timestamp)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid timestamp") from None

    if abs(time.time() - request_timestamp) > MAX_TIMESTAMP_DRIFT_SECONDS:
        raise HTTPException(status_code=401, detail="Request expired")

    request_body = await request.body()

    expected_signature = hmac.new(
        HMAC_SECRET.encode(),
        x_timestamp.encode() + b"." + request_body,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected_signature, x_signature):
        raise HTTPException(status_code=401, detail="Invalid signature")
