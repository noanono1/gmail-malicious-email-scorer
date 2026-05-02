# --- HMAC Authentication ---
#
# WHAT PROBLEM THIS SOLVES:
# Our /analyze endpoint is public on the internet. Without auth, anyone could
# send fake emails to it and get analysis results — or worse, probe our engine.
# We need to verify that the request really came from our Gmail Add-on.
#
# HOW IT WORKS (shared secret model):
# Both sides (Add-on + backend) know the same secret string (HMAC_SECRET).
# The Add-on signs every request: HMAC(secret, timestamp + body) → signature.
# The backend recomputes the same HMAC and compares. If they match, the sender
# knows the secret → it's our Add-on (or someone who stole the secret).
#
# WHY HMAC AND NOT JUST SENDING THE SECRET IN A HEADER:
# If we sent the raw secret, anyone sniffing one request (even over HTTPS logs)
# gets the secret forever. HMAC proves you KNOW the secret without revealing it.
# Different body → different signature, so captured signatures can't be reused
# on different payloads.
#
# WHY NOT PUBLIC/PRIVATE KEY (asymmetric crypto):
# We only have two parties that we both control. A shared secret is simpler
# and sufficient. Asymmetric crypto (RSA, ECDSA) is for when you need to prove
# identity WITHOUT sharing a secret — like TLS does between browser and server.
# TLS already protects our transport; HMAC just authenticates the caller.

from __future__ import annotations

import hashlib
import hmac
import time

from fastapi import Header, HTTPException, Request

from app.config import HMAC_SECRET

# WHY 5 MINUTES: limits replay attacks. If an attacker captures a valid request
# (e.g., from logs), they can only replay it within this window. Not perfect
# (a nonce/database would be), but good enough for a demo with no persistence.
MAX_TIMESTAMP_DRIFT_SECONDS = 300


async def verify_hmac(
    request: Request,
    # FastAPI magic: param named x_signature → reads header "X-Signature".
    # Header() tells FastAPI "this comes from HTTP headers, not the URL/body".
    x_signature: str = Header(),
    x_timestamp: str = Header(),
) -> None:
    """FastAPI dependency — runs BEFORE the route handler.
    If this raises HTTPException, the handler never executes.
    Usage: router = APIRouter(dependencies=[Depends(verify_hmac)])"""

    # Step 1: Validate timestamp format
    try:
        request_timestamp = int(x_timestamp)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid timestamp")

    # Step 2: Reject stale requests (anti-replay)
    # abs() handles clock skew in both directions
    if abs(time.time() - request_timestamp) > MAX_TIMESTAMP_DRIFT_SECONDS:
        raise HTTPException(status_code=401, detail="Request expired")

    # Step 3: Read raw body bytes (must be identical to what the Add-on signed)
    request_body = await request.body()

    # Step 4: Recompute the expected signature
    # HMAC = Hash-based Message Authentication Code
    # Input: secret key + message → deterministic output (hex string)
    # We bind the timestamp INTO the signed message so an attacker can't
    # take a valid signature and pair it with a different timestamp.
    expected_signature = hmac.new(
        HMAC_SECRET.encode(),           # the shared secret (key)
        f"{x_timestamp}".encode() + request_body,  # the message: timestamp + body
        hashlib.sha256,                 # hash algorithm
    ).hexdigest()                       # output as hex string

    # Step 5: Compare signatures
    # compare_digest() takes the SAME time regardless of how many bytes match.
    # Regular == would short-circuit on first mismatch, leaking how many
    # leading bytes are correct → an attacker could guess byte-by-byte.
    if not hmac.compare_digest(expected_signature, x_signature):
        raise HTTPException(status_code=401, detail="Invalid signature")
