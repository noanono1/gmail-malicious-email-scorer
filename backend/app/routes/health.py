# --- Health Check Endpoint ---
#
# A minimal endpoint that returns 200 OK. Used by:
# - Hosting platforms (Railway, etc.) to know the app is alive and restart if not
# - Monitoring/uptime checks
# - Quick manual "is it running?" verification
#
# No auth required — it reveals nothing sensitive, just "I'm alive".

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}