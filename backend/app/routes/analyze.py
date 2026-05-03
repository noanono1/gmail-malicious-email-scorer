from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app.auth import verify_hmac
from app.dependencies import DetectionEngineDependency
from app.schemas import AnalyzeRequest, AnalyzeResponse
from detection_engine import AnalyzerCrashed

logger = structlog.get_logger()

router = APIRouter(tags=["analysis"], dependencies=[Depends(verify_hmac)])

# TODO: Pydantic enforces field-level limits (max_length on body_text/body_html, max 200
# headers, max 20 attachments) but there is no check on total request payload size.
# A crafted request with many max-length fields could still consume significant memory.
# Options: (a) add a FastAPI middleware that rejects requests exceeding a total byte
# threshold (e.g. 1MB), (b) use a streaming body parser with an early-abort limit,
# (c) rely on a reverse proxy (Railway/nginx) to enforce max body size upstream.
# Option (c) is the lightest for demo, but the app should have its own defense too.
#
# TODO: HMAC auth proves the caller knows the shared secret, but any client with the
# secret can call /analyze — there is no session binding to the Gmail Add-on.
# For demo scope this is acceptable (the secret is never exposed to the browser).
# For production, consider: (a) short-lived tokens issued per add-on session,
# (b) tying HMAC to a per-user nonce from the Apps Script event object,
# (c) OAuth2 service account auth instead of symmetric HMAC.
@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_email(
    email_request: AnalyzeRequest,
    detection_engine: DetectionEngineDependency,
) -> AnalyzeResponse | JSONResponse:
    email_data = email_request.to_domain()

    structlog.contextvars.bind_contextvars(message_id=email_data.message_id)

    try:
        analysis_result = detection_engine.analyze(email_data)
    except AnalyzerCrashed as exc:
        logger.error(
            "analysis_failed",
            analyzer=exc.analyzer_name,
            error=str(exc),
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": "analysis_failed",
                "message": "Email analysis could not be completed due to an internal error.",
            },
        )
    except Exception:
        logger.exception("unexpected_analysis_error")
        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_error",
                "message": "An unexpected error occurred during analysis.",
            },
        )

    logger.info(
        "analysis_complete",
        verdict=analysis_result.verdict.value,
        score=analysis_result.score,
        signal_count=len(analysis_result.signals),
        blind_spot_count=len(analysis_result.blind_spots),
    )

    return AnalyzeResponse.from_domain(analysis_result)
