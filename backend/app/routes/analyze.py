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

# TODO: add safety checks on request size/content to prevent abuse (e.g. DoS with huge emails)
# TODO: verify the request originates from an active add-on session, not arbitrary callers
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

    logger.info(
        "analysis_complete",
        verdict=analysis_result.verdict.value,
        score=analysis_result.score,
        signal_count=len(analysis_result.signals),
        blind_spot_count=len(analysis_result.blind_spots),
    )

    return AnalyzeResponse.from_domain(analysis_result)
