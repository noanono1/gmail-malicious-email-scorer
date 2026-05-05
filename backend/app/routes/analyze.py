from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app.auth import verify_hmac
from app.dependencies import DetectionEngineDependency
from app.rate_limit import enforce_rate_limit
from app.schemas import AnalyzeRequest, AnalyzeResponse
from detection_engine import AnalyzerCrashed

logger = structlog.get_logger()

# Rate limit runs before HMAC so blocked clients short-circuit before SHA256.
router = APIRouter(
    tags=["analysis"],
    dependencies=[Depends(enforce_rate_limit), Depends(verify_hmac)],
)


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
