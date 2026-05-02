from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends

from app.auth import verify_hmac
from app.dependencies import DetectionEngineDependency
from app.schemas import AnalyzeRequest, AnalyzeResponse

logger = structlog.get_logger()

router = APIRouter(tags=["analysis"], dependencies=[Depends(verify_hmac)])


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_email(
    email_request: AnalyzeRequest,
    detection_engine: DetectionEngineDependency,
) -> AnalyzeResponse:
    email_data = email_request.to_domain()

    structlog.contextvars.bind_contextvars(message_id=email_data.message_id)

    analysis_result = detection_engine.analyze(email_data)

    logger.info(
        "analysis_complete",
        verdict=analysis_result.verdict.value,
        score=analysis_result.score,
        signal_count=len(analysis_result.signals),
        blind_spot_count=len(analysis_result.blind_spots),
    )

    return AnalyzeResponse.from_domain(analysis_result)
