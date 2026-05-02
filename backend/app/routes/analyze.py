# --- /analyze endpoint ---
#
# THE MAIN ENDPOINT. This is where the Gmail Add-on sends emails for analysis.
#
# REQUEST FLOW:
# 1. Add-on extracts email data from Gmail API
# 2. Add-on signs the request with HMAC and sends POST /analyze
# 3. FastAPI runs verify_hmac dependency FIRST (authentication gate)
# 4. FastAPI validates the JSON body against AnalyzeRequest (Pydantic)
# 5. This handler converts to domain types, runs the engine, returns results
#
# LAYER SEPARATION:
# This file is a thin adapter — it translates HTTP ↔ domain.
# It does NOT contain analysis logic. That's the engine's job.
# Pydantic models (schemas.py) handle serialization.
# Domain models (detection_engine/) handle business logic.

from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends

from app.auth import verify_hmac
from app.dependencies import DetectionEngineDependency
from app.schemas import AnalyzeRequest, AnalyzeResponse

logger = structlog.get_logger()

# dependencies=[Depends(verify_hmac)] → every route on this router runs HMAC
# check before the handler. If auth fails, the handler never executes.
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
