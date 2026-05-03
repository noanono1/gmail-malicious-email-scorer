from __future__ import annotations

import time
import uuid

import structlog
from fastapi import FastAPI, Request, Response

from app.log_setup import setup_logging
from app.routes import analyze, health

setup_logging()
logger = structlog.get_logger()


def create_app() -> FastAPI:
    application = FastAPI(
        title="Malicious Email Scorer",
        docs_url="/docs", #TODO: Remove that in production
        redoc_url=None,
    )

    application.middleware("http")(_request_context_middleware)
    application.include_router(health.router)
    application.include_router(analyze.router)

    return application


async def _request_context_middleware(request: Request, call_next) -> Response:  # noqa: ANN001
    """Bind request_id to structlog context and log request duration."""
    request_id = uuid.uuid4().hex[:12]
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(request_id=request_id)

    request_start_time = time.monotonic()
    response = await call_next(request)
    request_duration_ms = round((time.monotonic() - request_start_time) * 1000, 1)

    logger.info(
        "request",
        method=request.method,
        path=request.url.path,
        status=response.status_code,
        duration_ms=request_duration_ms,
    )
    return response


app = create_app()
