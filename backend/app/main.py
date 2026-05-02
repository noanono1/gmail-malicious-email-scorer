# --- App Factory & Middleware ---
#
# This is the FastAPI entry point — the file that uvicorn loads.
# Run with: uvicorn app.main:app --reload
#
# PATTERN: "app factory" — create_app() builds and returns the FastAPI instance.
# This lets tests create a fresh app per test without import side effects.

from __future__ import annotations

import time
import uuid

import structlog
from fastapi import FastAPI, Request, Response

from app.log_setup import setup_logging
from app.routes import analyze, health

# Called at import time — configures structlog ONCE for the whole process.
setup_logging()
logger = structlog.get_logger()


def create_app() -> FastAPI:
    application = FastAPI(
        title="Malicious Email Scorer",
        # docs_url=None disables the auto-generated /docs page.
        # We don't want to expose our API schema publicly.
        docs_url=None,
        redoc_url=None,
    )

    # Middleware wraps EVERY request. It runs before the route handler
    # and after the response. Think of it as a pipeline stage.
    application.middleware("http")(_request_context_middleware)

    # include_router mounts route groups. Each router defines its own
    # endpoints — this keeps main.py as pure wiring.
    application.include_router(health.router)
    application.include_router(analyze.router)

    return application


async def _request_context_middleware(request: Request, call_next) -> Response:  # noqa: ANN001
    """Runs on every request. Two jobs:
    1. Assign a unique request_id so all log lines from one request are linked.
    2. Measure and log request duration."""

    # Short random ID to correlate all log lines from this request
    request_id = uuid.uuid4().hex[:12]

    # structlog contextvars: any log.info() call in this request's code path
    # will automatically include request_id without passing it explicitly.
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(request_id=request_id)

    # time.monotonic() never goes backwards (unlike time.time() which adjusts
    # for NTP). Better for measuring elapsed time.
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


# Module-level instance — uvicorn imports this: uvicorn app.main:app
app = create_app()
