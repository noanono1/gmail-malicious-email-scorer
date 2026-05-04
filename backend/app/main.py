from __future__ import annotations

import time
import uuid

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from app.config import MAX_REQUEST_BYTES
from app.log_setup import setup_logging
from app.routes import analyze, health

setup_logging()
logger = structlog.get_logger()


def create_app(*, max_request_bytes: int = MAX_REQUEST_BYTES) -> FastAPI:
    # Schema endpoints (/docs, /redoc, /openapi.json) are unconditionally
    # disabled. There is no production reason to publish the API surface,
    # and no toggle to forget to flip in deployment.
    application = FastAPI(
        title="Malicious Email Scorer",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # Middleware registration is LIFO: the LAST @middleware decorator ends up
    # outermost (runs first on the way in, last on the way out). The intended
    # execution order is:
    #   1. _request_context_middleware  — outermost; tags every response with
    #      a request_id and logs duration, including 411/413 short-circuits
    #      from the size middleware below.
    #   2. _enforce_request_size  — innermost user middleware; rejects
    #      oversized bodies before the route's HMAC dependency reads the body.

    @application.middleware("http")
    async def _enforce_request_size(request: Request, call_next) -> Response:  # noqa: ANN001
        """Reject oversized bodies before HMAC reads anything into memory.

        POST must declare a Content-Length so we can fail fast — a missing
        length is rejected with 411. This rejects chunked POST bodies, which
        is acceptable here because Apps Script's UrlFetchApp always sets
        Content-Length."""
        if request.method == "POST":
            content_length = request.headers.get("content-length")
            if content_length is None:
                return JSONResponse(
                    status_code=411, content={"detail": "Length Required"}
                )
            try:
                declared_length = int(content_length)
            except ValueError:
                return JSONResponse(
                    status_code=400, content={"detail": "Invalid Content-Length"}
                )
            if declared_length > max_request_bytes:
                return JSONResponse(
                    status_code=413, content={"detail": "Request body too large"}
                )
        return await call_next(request)

    @application.middleware("http")
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

    application.include_router(health.router)
    application.include_router(analyze.router)

    return application


app = create_app()
