# --- Structured Logging Setup ---
#
# WHY STRUCTLOG (not just print or stdlib logging):
# Regular logging gives you flat strings: "Analysis complete for msg 123"
# Structlog gives you key-value pairs: verdict=malicious score=87.3 elapsed_ms=42
# This makes logs searchable and parseable — you can filter by verdict, alert
# on high scores, or graph latency. Essential for production observability.
#
# SECURITY NOTE: We log analysis metadata (score, verdict, signal count) but
# NEVER email content (subject, body, sender). Email content is PII/sensitive.

import logging

import structlog

from app.config import LOG_LEVEL


def setup_logging() -> None:
    # getattr(logging, "INFO") → logging.INFO (the integer 20)
    # This converts the string from our env var to a log level constant.
    log_level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)

    structlog.configure(
        # Processors are a pipeline — each one transforms the log event dict
        # before passing it to the next. Order matters.
        processors=[
            # Pulls in context vars (request_id, message_id) bound earlier
            structlog.contextvars.merge_contextvars,
            # Adds "level": "info" / "warning" / etc.
            structlog.stdlib.add_log_level,
            # Adds ISO timestamp to every log line
            structlog.processors.TimeStamper(fmt="iso"),
            # Pretty-prints for local dev. In production you'd swap this
            # for JSONRenderer() so log aggregators can parse it.
            structlog.dev.ConsoleRenderer(),
        ],
        # Only emit logs at this level or above (e.g., INFO filters out DEBUG)
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        # After first use, reuse the same logger — small perf optimization
        cache_logger_on_first_use=True,
    )
