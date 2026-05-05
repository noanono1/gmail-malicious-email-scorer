import os

from dotenv import load_dotenv

load_dotenv()


def _env_int(name: str, *, default: int, minimum: int = 1) -> int:
    """Fall back to *default* on missing, non-numeric, or sub-*minimum* values.

    The minimum guards against typos like ``MAX_REQUEST_BYTES=0`` silently
    disabling the endpoint."""
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value >= minimum else default


def _env_bool(name: str, *, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"true", "1", "yes", "on"}


HMAC_SECRET: str = os.environ["HMAC_SECRET"]
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

# Memory-blowup guard applied before HMAC reads the body. Pydantic per-field
# limits are the real correctness gate.
MAX_REQUEST_BYTES: int = _env_int("MAX_REQUEST_BYTES", default=1_048_576)

RATE_LIMIT_PER_WINDOW: int = _env_int("RATE_LIMIT_PER_WINDOW", default=60)
RATE_LIMIT_WINDOW_SECONDS: int = _env_int("RATE_LIMIT_WINDOW_SECONDS", default=60)

# "local" (Ollama) keeps email content on-host. "openai" sends subjects and
# bodies to a third-party API — opt-in for development.
LANGUAGE_PROVIDER: str = os.getenv("LANGUAGE_PROVIDER", "local").strip().lower()

LLM_HOST: str = os.getenv("LLM_HOST", "http://localhost:11434")
LLM_MODEL: str = os.getenv("LLM_MODEL", "gemma:2b")
# Bounds the per-email wait when Ollama accepts but stalls, so a degraded
# SLM falls back to the blind spot instead of blocking the add-on.
LLM_TIMEOUT: int = _env_int("LLM_TIMEOUT", default=8)

OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
OPENAI_TIMEOUT: int = _env_int("OPENAI_TIMEOUT", default=8)

# Off by default so deployments without a configured SLM provider do not emit
# a LANGUAGE_ASSESSMENT blind spot on every email.
LANGUAGE_ANALYZER_ENABLED: bool = _env_bool("LANGUAGE_ANALYZER_ENABLED", default=False)
