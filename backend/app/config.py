import os

from dotenv import load_dotenv

load_dotenv()


def _env_int(name: str, *, default: int, minimum: int = 1) -> int:
    """Read an int from the environment, falling back to *default* on a
    missing, non-numeric, or out-of-range value (< *minimum*) rather than
    crashing the app at boot. The minimum guards against typos like
    ``MAX_REQUEST_BYTES=0`` silently disabling the endpoint."""
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value >= minimum else default


HMAC_SECRET: str = os.environ["HMAC_SECRET"]
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

# Hard ceiling on the raw request body, applied before HMAC reads anything.
# Per-field Pydantic limits still apply on top and are the real correctness
# gate; this cap is a memory-blowup guard. Default: 1 MiB.
MAX_REQUEST_BYTES: int = _env_int("MAX_REQUEST_BYTES", default=1_048_576)
