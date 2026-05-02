# --- Configuration: single place where env vars become Python constants ---
# Everything external (secrets, feature flags) enters the app HERE and nowhere else.
# Other modules import from config — they never call os.environ directly.

import os

from dotenv import load_dotenv

# load_dotenv() reads a .env file into os.environ so we don't have to export
# vars manually every time we start the server during development.
load_dotenv()

# os.environ["X"] raises KeyError if missing — the app crashes at startup
# with a clear error instead of silently running without a secret.
HMAC_SECRET: str = os.environ["HMAC_SECRET"]

# os.getenv("X", default) returns the default if missing — LOG_LEVEL is
# optional, so the app still starts without it.
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
