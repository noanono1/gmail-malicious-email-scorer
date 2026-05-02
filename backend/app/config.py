import os

from dotenv import load_dotenv

load_dotenv()

# TODO: restore os.environ["HMAC_SECRET"] before deploy — hardcoded secret must not reach Railway
HMAC_SECRET: str = "test-secret"
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
