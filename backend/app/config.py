import os

from dotenv import load_dotenv

load_dotenv()

HMAC_SECRET: str = os.environ["HMAC_SECRET"]
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
