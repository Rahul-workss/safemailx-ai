import os
from pathlib import Path

from dotenv import load_dotenv


SRC_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = SRC_DIR.parent

load_dotenv(PROJECT_ROOT / ".env")

MODEL_PATH = PROJECT_ROOT / "models" / "phishing_ai_model.joblib"
REPORTS_DIR = PROJECT_ROOT / "reports"
TEMP_IMAGES_DIR = SRC_DIR / "temp_images"
GMAIL_CREDENTIALS_PATH = SRC_DIR / "credentials.json"
GMAIL_TOKEN_PATH = SRC_DIR / "token.pickle"

LM_STUDIO_URL = os.getenv(
    "LM_STUDIO_URL",
    "http://127.0.0.1:1234/v1/chat/completions",
)
LM_STUDIO_MODEL = os.getenv("LM_STUDIO_MODEL", "qwen2.5-7b-instruct-1m")
LM_STUDIO_TIMEOUT = int(os.getenv("LM_STUDIO_TIMEOUT", "300"))
LM_STUDIO_AUTO_CONTEXT = os.getenv("LM_STUDIO_AUTO_CONTEXT", "true").strip().lower() in {
    "1", "true", "yes", "on"
}
LM_STUDIO_MAX_CONTEXT_TOKENS = int(os.getenv("LM_STUDIO_MAX_CONTEXT_TOKENS", "1010000"))
LM_STUDIO_MAX_OUTPUT_TOKENS = int(os.getenv("LM_STUDIO_MAX_OUTPUT_TOKENS", "700"))
LM_STUDIO_EMAIL_CHAR_LIMIT = int(os.getenv("LM_STUDIO_EMAIL_CHAR_LIMIT", "120000"))

SAFEMAILX_DEBUG = os.getenv("SAFEMAILX_DEBUG", "").strip().lower() in {
    "1", "true", "yes", "on"
}

SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY", "").strip()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
TESSERACT_CMD = os.getenv("TESSERACT_CMD", "").strip()


def is_configured_secret(value: str | None) -> bool:
    if not value:
        return False
    normalized = value.strip()
    if not normalized:
        return False
    return normalized.upper() not in {
        "YOUR_API_KEY_HERE",
        "YOUR_SAFE_BROWSING_API_KEY",
        "YOUR_VIRUSTOTAL_API_KEY",
        "NONE",
        "NULL",
    }


def debug_log(message: str) -> None:
    if SAFEMAILX_DEBUG:
        print(message)
