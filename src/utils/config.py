import os
from pathlib import Path

from dotenv import load_dotenv


SRC_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = SRC_DIR.parent

load_dotenv(PROJECT_ROOT / ".env", override=False)

MODEL_PATH = PROJECT_ROOT / "models" / "phishing_ai_model.joblib"
REPORTS_DIR = PROJECT_ROOT / "reports"
TEMP_IMAGES_DIR = SRC_DIR / "temp_images"
_RENDER_SECRETS = Path("/etc/secrets")
GMAIL_CREDENTIALS_PATH = _RENDER_SECRETS / "credentials.json" if (_RENDER_SECRETS / "credentials.json").exists() else SRC_DIR / "credentials.json"
SIGNIN_CREDENTIALS_PATH = _RENDER_SECRETS / "signin_credentials.json" if (_RENDER_SECRETS / "signin_credentials.json").exists() else SRC_DIR / "server" / "signin_credentials.json"
GMAIL_TOKEN_PATH = SRC_DIR / "token.pickle"
GMAIL_TOKEN_ENCRYPTION_KEY = os.getenv("GMAIL_TOKEN_ENCRYPTION_KEY", "").strip()

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

# Generic production LLM settings. The old LM_STUDIO_* names remain supported
# for local demos, while server deployments can point at vLLM/Ollama/llama.cpp.
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "lmstudio").strip().lower()
LLM_BASE_URL = os.getenv("LLM_BASE_URL", LM_STUDIO_URL).strip()
LLM_MODEL = os.getenv("LLM_MODEL", LM_STUDIO_MODEL).strip()
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", str(LM_STUDIO_TIMEOUT)))
LLM_MAX_CONTEXT_TOKENS = int(os.getenv("LLM_MAX_CONTEXT_TOKENS", str(LM_STUDIO_MAX_CONTEXT_TOKENS)))
LLM_MAX_OUTPUT_TOKENS = int(os.getenv("LLM_MAX_OUTPUT_TOKENS", str(LM_STUDIO_MAX_OUTPUT_TOKENS)))
LLM_EMAIL_CHAR_LIMIT = int(os.getenv("LLM_EMAIL_CHAR_LIMIT", str(LM_STUDIO_EMAIL_CHAR_LIMIT)))
LLM_SCAN_MODE = os.getenv("LLM_SCAN_MODE", "balanced").strip().lower()
LLM_HEALTH_URL = os.getenv("LLM_HEALTH_URL", "").strip()

SAFEMAILX_DEBUG = os.getenv("SAFEMAILX_DEBUG", "").strip().lower() in {
    "1", "true", "yes", "on"
}

SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY", "").strip()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
IPQUALITYSCORE_API_KEY = os.getenv("IPQUALITYSCORE_API_KEY", "").strip()
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
