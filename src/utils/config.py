import os
from pathlib import Path

from dotenv import load_dotenv


SRC_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = SRC_DIR.parent

load_dotenv(PROJECT_ROOT / ".env", override=True)

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
LM_STUDIO_MODEL = os.getenv("LM_STUDIO_MODEL", "qwen3-8b")  # Updated: Qwen 3 8B (Aug 2026)
LM_STUDIO_TIMEOUT = int(os.getenv("LM_STUDIO_TIMEOUT", "300"))
LM_STUDIO_AUTO_CONTEXT = os.getenv("LM_STUDIO_AUTO_CONTEXT", "true").strip().lower() in {
    "1", "true", "yes", "on"
}
LM_STUDIO_MAX_CONTEXT_TOKENS = int(os.getenv("LM_STUDIO_MAX_CONTEXT_TOKENS", "1010000"))
LM_STUDIO_MAX_OUTPUT_TOKENS = int(os.getenv("LM_STUDIO_MAX_OUTPUT_TOKENS", "3200"))
LM_STUDIO_EMAIL_CHAR_LIMIT = int(os.getenv("LM_STUDIO_EMAIL_CHAR_LIMIT", "120000"))

# Generic production LLM settings. The old LM_STUDIO_* names remain supported
# for local demos, while server deployments can point at vLLM/Ollama/llama.cpp.
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "lmstudio").strip().lower()
LLM_BASE_URL = os.getenv("LLM_BASE_URL", LM_STUDIO_URL).strip()
LLM_MODEL = os.getenv("LLM_MODEL", LM_STUDIO_MODEL).strip()
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", str(LM_STUDIO_TIMEOUT)))
LLM_MAX_CONTEXT_TOKENS = int(os.getenv("LLM_MAX_CONTEXT_TOKENS", str(LM_STUDIO_MAX_CONTEXT_TOKENS)))
LLM_MAX_OUTPUT_TOKENS = int(os.getenv("LLM_MAX_OUTPUT_TOKENS", str(LM_STUDIO_MAX_OUTPUT_TOKENS)))

# ── Qwen 3 temperature configurations (evaluated in Step 5) ────────────────
# Do NOT apply either to the payload yet — Step 5 decides which to use.
TEMP_CONSERVATIVE = {"temperature": 0.1, "top_p": 0.80}   # Qwen 2.5 baseline values
TEMP_THINKING     = {"temperature": 0.6, "top_p": 0.95}   # Qwen 3 thinking-mode recommended

# LLM_MAX_OUTPUT_TOKENS budget breakdown for Qwen 3 (thinking mode):
# think_block   : up to ~2048 tokens  (internal reasoning)
# json_output   : ~400 tokens         (same structure as Qwen 2.5)
# buffer        : ~256 tokens         (</think> close, whitespace, margin)
# safety margin : ~496 tokens
# total         : 3200 tokens
#
# For non-thinking mode (enable_thinking=False), use max_tokens=700 in payload.
LLM_EMAIL_CHAR_LIMIT = int(os.getenv("LLM_EMAIL_CHAR_LIMIT", str(LM_STUDIO_EMAIL_CHAR_LIMIT)))
LLM_SCAN_MODE = os.getenv("LLM_SCAN_MODE", "balanced").strip().lower()
LLM_HEALTH_URL = os.getenv("LLM_HEALTH_URL", "").strip()
# Enable Qwen 3 chain-of-thought reasoning (chat_template_kwargs in LM Studio payload).
# Set LLM_ENABLE_THINKING=false in .env to disable (e.g., for Qwen 2.5 rollback).
LLM_ENABLE_THINKING = os.getenv("LLM_ENABLE_THINKING", "true").strip().lower() in {
    "1", "true", "yes", "on"
}

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


# ── Feature flags ──────────────────────────────────────────────────────────
# Each new feature ships behind a flag defaulting to a safe value.
# Set to true in .env to enable.

FEATURE_QR_DETECTION_ENABLED = os.getenv("FEATURE_QR_DETECTION_ENABLED", "true").strip().lower() in {
    "1", "true", "yes", "on"
}

FEATURE_PROMPT_INJECTION_GUARD_ENABLED = os.getenv("FEATURE_PROMPT_INJECTION_GUARD_ENABLED", "true").strip().lower() in {
    "1", "true", "yes", "on"
}

FEATURE_OFFLINE_SAFEBROWSING_ENABLED = os.getenv("FEATURE_OFFLINE_SAFEBROWSING_ENABLED", "true").strip().lower() in {
    "1", "true", "yes", "on"
}
# Empty by default — set to a feed URL to enable auto-sync.
# Examples:
#   OpenPhish:  https://openphish.com/feed.txt
#   PhishTank:  https://data.phishtank.com/data/online-valid.csv (requires free API account)
OFFLINE_HASH_FEED_URL = os.getenv("OFFLINE_HASH_FEED_URL", "").strip()
OFFLINE_HASH_SYNC_INTERVAL_HOURS = float(os.getenv("OFFLINE_HASH_SYNC_INTERVAL_HOURS", "6"))

FEATURE_CAMPAIGN_CORRELATION_ENABLED = os.getenv("FEATURE_CAMPAIGN_CORRELATION_ENABLED", "true").strip().lower() in {
    "1", "true", "yes", "on"
}
CAMPAIGN_CORRELATION_WINDOW_HOURS = int(os.getenv("CAMPAIGN_CORRELATION_WINDOW_HOURS", "48"))
CAMPAIGN_CORRELATION_MIN_MATCHES = int(os.getenv("CAMPAIGN_CORRELATION_MIN_MATCHES", "3"))

FEATURE_ADAPTIVE_TRUST_ENABLED = os.getenv("FEATURE_ADAPTIVE_TRUST_ENABLED", "true").strip().lower() in {
    "1", "true", "yes", "on"
}
ADAPTIVE_TRUST_MIN_SCANS = int(os.getenv("ADAPTIVE_TRUST_MIN_SCANS", "3"))

FEATURE_SECOND_LOOK_RESCAN_ENABLED = os.getenv("FEATURE_SECOND_LOOK_RESCAN_ENABLED", "true").strip().lower() in {
    "1", "true", "yes", "on"
}
RESCAN_INTERVAL_HOURS = float(os.getenv("RESCAN_INTERVAL_HOURS", "12"))
RESCAN_LOOKBACK_HOURS = int(os.getenv("RESCAN_LOOKBACK_HOURS", "24"))

FEATURE_VISHING_DETECTION_ENABLED = os.getenv("FEATURE_VISHING_DETECTION_ENABLED", "false").strip().lower() in {
    "1", "true", "yes", "on"
}
# Whisper model size for vishing detection.
# MUST be 'tiny' (~75MB) on Koyeb/Render free tier (512MB RAM limit).
# Other valid values: 'base', 'small', 'medium', 'large' (for self-hosted).
WHISPER_MODEL_SIZE = os.getenv("WHISPER_MODEL_SIZE", "tiny").strip().lower()

