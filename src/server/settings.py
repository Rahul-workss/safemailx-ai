import os
from pathlib import Path

from cryptography.fernet import Fernet

from utils.config import PROJECT_ROOT


SERVER_HOST = os.getenv("SAFEMAILX_API_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("SAFEMAILX_API_PORT", "8080"))
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8080")
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"sqlite:///{PROJECT_ROOT / 'safemailx_app.db'}",
)
REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-before-production")
SAFEMAILX_ADMIN_EMAIL = os.getenv("SAFEMAILX_ADMIN_EMAIL", "admin@safemailx.local")
SAFEMAILX_ADMIN_PASSWORD = os.getenv("SAFEMAILX_ADMIN_PASSWORD", "change-me-before-production")
SAFEMAILX_PRODUCTION = os.getenv("SAFEMAILX_PRODUCTION", "false").strip().lower() in {
    "1", "true", "yes", "on"
}
SAFEMAILX_REQUIRE_AUTH = os.getenv(
    "SAFEMAILX_REQUIRE_AUTH",
    "true" if SAFEMAILX_PRODUCTION else "false",
).strip().lower() in {
    "1", "true", "yes", "on"
}
FEATURE_REFRESH_TOKEN_ENABLED = os.getenv("FEATURE_REFRESH_TOKEN_ENABLED", "true").strip().lower() in {
    "1", "true", "yes", "on"
}
JWT_EXPIRES_MINUTES = int(os.getenv("JWT_EXPIRES_MINUTES", "1440"))
REFRESH_TOKEN_EXPIRES_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRES_DAYS", "30"))
REPORT_BASE_DIR = Path(os.getenv("REPORT_BASE_DIR", str(PROJECT_ROOT / "reports")))
SCAN_MODE_DEFAULT = os.getenv("SAFEMAILX_SCAN_MODE", "balanced").lower()
GMAIL_POLL_INTERVAL_SECONDS = int(os.getenv("GMAIL_POLL_INTERVAL_SECONDS", "60"))
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(10 * 1024 * 1024)))
MAX_BODY_BYTES = int(os.getenv("MAX_BODY_BYTES", str(12 * 1024 * 1024)))
AUTH_LOCKOUT_MINUTES = int(os.getenv("AUTH_LOCKOUT_MINUTES", "15"))
RATE_LIMIT_AUTH_LOGIN = os.getenv("RATE_LIMIT_AUTH_LOGIN", "5/minute")
RATE_LIMIT_AUTH_REGISTER = os.getenv("RATE_LIMIT_AUTH_REGISTER", "3/minute")
RATE_LIMIT_AUTH_RESET = os.getenv("RATE_LIMIT_AUTH_RESET", "3/hour")
RATE_LIMIT_INSTANT_SCAN = os.getenv("RATE_LIMIT_INSTANT_SCAN", "30/minute")
RATE_LIMIT_SCANS = os.getenv("RATE_LIMIT_SCANS", "100/hour")
RATE_LIMIT_GMAIL = os.getenv("RATE_LIMIT_GMAIL", "20/minute")
RATE_LIMIT_DEFAULT = os.getenv("RATE_LIMIT_DEFAULT", "60/minute")
WS_MAX_SECONDS = int(os.getenv("WS_MAX_SECONDS", "300"))
CORS_ALLOWED_ORIGINS = [
    value.strip()
    for value in os.getenv(
        "CORS_ALLOWED_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000,http://192.168.56.1:3000",
    ).split(",")
    if value.strip()
]
GMAIL_TOKEN_ENCRYPTION_KEY = os.getenv("GMAIL_TOKEN_ENCRYPTION_KEY", "").strip()
GMAIL_OAUTH_REDIRECT_URI = os.getenv("GMAIL_OAUTH_REDIRECT_URI", "http://127.0.0.1:8080/api/gmail/oauth/callback")
EXPO_ACCESS_TOKEN = os.getenv("EXPO_ACCESS_TOKEN", "").strip()
PASSWORD_RESET_URL_BASE = os.getenv("PASSWORD_RESET_URL_BASE", "http://127.0.0.1:8080/reset-password")
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").strip()
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "").strip()
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").strip().lower() in {"1", "true", "yes", "on"}

# Bot integration (WhatsApp + Telegram SMS forwarding)
# Twilio (WhatsApp Business API)
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "").strip()
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "").strip()
TWILIO_WHATSAPP_NUMBER = os.getenv("TWILIO_WHATSAPP_NUMBER", "").strip()
# Telegram
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET", "").strip()
# Feature flags -- default off; set to true once credentials are configured
FEATURE_WHATSAPP_BOT_ENABLED = os.getenv("FEATURE_WHATSAPP_BOT_ENABLED", "false").strip().lower() in {
    "1", "true", "yes", "on"
}
FEATURE_TELEGRAM_BOT_ENABLED = os.getenv("FEATURE_TELEGRAM_BOT_ENABLED", "false").strip().lower() in {
    "1", "true", "yes", "on"
}


def validate_security_settings() -> None:
    """Fail closed for production-shaped deployments with unsafe secrets/config."""
    if not SAFEMAILX_PRODUCTION:
        return
    if not SAFEMAILX_REQUIRE_AUTH:
        raise RuntimeError("SAFEMAILX_REQUIRE_AUTH must be true in production")
    if DATABASE_URL.startswith("sqlite:///"):
        raise RuntimeError("DATABASE_URL must use a persistent production database")
    if REDIS_URL.startswith(("redis://127.0.0.1", "redis://localhost", "rediss://127.0.0.1", "rediss://localhost")):
        raise RuntimeError("REDIS_URL must point to the production Redis service")
    if len(JWT_SECRET) < 32 or JWT_SECRET.lower() in {
        "change-me-before-production",
        "replace-with-long-random-secret",
    }:
        raise RuntimeError("JWT_SECRET must be at least 32 random characters in production")
    if not GMAIL_TOKEN_ENCRYPTION_KEY:
        raise RuntimeError("GMAIL_TOKEN_ENCRYPTION_KEY is required in production")
    try:
        Fernet(GMAIL_TOKEN_ENCRYPTION_KEY.encode("utf-8"))
    except Exception as exc:
        raise RuntimeError("GMAIL_TOKEN_ENCRYPTION_KEY is invalid") from exc
    if not SMTP_HOST or not SMTP_FROM_EMAIL:
        raise RuntimeError(
            "SMTP_HOST and SMTP_FROM_EMAIL are required in production "
            "to deliver password reset emails"
        )
