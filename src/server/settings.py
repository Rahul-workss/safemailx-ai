import os
from pathlib import Path

from utils.config import PROJECT_ROOT


SERVER_HOST = os.getenv("TRUSTMAIL_API_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("TRUSTMAIL_API_PORT", "8080"))
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"sqlite:///{PROJECT_ROOT / 'trustmail_app.db'}",
)
REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-before-production")
TRUSTMAIL_ADMIN_EMAIL = os.getenv("TRUSTMAIL_ADMIN_EMAIL", "admin@trustmail.local")
TRUSTMAIL_ADMIN_PASSWORD = os.getenv("TRUSTMAIL_ADMIN_PASSWORD", "change-me-before-production")
TRUSTMAIL_REQUIRE_AUTH = os.getenv("TRUSTMAIL_REQUIRE_AUTH", "").strip().lower() in {
    "1", "true", "yes", "on"
}
JWT_EXPIRES_MINUTES = int(os.getenv("JWT_EXPIRES_MINUTES", "1440"))
REPORT_BASE_DIR = Path(os.getenv("REPORT_BASE_DIR", str(PROJECT_ROOT / "reports")))
SCAN_MODE_DEFAULT = os.getenv("TRUSTMAIL_SCAN_MODE", "balanced").lower()
GMAIL_POLL_INTERVAL_SECONDS = int(os.getenv("GMAIL_POLL_INTERVAL_SECONDS", "60"))
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(10 * 1024 * 1024)))
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
