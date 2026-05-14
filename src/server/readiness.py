import json
import os
from pathlib import Path
from urllib.parse import urlparse

from utils.config import GMAIL_CREDENTIALS_PATH, is_configured_secret


PLACEHOLDER_VALUES = {
    "change-me-before-production",
    "replace-with-long-random-secret",
    "replace-with-strong-password",
    "your-user",
    "your-password",
    "no-reply@your-domain.com",
}


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _is_truthy(name: str) -> bool:
    return _env(name).lower() in {"1", "true", "yes", "on"}


def _is_real_value(value: str) -> bool:
    normalized = value.strip()
    if not is_configured_secret(normalized):
        return False
    return normalized.lower() not in PLACEHOLDER_VALUES and "YOUR_DOMAIN" not in normalized


def _item(key: str, status: str, message: str) -> dict[str, str]:
    return {"key": key, "status": status, "message": message}


def _credential_file_status(path: Path) -> dict[str, str]:
    if not path.exists():
        return _item("gmail_credentials", "missing", f"Missing Google OAuth client file at {path}.")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return _item("gmail_credentials", "missing", f"Google OAuth credentials file is not valid JSON: {exc}")

    client = payload.get("web") or payload.get("installed") or {}
    client_id = client.get("client_id", "")
    client_secret = client.get("client_secret", "")
    if not _is_real_value(client_id) or not _is_real_value(client_secret):
        return _item("gmail_credentials", "missing", "Google OAuth client_id/client_secret are not configured.")
    return _item("gmail_credentials", "ready", "Google OAuth client credentials are present.")


def _redirect_status(redirect_uri: str, production: bool) -> dict[str, str]:
    parsed = urlparse(redirect_uri)
    if not redirect_uri or "YOUR_DOMAIN" in redirect_uri:
        return _item("gmail_redirect_uri", "missing", "Set GMAIL_OAUTH_REDIRECT_URI to your deployed callback URL.")
    if production and parsed.scheme != "https":
        return _item("gmail_redirect_uri", "missing", "Production Gmail OAuth callback must use HTTPS.")
    if not parsed.netloc:
        return _item("gmail_redirect_uri", "missing", "GMAIL_OAUTH_REDIRECT_URI is not a valid absolute URL.")
    return _item("gmail_redirect_uri", "ready", f"OAuth callback is configured for {parsed.netloc}.")


def build_readiness() -> dict:
    production = _is_truthy("TRUSTMAIL_PRODUCTION") or _is_truthy("TRUSTMAIL_REQUIRE_AUTH")
    items: list[dict[str, str]] = []

    jwt_secret = _env("JWT_SECRET", "change-me-before-production")
    if not production:
        items.append(_item("auth_mode", "warning", "Local mode is active; bearer auth is optional."))
    elif not _is_real_value(jwt_secret) or len(jwt_secret) < 32:
        items.append(_item("jwt_secret", "missing", "Set JWT_SECRET to a unique production secret of at least 32 characters."))
    else:
        items.append(_item("jwt_secret", "ready", "JWT signing secret is production-shaped."))

    admin_email = _env("TRUSTMAIL_ADMIN_EMAIL", "admin@trustmail.local")
    admin_password = _env("TRUSTMAIL_ADMIN_PASSWORD", "change-me-before-production")
    if production and (admin_email.endswith(".local") or not _is_real_value(admin_password) or len(admin_password) < 12):
        items.append(_item("admin_account", "missing", "Set a real TRUSTMAIL_ADMIN_EMAIL and a strong bootstrap admin password."))
    else:
        items.append(_item("admin_account", "ready", "Bootstrap admin account settings are present."))

    items.append(_credential_file_status(GMAIL_CREDENTIALS_PATH))
    items.append(_redirect_status(_env("GMAIL_OAUTH_REDIRECT_URI", "http://127.0.0.1:8080/api/gmail/oauth/callback"), production))

    encryption_key = _env("GMAIL_TOKEN_ENCRYPTION_KEY")
    if production and not encryption_key:
        items.append(_item("gmail_token_encryption", "missing", "Set GMAIL_TOKEN_ENCRYPTION_KEY before storing user Gmail refresh tokens."))
    elif encryption_key:
        items.append(_item("gmail_token_encryption", "ready", "Gmail tokens will be encrypted at rest."))
    else:
        items.append(_item("gmail_token_encryption", "warning", "Gmail token encryption is disabled for local development."))

    smtp_required = production
    smtp_fields = ["SMTP_HOST", "SMTP_FROM_EMAIL", "SMTP_USERNAME", "SMTP_PASSWORD"]
    missing_smtp = [name for name in smtp_fields if not _is_real_value(_env(name))]
    if smtp_required and missing_smtp:
        items.append(_item("smtp", "missing", f"Configure SMTP for password reset delivery: {', '.join(missing_smtp)}."))
    elif missing_smtp:
        items.append(_item("smtp", "warning", "SMTP is not configured; reset links will be printed in local server logs."))
    else:
        items.append(_item("smtp", "ready", "SMTP password reset delivery is configured."))

    if _env("EXPO_ACCESS_TOKEN"):
        items.append(_item("expo_push", "ready", "Expo push access token is configured."))
    else:
        items.append(_item("expo_push", "warning", "EXPO_ACCESS_TOKEN is not set; push delivery may be limited by Expo project settings."))

    if production:
        items.append(_item("oauth_consent", "warning", "Google OAuth consent verification and app-store provider setup must be completed in the provider consoles."))

    ready = all(item["status"] != "missing" for item in items)
    return {
        "environment": "production" if production else "local",
        "ready": ready,
        "items": items,
    }
