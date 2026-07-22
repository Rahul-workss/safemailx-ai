"""
sms_webhook_handler.py -- SafeMail X AI
Handles inbound webhook calls from WhatsApp (via Twilio) and Telegram.

Design decisions:
  - ANONYMOUS mode: no user account linking. user_id = "bot_anonymous".
    Scan results are NOT saved to any user history (save_to_history=False).
  - Both channels share the same scan pipeline (inline_scan_service).
  - Never raises -- always returns a formatted reply string, even on failure.
  - Twilio: respond with TwiML XML. Telegram: respond with JSON (sendMessage).
  - Signature verification is enforced when secrets are configured.
"""

import hashlib
import hmac
import json
import logging
import urllib.parse
from typing import Any

import httpx

from server.bot_reply_formatter import (
    format_error_reply,
    format_help_message_telegram,
    format_help_message_whatsapp,
    format_telegram_reply,
    format_whatsapp_reply,
)
from server.schemas import InstantSmsScanRequest
from server.settings import (
    FEATURE_TELEGRAM_BOT_ENABLED,
    FEATURE_WHATSAPP_BOT_ENABLED,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_WEBHOOK_SECRET,
    TWILIO_AUTH_TOKEN,
)

logger = logging.getLogger("SMS_WEBHOOK")

BOT_ANONYMOUS_USER_ID = "bot_anonymous"


# ---------------------------------------------------------------------------
# Helper: run an inline scan without saving to history
# ---------------------------------------------------------------------------

def _scan_text_anonymously(text: str, inline_scan_service) -> "InstantScanResult | None":
    """Run an inline SMS scan. Returns None on any failure."""
    try:
        req = InstantSmsScanRequest(text=text, scan_mode="fast")
        result = inline_scan_service.orchestrator.process_sms_scan(
            req.text,
            sender=None,
            scan_mode=req.scan_mode,
        )
        # Mark as not saved to history (anonymous)
        result.saved_to_history = False
        return result
    except Exception as exc:
        logger.error(f"[BOT] Scan failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# Twilio / WhatsApp helpers
# ---------------------------------------------------------------------------

def _verify_twilio_signature(
    auth_token: str,
    x_twilio_signature: str,
    url: str,
    form_params: dict[str, str],
) -> bool:
    """
    Validates the X-Twilio-Signature header per Twilio's signing algorithm.
    https://www.twilio.com/docs/usage/webhooks/webhooks-security
    """
    if not auth_token:
        return True  # No secret configured — skip verification (dev mode)
    s = url
    for key in sorted(form_params.keys()):
        s += key + form_params[key]
    mac = hmac.new(auth_token.encode("utf-8"), s.encode("utf-8"), hashlib.sha1)
    import base64
    expected = base64.b64encode(mac.digest()).decode("ascii")
    return hmac.compare_digest(expected, x_twilio_signature)


def build_twiml_reply(body: str) -> str:
    """Returns a minimal TwiML XML response with the given message body."""
    escaped = body.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<Response>"
        f"<Message>{escaped}</Message>"
        "</Response>"
    )


def handle_whatsapp_webhook(
    form_data: dict[str, str],
    x_twilio_signature: str,
    webhook_url: str,
    inline_scan_service,
) -> str:
    """
    Process an inbound WhatsApp message via Twilio.
    Returns TwiML XML string.
    """
    if not FEATURE_WHATSAPP_BOT_ENABLED:
        logger.debug("[BOT/WA] Feature disabled, ignoring webhook.")
        return build_twiml_reply("SafeMail X WhatsApp bot is currently disabled.")

    if TWILIO_AUTH_TOKEN and not _verify_twilio_signature(
        TWILIO_AUTH_TOKEN, x_twilio_signature, webhook_url, form_data
    ):
        logger.warning("[BOT/WA] Twilio signature verification FAILED. Rejecting.")
        return build_twiml_reply("Request validation failed.")

    body: str = (form_data.get("Body") or "").strip()

    if not body or body.lower() in ("/start", "/help", "help", "hi", "hello"):
        return build_twiml_reply(format_help_message_whatsapp())

    logger.info(f"[BOT/WA] Scanning message ({len(body)} chars) anonymously.")
    result = _scan_text_anonymously(body, inline_scan_service)
    if result is None:
        return build_twiml_reply(format_error_reply())

    reply = format_whatsapp_reply(result)
    return build_twiml_reply(reply)


# ---------------------------------------------------------------------------
# Telegram helpers
# ---------------------------------------------------------------------------

def _verify_telegram_secret(secret_token: str, x_telegram_secret: str) -> bool:
    if not secret_token:
        return True  # No secret configured — skip verification (dev mode)
    return hmac.compare_digest(secret_token, x_telegram_secret)


def _send_telegram_message(chat_id: int, text: str) -> None:
    """Fire-and-forget: send a reply to a Telegram chat."""
    if not TELEGRAM_BOT_TOKEN:
        logger.debug(f"[BOT/TG] No token configured. Would send: {text[:80]}")
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        with httpx.Client(timeout=8) as client:
            client.post(url, json={
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "HTML",
            })
    except Exception as exc:
        logger.warning(f"[BOT/TG] Failed to send reply to chat {chat_id}: {exc}")


def handle_telegram_webhook(
    update: dict[str, Any],
    x_telegram_secret: str,
    inline_scan_service,
) -> None:
    """
    Process an inbound Telegram update (message).
    Sends the reply back to Telegram via REST API (fire-and-forget).
    Returns immediately -- the HTTP response to Telegram is always 200 OK.
    """
    if not FEATURE_TELEGRAM_BOT_ENABLED:
        logger.debug("[BOT/TG] Feature disabled, ignoring update.")
        return

    if TELEGRAM_WEBHOOK_SECRET and not _verify_telegram_secret(
        TELEGRAM_WEBHOOK_SECRET, x_telegram_secret
    ):
        logger.warning("[BOT/TG] Telegram secret verification FAILED. Ignoring.")
        return

    message: dict[str, Any] = update.get("message") or {}
    chat_id: int | None = message.get("chat", {}).get("id")
    text: str = (message.get("text") or "").strip()

    if not chat_id:
        return  # Ignore non-message updates (e.g. edited_message, channel_post)

    if not text or text.lower() in ("/start", "/help"):
        _send_telegram_message(chat_id, format_help_message_telegram())
        return

    logger.info(f"[BOT/TG] Scanning message ({len(text)} chars) from chat {chat_id}.")
    result = _scan_text_anonymously(text, inline_scan_service)
    if result is None:
        _send_telegram_message(chat_id, format_error_reply())
        return

    reply = format_telegram_reply(result)
    _send_telegram_message(chat_id, reply)


# ---------------------------------------------------------------------------
# Telegram: register/update webhook URL with BotFather API
# ---------------------------------------------------------------------------

def register_telegram_webhook(public_url: str) -> bool:
    """
    Call once (e.g. on app startup) to register the Telegram webhook URL.
    public_url should be the full HTTPS URL, e.g. https://safemailx-ai.onrender.com
    Returns True on success, False otherwise.
    """
    if not TELEGRAM_BOT_TOKEN:
        logger.info("[BOT/TG] No TELEGRAM_BOT_TOKEN set -- skipping webhook registration.")
        return False
    webhook_url = f"{public_url.rstrip('/')}/api/webhooks/telegram"
    payload: dict[str, Any] = {"url": webhook_url}
    if TELEGRAM_WEBHOOK_SECRET:
        payload["secret_token"] = TELEGRAM_WEBHOOK_SECRET
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/setWebhook"
        with httpx.Client(timeout=10) as client:
            resp = client.post(url, json=payload)
        data = resp.json()
        if data.get("ok"):
            logger.info(f"[BOT/TG] Webhook registered: {webhook_url}")
            return True
        logger.warning(f"[BOT/TG] Webhook registration failed: {data}")
        return False
    except Exception as exc:
        logger.warning(f"[BOT/TG] Could not register Telegram webhook: {exc}")
        return False
