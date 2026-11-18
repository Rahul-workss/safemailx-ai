"""Microsoft Outlook / Office 365 OAuth 2.0 helpers.

Uses the Microsoft Identity Platform (v2.0) with httpx (already a dependency).
No msal — pure httpx + standard library only.
"""
from __future__ import annotations

import base64
import json
import logging
import threading
import time
from typing import Any
from urllib.parse import urlencode

import httpx

from server.settings import (
    GMAIL_TOKEN_ENCRYPTION_KEY,
    OUTLOOK_CLIENT_ID,
    OUTLOOK_CLIENT_SECRET,
    OUTLOOK_REDIRECT_URI,
    OUTLOOK_TENANT_ID,
)

logger = logging.getLogger("outlook_oauth")

OUTLOOK_SCOPES = [
    "offline_access",
    "User.Read",
    "Mail.ReadWrite",
    "MailboxSettings.ReadWrite",
]
# Lowercase for case-insensitive comparison
REQUIRED_SCOPES = {"mail.readwrite", "mailboxsettings.readwrite"}

_AUTH_BASE = f"https://login.microsoftonline.com/{OUTLOOK_TENANT_ID}/oauth2/v2.0"

# Per-user locks to prevent concurrent token refresh races
_refresh_locks: dict[str, threading.Lock] = {}
_refresh_locks_mutex = threading.Lock()


def _get_user_lock(user_id: str) -> threading.Lock:
    with _refresh_locks_mutex:
        if user_id not in _refresh_locks:
            _refresh_locks[user_id] = threading.Lock()
        return _refresh_locks[user_id]


# ── Fernet encrypt/decrypt (reuses GMAIL_TOKEN_ENCRYPTION_KEY) ───────────────

def _cipher():
    """Return a Fernet cipher or None if no key is configured."""
    if not GMAIL_TOKEN_ENCRYPTION_KEY:
        return None
    try:
        from cryptography.fernet import Fernet
        return Fernet(GMAIL_TOKEN_ENCRYPTION_KEY.encode("utf-8"))
    except Exception:
        return None


def encrypt_token_blob(token_dict: dict) -> str:
    """Serialize and optionally encrypt a token dict → base64 string."""
    raw = json.dumps(token_dict).encode("utf-8")
    cipher = _cipher()
    if cipher:
        raw = cipher.encrypt(raw)
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decrypt_token_blob(blob: str) -> dict:
    """Reverse of encrypt_token_blob."""
    raw = base64.urlsafe_b64decode(blob.encode("ascii"))
    cipher = _cipher()
    if cipher:
        raw = cipher.decrypt(raw)
    return json.loads(raw.decode("utf-8"))


# ── OAuth URL builder ─────────────────────────────────────────────────────────

def build_outlook_authorization_url(state: str, redirect_uri: str | None = None) -> str:
    """Return the Microsoft login URL to open in the browser."""
    params = {
        "client_id": OUTLOOK_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri or OUTLOOK_REDIRECT_URI,
        "response_mode": "query",
        "scope": " ".join(OUTLOOK_SCOPES),
        "state": state,
        "prompt": "select_account",
    }
    return f"{_AUTH_BASE}/authorize?{urlencode(params)}"


# ── Token exchange ────────────────────────────────────────────────────────────

def exchange_code_for_outlook_token(
    code: str,
    redirect_uri: str | None = None,
) -> dict[str, Any]:
    """Exchange an authorisation code for a token dict."""
    resp = httpx.post(
        f"{_AUTH_BASE}/token",
        data={
            "client_id": OUTLOOK_CLIENT_ID,
            "client_secret": OUTLOOK_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri or OUTLOOK_REDIRECT_URI,
            "scope": " ".join(OUTLOOK_SCOPES),
        },
        timeout=20,
    )
    if resp.status_code != 200:
        logger.warning("Outlook token exchange failed: %s %s", resp.status_code, resp.text[:300])
        raise RuntimeError(f"Outlook token exchange failed ({resp.status_code})")

    data = resp.json()
    granted = set(data.get("scope", "").lower().split())
    missing = REQUIRED_SCOPES - granted
    if missing:
        raise RuntimeError(
            f"Outlook token missing required scopes: {missing}. "
            "Ensure the Azure app registration has Mail.ReadWrite and MailboxSettings.ReadWrite."
        )

    token = {
        "access_token": data["access_token"],
        "refresh_token": data.get("refresh_token", ""),
        "expires_at": time.time() + int(data.get("expires_in", 3600)) - 60,
        "scope": data.get("scope", ""),
    }
    return token


# ── Token refresh ─────────────────────────────────────────────────────────────

class OutlookReauthRequired(Exception):
    """Raised when the refresh token is expired/revoked and the user must re-authorise."""


def _refresh_token(repo: Any, user_id: str, token: dict) -> dict:
    """POST to /token with grant_type=refresh_token. Updates DB on success."""
    resp = httpx.post(
        f"{_AUTH_BASE}/token",
        data={
            "client_id": OUTLOOK_CLIENT_ID,
            "client_secret": OUTLOOK_CLIENT_SECRET,
            "grant_type": "refresh_token",
            "refresh_token": token["refresh_token"],
            "scope": " ".join(OUTLOOK_SCOPES),
        },
        timeout=20,
    )

    if resp.status_code != 200:
        err = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        err_code = err.get("error", "")
        logger.warning("Outlook token refresh failed for %s: %s %s", user_id, resp.status_code, err_code)

        # Reauth-requiring errors
        if err_code in {
            "invalid_grant",
            "interaction_required",
            "consent_required",
            "access_denied",
        }:
            repo.set_outlook_status(user_id, "reauth_required")
            raise OutlookReauthRequired(
                f"Outlook token expired for user {user_id}. User must reconnect Outlook."
            )

        if err_code == "invalid_client":
            logger.error(
                "[OUTLOOK] invalid_client error — check OUTLOOK_CLIENT_ID and OUTLOOK_CLIENT_SECRET "
                "in Render env vars. User: %s",
                user_id,
            )

        raise RuntimeError(f"Outlook token refresh failed ({resp.status_code}): {err_code}")

    data = resp.json()
    new_token = {
        "access_token": data["access_token"],
        # Microsoft rotates refresh tokens — persist the new one
        "refresh_token": data.get("refresh_token") or token["refresh_token"],
        "expires_at": time.time() + int(data.get("expires_in", 3600)) - 60,
        "scope": data.get("scope", token.get("scope", "")),
    }
    # Persist refreshed token immediately
    repo.update_outlook_token_blob(user_id, encrypt_token_blob(new_token))
    return new_token


def get_access_token(repo: Any, user_id: str) -> str:
    """Return a valid access token for *user_id*, refreshing if needed.

    Uses a per-user lock to prevent concurrent refreshes.
    """
    lock = _get_user_lock(user_id)
    with lock:
        conn = repo.get_outlook_connection(user_id)
        if not conn:
            raise RuntimeError(f"Outlook is not connected for user {user_id}")
        if conn.get("status") == "reauth_required":
            raise OutlookReauthRequired(f"Outlook needs reauth for user {user_id}")

        token = decrypt_token_blob(conn["token_blob"])
        if time.time() < token.get("expires_at", 0):
            return token["access_token"]

        # Token expired — refresh
        token = _refresh_token(repo, user_id, token)
        return token["access_token"]


# ── Account email lookup ──────────────────────────────────────────────────────

def fetch_account_email(access_token: str) -> str:
    """Call /me to get the user's primary email address."""
    resp = httpx.get(
        "https://graph.microsoft.com/v1.0/me?$select=mail,userPrincipalName",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    )
    if resp.status_code == 200:
        data = resp.json()
        return data.get("mail") or data.get("userPrincipalName") or ""
    logger.warning("fetch_account_email failed: %s", resp.status_code)
    return ""
