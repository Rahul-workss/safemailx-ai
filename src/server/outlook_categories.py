"""Manage Microsoft Outlook categories for SafeMail X scanning.

Category colours use Microsoft Graph preset codes (preset0-preset24).
We always READ → merge → PATCH to avoid destroying the user's own categories.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("outlook_categories")

# ── SafeMail X category definitions ──────────────────────────────────────────
# Format: key -> (display_name, preset_color)
# Presets: https://learn.microsoft.com/graph/api/resources/outlookcategory
SAFEMAILX_CATEGORIES: dict[str, tuple[str, str]] = {
    "scan":       ("SafeMail X Scan",       "preset1"),    # orange  — user tags to scan
    "queued":     ("SafeMail X Queued",     "preset12"),   # gray    — claimed, scan in progress
    "safe":       ("SafeMail X Safe",       "preset4"),    # green
    "suspicious": ("SafeMail X Suspicious", "preset3"),    # yellow
    "phishing":   ("SafeMail X Phishing",   "preset0"),    # red
    "failed":     ("SafeMail X Failed",     "preset13"),   # dark gray — backend only, not in UI
}

# Lowercase display names for case-insensitive matching
_SAFEMAILX_DISPLAY_NAMES_LOWER = {
    name.lower() for name, _ in SAFEMAILX_CATEGORIES.values()
}


def ensure_safemailx_categories(client: Any) -> dict[str, str]:
    """Ensure all SafeMail X categories exist in the user's Outlook.

    Returns a dict mapping our key → Outlook category display_name.
    Tolerates 409 (already exists) gracefully.
    """
    try:
        existing_resp = client.get("/me/outlook/masterCategories")
        existing = {
            cat["displayName"].lower(): cat["displayName"]
            for cat in existing_resp.get("value", [])
        }
    except Exception as exc:
        logger.warning("Could not list Outlook master categories: %s", exc)
        existing = {}

    result: dict[str, str] = {}
    for key, (display_name, preset) in SAFEMAILX_CATEGORIES.items():
        if display_name.lower() in existing:
            result[key] = display_name
            continue
        try:
            client.post(
                "/me/outlook/masterCategories",
                {"displayName": display_name, "color": preset},
            )
            result[key] = display_name
        except Exception as exc:
            # 409 = already exists (race condition) — treat as success
            from server.outlook_graph import GraphError
            if isinstance(exc, GraphError) and exc.status == 409:
                result[key] = display_name
            else:
                logger.warning("Could not create Outlook category %r: %s", display_name, exc)
                result[key] = display_name  # proceed anyway

    return result


def merge_categories(
    existing: list[str],
    add_key: str | None,
) -> list[str]:
    """Return a new category list that:
    - Removes all SafeMail X categories (case-insensitive)
    - Keeps all user-defined categories
    - Appends the new SafeMail X verdict category (if add_key is set)
    """
    cleaned = [
        cat for cat in existing
        if cat.lower() not in _SAFEMAILX_DISPLAY_NAMES_LOWER
    ]
    if add_key and add_key in SAFEMAILX_CATEGORIES:
        cleaned.append(SAFEMAILX_CATEGORIES[add_key][0])
    return cleaned


def set_message_category(
    client: Any,
    message_id: str,
    key: str,
) -> None:
    """Apply a SafeMail X category to an Outlook message.

    Strategy: READ existing categories → merge (drop SafeMail X, add new) → PATCH.
    Never replaces all categories wholesale to protect user's own categories.
    """
    try:
        msg = client.get(f"/me/messages/{message_id}?$select=categories")
        current = msg.get("categories") or []
    except Exception as exc:
        logger.warning("Could not read categories for message %s: %s", message_id, exc)
        current = []

    new_categories = merge_categories(current, key)

    try:
        client.patch(
            f"/me/messages/{message_id}",
            {"categories": new_categories},
        )
        logger.debug(
            "Set Outlook category %r on message %s (was: %r → now: %r)",
            key, message_id, current, new_categories,
        )
    except Exception as exc:
        logger.warning(
            "Could not set Outlook category %r on message %s: %s",
            key, message_id, exc,
        )
        raise
