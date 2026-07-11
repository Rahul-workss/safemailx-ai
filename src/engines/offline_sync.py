# ============================================================
# SafeMail X — Offline Hash-Prefix Safe-Browsing
# Feature 3: Privacy-preserving malicious URL check
# Controlled by: FEATURE_OFFLINE_SAFEBROWSING_ENABLED
# ============================================================
#
# PRIVACY PROPERTY (non-negotiable — do not remove this comment):
#   Full URLs and full hashes are NEVER persisted or transmitted.
#   Only 4-byte (8 hex-char) SHA-256 prefixes are stored locally.
#   Lookups are 100% offline at query time — zero network calls.
#   This is k-anonymity: a prefix match is a CANDIDATE, not a
#   certainty. Treat it as one signal among several, never as a
#   sole verdict.
#
# Feed compatibility:
#   Any newline-delimited list of plain URLs can be used as a feed.
#   Recommended options (document in .env.example / README):
#     - OpenPhish:  https://openphish.com/feed.txt
#     - PhishTank:  https://data.phishtank.com/data/online-valid.csv
#       (PhishTank requires free account API key — has reliability issues)
#   Default OFFLINE_HASH_FEED_URL is EMPTY. Set it in .env to enable sync.
# ============================================================

import hashlib
import logging
import os
import sqlite3
import time
from typing import Optional

logger = logging.getLogger("OFFLINE_SYNC")

# ── DB path (inherited from existing skeleton) ──────────────────────────────
DB_PATH = os.path.join(os.path.dirname(__file__), "hash_prefixes.db")

# k-anonymity prefix length: 4 bytes = 8 hex chars
# Matches Google Safe Browsing v4 convention.
PREFIX_LENGTH = 4   # bytes → PREFIX_LENGTH * 2 hex chars


# ── Schema init (existing function preserved, now called from module level) ──

def init_db() -> None:
    """Initialize the local SQLite database for hash prefixes."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS prefixes (prefix_hex TEXT PRIMARY KEY)"
    )
    conn.commit()
    conn.close()


# Initialize at import time (preserves existing behavior)
init_db()


# ── Core privacy-preserving functions ───────────────────────────────────────

def url_to_hash_prefix(url: str) -> str:
    """
    Compute the k-anonymity hash prefix for a URL.

    The full URL (lowercased, stripped) is SHA-256 hashed and only
    the first PREFIX_LENGTH bytes (8 hex chars) are returned.
    The full hash is NEVER stored or returned — only this prefix.
    """
    normalized = url.strip().lower()
    full_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return full_hash[: PREFIX_LENGTH * 2]


def sync_prefixes_from_feed(feed_url: str) -> int:
    """
    Download a newline-delimited list of known-malicious URLs from
    `feed_url`, hash each one locally, and store ONLY the 4-byte prefix.

    Returns the number of NEW prefixes inserted (existing are skipped via
    INSERT OR IGNORE). Returns 0 if feed_url is empty/unset.

    Privacy guarantee: full URLs and full hashes are NEVER persisted.
    Only prefixes are stored — lookups at query time require zero network.
    """
    if not feed_url or not feed_url.strip():
        logger.info("[OFFLINE_SYNC] OFFLINE_HASH_FEED_URL is not set — sync skipped.")
        return 0

    import requests as _requests  # lazy import to avoid dep if feature disabled

    logger.info("[OFFLINE_SYNC] Starting prefix sync from: %s", feed_url)
    try:
        resp = _requests.get(feed_url.strip(), timeout=60)
        resp.raise_for_status()
    except Exception as exc:
        logger.warning("[OFFLINE_SYNC] Feed fetch failed: %s", exc)
        return 0

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    new_count = 0

    for line in resp.text.splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        # PhishTank CSV has extra columns — take first field only
        url_candidate = raw.split(",")[0].strip().strip('"')
        if not url_candidate:
            continue
        # Ensure it looks like a URL (very light guard, not strict validation)
        if not (url_candidate.startswith("http://") or url_candidate.startswith("https://")):
            url_candidate = "http://" + url_candidate
        prefix = url_to_hash_prefix(url_candidate)
        cursor.execute(
            "INSERT OR IGNORE INTO prefixes (prefix_hex) VALUES (?)", (prefix,)
        )
        if cursor.rowcount:
            new_count += 1

    conn.commit()
    conn.close()
    logger.info("[OFFLINE_SYNC] Sync complete — %d new prefix(es) inserted.", new_count)
    return new_count


def check_url_against_offline_db(url: str) -> bool:
    """
    Check whether a URL's hash prefix matches any known-bad entry in the
    local offline database.

    Returns True if the prefix matches (CANDIDATE — not a certainty).
    A positive here means one more signal, not a definitive verdict.

    This function makes ZERO network calls — it is entirely local SQLite.
    """
    if not url or not url.strip():
        return False
    try:
        prefix = url_to_hash_prefix(url)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM prefixes WHERE prefix_hex = ?", (prefix,))
        result = cursor.fetchone()
        conn.close()
        return result is not None
    except Exception as exc:
        logger.debug("[OFFLINE_SYNC] check_url_against_offline_db error: %s", exc)
        return False


# ── Legacy function (kept for backward compat with existing url_analyzer callers) ──

def sync_prefixes() -> None:
    """
    Legacy stub — retained for backward compatibility.
    In production use sync_prefixes_from_feed(feed_url) instead.
    """
    logger.info(
        "[OFFLINE_SYNC] sync_prefixes() is the legacy stub. "
        "Call sync_prefixes_from_feed(feed_url) for real sync."
    )


def check_url_prefix(url: str) -> bool:
    """
    Legacy function — routes to check_url_against_offline_db().
    Kept so existing url_analyzer.py callers (check_offline_prefix → check_url_prefix)
    are not broken. Behavior now uses the full URL hash (not domain-only as before),
    which is strictly more correct and more private.
    """
    return check_url_against_offline_db(url)


# ── Periodic sync job (called from worker.py) ───────────────────────────────

def run_periodic_sync(feed_url: str, interval_hours: float = 6.0) -> None:
    """
    Blocking loop that calls sync_prefixes_from_feed() every `interval_hours`.
    Intended to run in a daemon thread via worker.py.

    If feed_url is empty, logs once and exits immediately (safe no-op).
    """
    if not feed_url or not feed_url.strip():
        logger.info(
            "[OFFLINE_SYNC] Periodic sync thread exiting — OFFLINE_HASH_FEED_URL is not set. "
            "Set it in .env to enable automatic threat-feed synchronization. "
            "Example: OFFLINE_HASH_FEED_URL=https://openphish.com/feed.txt"
        )
        return

    interval_secs = interval_hours * 3600
    logger.info(
        "[OFFLINE_SYNC] Periodic sync started. Feed: %s | Interval: %.1fh",
        feed_url, interval_hours
    )

    while True:
        try:
            sync_prefixes_from_feed(feed_url)
        except Exception as exc:
            logger.warning("[OFFLINE_SYNC] Sync iteration failed: %s", exc)
        time.sleep(interval_secs)
