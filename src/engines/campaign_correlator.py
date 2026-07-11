# ============================================================
# SafeMail X — Campaign Correlation Engine
# Feature 4: Pattern-match across scan history to detect
#             coordinated phishing campaigns
# Controlled by: FEATURE_CAMPAIGN_CORRELATION_ENABLED
# ============================================================
#
# HOW IT WORKS:
#   For every scan, we extract a "fingerprint" — a stable,
#   compact representation of the structural attack patterns
#   present (domain, tactic list, intent).
#   We then check recent scans (within a configurable lookback
#   window) for similar fingerprints. If N+ matches are found,
#   we flag the email as part of a campaign.
#
# PRIVACY:
#   Only structural signal hashes are stored, never raw body
#   text or PII. The fingerprint is a SHA-256 of the sorted
#   (domain + tactic + intent) tuple — no content is recoverable.
#
# SCOPE:
#   Single-user only. No cross-user fingerprint sharing in
#   this phase. All lookups are scoped to user_id.
# ============================================================

import hashlib
import json
import logging
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger("CAMPAIGN_CORRELATOR")

# Default thresholds (overridable via config)
DEFAULT_CAMPAIGN_WINDOW_HOURS = 48
DEFAULT_CAMPAIGN_MIN_MATCHES = 3


def compute_campaign_fingerprint(
    sender_domain: str,
    tactics: list[str],
    intent: str,
) -> str:
    """
    Compute a stable campaign fingerprint from structural signals.

    The fingerprint is a short (12-char) hex prefix of SHA-256 over
    the canonical {domain}|{sorted_tactics}|{intent} representation.
    Short prefix chosen deliberately: similar campaigns from the same
    threat actor share the same fingerprint even if the domain
    subpath varies slightly.

    Privacy: no body text or PII enters this hash.
    """
    canonical = (
        (sender_domain or "").lower().strip()
        + "|"
        + ",".join(sorted(t.lower().strip() for t in tactics if t))
        + "|"
        + (intent or "unknown").lower().strip()
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]


def store_fingerprint(
    conn,          # active DB connection
    scan_id: str,
    user_id: str,
    fingerprint: str,
    sender_domain: str,
    intent: str,
) -> None:
    """
    Persist a scan fingerprint to the scan_fingerprints table.
    Called immediately after a scan completes, inside the same transaction.
    """
    try:
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT OR IGNORE INTO scan_fingerprints
                (scan_id, user_id, fingerprint, sender_domain, intent, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (scan_id, user_id, fingerprint, sender_domain, intent, now),
        )
    except Exception as exc:
        logger.warning("[CAMPAIGN] store_fingerprint error: %s", exc)


def query_matching_fingerprints(
    conn,
    user_id: str,
    fingerprint: str,
    exclude_scan_id: str,
    window_hours: int = DEFAULT_CAMPAIGN_WINDOW_HOURS,
) -> list[dict]:
    """
    Query the DB for recent scans (within `window_hours`) by the same user
    with the same fingerprint, excluding the current scan.

    Returns a list of matching scan dicts. Empty list = no campaign match.
    """
    try:
        since = (
            datetime.now(timezone.utc) - timedelta(hours=window_hours)
        ).isoformat()
        cursor = conn.execute(
            """
            SELECT scan_id, sender_domain, intent, created_at
            FROM scan_fingerprints
            WHERE user_id = ?
              AND fingerprint = ?
              AND scan_id != ?
              AND created_at >= ?
            ORDER BY created_at DESC
            """,
            (user_id, fingerprint, exclude_scan_id, since),
        )
        rows = cursor.fetchall()
        return [
            {
                "scan_id": r[0],
                "sender_domain": r[1],
                "intent": r[2],
                "created_at": r[3],
            }
            for r in rows
        ]
    except Exception as exc:
        logger.warning("[CAMPAIGN] query_matching_fingerprints error: %s", exc)
        return []


def analyze_campaign_correlation(
    db_conn,
    scan_id: str,
    user_id: str,
    sender_domain: str,
    tactics: list[str],
    intent: str,
    window_hours: int = DEFAULT_CAMPAIGN_WINDOW_HOURS,
    min_matches: int = DEFAULT_CAMPAIGN_MIN_MATCHES,
) -> dict:
    """
    Full campaign correlation analysis for a completed scan.

    Steps:
      1. Compute fingerprint for this scan
      2. Store it
      3. Query for recent matching fingerprints
      4. Return a structured finding dict

    Return schema:
      campaign_detected    bool
      fingerprint          str    (12-char hex prefix)
      matching_scan_count  int
      matching_scan_ids    list[str]
      campaign_confidence  float  (0.0–1.0)
      window_hours         int
    """
    empty = {
        "campaign_detected": False,
        "fingerprint": "",
        "matching_scan_count": 0,
        "matching_scan_ids": [],
        "campaign_confidence": 0.0,
        "window_hours": window_hours,
    }

    try:
        fp = compute_campaign_fingerprint(sender_domain, tactics, intent)

        # Store first (so this scan contributes to future correlation)
        store_fingerprint(db_conn, scan_id, user_id, fp, sender_domain, intent)

        matches = query_matching_fingerprints(
            db_conn, user_id, fp, scan_id, window_hours
        )
        match_count = len(matches)
        detected = match_count >= min_matches

        # Confidence: scales linearly from min_matches to 3× min_matches
        if detected:
            confidence = min(1.0, 0.5 + 0.1 * (match_count - min_matches))
        else:
            confidence = 0.0

        if detected:
            logger.warning(
                "[CAMPAIGN] Campaign detected for scan %s — %d matching scans found "
                "(fingerprint=%s, intent=%s)",
                scan_id, match_count, fp, intent,
            )

        return {
            "campaign_detected": detected,
            "fingerprint": fp,
            "matching_scan_count": match_count,
            "matching_scan_ids": [m["scan_id"] for m in matches],
            "campaign_confidence": round(confidence, 2),
            "window_hours": window_hours,
        }
    except Exception as exc:
        logger.warning("[CAMPAIGN] analyze_campaign_correlation error: %s", exc)
        return empty
