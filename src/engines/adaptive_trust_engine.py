# ============================================================
# SafeMail X — Adaptive Trust Baseline Engine
# Feature 5: Per-sender behavioral trust baseline
# Controlled by: FEATURE_ADAPTIVE_TRUST_ENABLED
# ============================================================
#
# HOW IT WORKS:
#   After a scan completes with verdict "legitimate", we record
#   the sender_domain + a structural signature of the communication.
#   On future scans, if the sender domain matches an established
#   baseline, the final_score is softened slightly (trust bonus).
#   A scan that fires phishing indicators always IGNORES the baseline
#   (the baseline can only soften, never excuse a phishing verdict).
#
# PRIVACY:
#   - Only sender_domain and scan_count are stored — not email body,
#     subject, or raw sender address.
#   - Data is scoped to a single user_id.
#   - The user can delete their entire baseline via a dedicated API
#     endpoint (DELETE /api/settings/adaptive-trust/data).
#
# SCOPE:
#   Single-user only. No cross-user baseline sharing in this phase.
# ============================================================

import logging
import sqlite3
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("ADAPTIVE_TRUST")

# Trust bonus applied when a known-good sender domain is seen again.
# Expressed as a multiplier on final_score — keeps score above 0.
# Value of 0.85 means "reduce score by 15%".
# Never applied when final_score >= PHISHING_FLOOR.
TRUST_MULTIPLIER = 0.85
PHISHING_FLOOR   = 0.70   # Do not apply trust bonus above this — could mask phishing


def get_sender_baseline_db_path() -> str:
    """Return the path to the sender_baseline SQLite DB."""
    import os
    return os.path.join(os.path.dirname(__file__), "sender_baseline.db")


def init_baseline_db(db_path: Optional[str] = None) -> None:
    """Create the sender_baseline table if it does not exist."""
    path = db_path or get_sender_baseline_db_path()
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sender_baseline (
            user_id          TEXT NOT NULL,
            sender_domain    TEXT NOT NULL,
            trusted_scan_count INTEGER NOT NULL DEFAULT 1,
            last_seen_at     TEXT NOT NULL,
            PRIMARY KEY (user_id, sender_domain)
        )
        """
    )
    conn.commit()
    conn.close()


def record_trusted_sender(
    user_id: str,
    sender_domain: str,
    db_path: Optional[str] = None,
) -> None:
    """
    Record or update a trusted sender domain for a user after a
    scan returns verdict "legitimate". Upserts the record.
    """
    if not sender_domain or not sender_domain.strip():
        return
    path = db_path or get_sender_baseline_db_path()
    now = datetime.now(timezone.utc).isoformat()
    try:
        conn = sqlite3.connect(path)
        conn.execute(
            """
            INSERT INTO sender_baseline (user_id, sender_domain, trusted_scan_count, last_seen_at)
            VALUES (?, ?, 1, ?)
            ON CONFLICT(user_id, sender_domain) DO UPDATE SET
                trusted_scan_count = trusted_scan_count + 1,
                last_seen_at = excluded.last_seen_at
            """,
            (user_id, sender_domain.lower().strip(), now),
        )
        conn.commit()
        conn.close()
    except Exception as exc:
        logger.debug("[ADAPTIVE_TRUST] record_trusted_sender error: %s", exc)


def get_trust_entry(
    user_id: str,
    sender_domain: str,
    db_path: Optional[str] = None,
) -> Optional[dict]:
    """
    Return the baseline entry for a sender domain, or None if not found.

    Return schema:
      sender_domain       str
      trusted_scan_count  int
      last_seen_at        str (ISO8601)
    """
    if not sender_domain:
        return None
    path = db_path or get_sender_baseline_db_path()
    try:
        conn = sqlite3.connect(path)
        row = conn.execute(
            "SELECT sender_domain, trusted_scan_count, last_seen_at "
            "FROM sender_baseline WHERE user_id = ? AND sender_domain = ?",
            (user_id, sender_domain.lower().strip()),
        ).fetchone()
        conn.close()
        if row:
            return {
                "sender_domain": row[0],
                "trusted_scan_count": row[1],
                "last_seen_at": row[2],
            }
    except Exception as exc:
        logger.debug("[ADAPTIVE_TRUST] get_trust_entry error: %s", exc)
    return None


def apply_adaptive_trust(
    final_score: float,
    user_id: str,
    sender_domain: str,
    verdict: str,
    db_path: Optional[str] = None,
    min_trusted_scans: int = 3,
) -> tuple[float, bool, Optional[dict]]:
    """
    Apply adaptive trust softening to final_score if conditions are met.

    Rules:
      1. Feature must be enabled (caller's responsibility to gate).
      2. score must be < PHISHING_FLOOR — trust can NOT excuse phishing.
      3. sender_domain must have >= min_trusted_scans trusted history.
      4. verdict must NOT already be "phishing" (belt-and-suspenders).

    Returns:
      (adjusted_score, trust_applied: bool, trust_entry: Optional[dict])
    """
    if not sender_domain or verdict == "phishing":
        return final_score, False, None

    try:
        entry = get_trust_entry(user_id, sender_domain, db_path)
        if entry and entry["trusted_scan_count"] >= min_trusted_scans:
            if final_score < PHISHING_FLOOR:
                adjusted = round(final_score * TRUST_MULTIPLIER, 3)
                logger.info(
                    "[ADAPTIVE_TRUST] Trust bonus applied for %s (user=%s, "
                    "trusted_count=%d): %.3f → %.3f",
                    sender_domain, user_id, entry["trusted_scan_count"],
                    final_score, adjusted,
                )
                return adjusted, True, entry
    except Exception as exc:
        logger.warning("[ADAPTIVE_TRUST] apply_adaptive_trust error: %s", exc)

    return final_score, False, None


def clear_all_baseline_data(user_id: str, db_path: Optional[str] = None) -> int:
    """
    Delete all baseline data for a user. Called from the
    DELETE /api/settings/adaptive-trust/data endpoint.

    Returns the number of rows deleted.
    """
    path = db_path or get_sender_baseline_db_path()
    try:
        conn = sqlite3.connect(path)
        cursor = conn.execute(
            "DELETE FROM sender_baseline WHERE user_id = ?", (user_id,)
        )
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        logger.info("[ADAPTIVE_TRUST] Cleared %d baseline record(s) for user %s", deleted, user_id)
        return deleted
    except Exception as exc:
        logger.warning("[ADAPTIVE_TRUST] clear_all_baseline_data error: %s", exc)
        return 0


def list_baseline_summary(user_id: str, db_path: Optional[str] = None) -> list[dict]:
    """
    Return a list of all trusted domains for a user (for the Privacy screen).
    Only returns domain and count — no body text or PII.
    """
    path = db_path or get_sender_baseline_db_path()
    try:
        conn = sqlite3.connect(path)
        rows = conn.execute(
            "SELECT sender_domain, trusted_scan_count, last_seen_at "
            "FROM sender_baseline WHERE user_id = ? ORDER BY trusted_scan_count DESC",
            (user_id,),
        ).fetchall()
        conn.close()
        return [
            {"sender_domain": r[0], "trusted_scan_count": r[1], "last_seen_at": r[2]}
            for r in rows
        ]
    except Exception as exc:
        logger.warning("[ADAPTIVE_TRUST] list_baseline_summary error: %s", exc)
        return []


# Initialize the DB at module import time (same pattern as offline_sync.py)
try:
    init_baseline_db()
except Exception:
    pass
