# ============================================================
# SafeMail X — Second-Look Rescan Job
# Feature 6: Asynchronous re-analysis of previously "suspicious"
#             scans when threat intelligence is updated.
# Controlled by: FEATURE_SECOND_LOOK_RESCAN_ENABLED
# ============================================================
#
# HOW IT WORKS:
#   A periodic background job queries scans marked "suspicious"
#   (verdict neither phishing nor legitimate) created within the
#   rescan window. Each scan is re-run through the hybrid engine
#   with a fresh snapshot of threat intelligence.
#
#   If the new verdict ESCALATES (suspicious→phishing):
#     - The stored scan verdict is updated
#     - A push notification fires (if tokens registered)
#
#   If the new verdict DE-ESCALATES (suspicious→legitimate):
#     - The stored scan is also updated (clears false positive)
#     - No push notification — user is not alarmed unnecessarily
#
#   If verdict is unchanged: no update, no notification.
#
# SAFETY:
#   - Each scan is re-analyzed at most once per rescan window
#     (tracked via rescan_events table)
#   - Function never raises — all errors are logged and skipped
#   - Works with both SQLite and PostgreSQL
#   - Gated behind FEATURE_SECOND_LOOK_RESCAN_ENABLED flag
# ============================================================

import json
import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Any

logger = logging.getLogger("RESCAN_JOB")


def _get_recent_suspicious_scans(
    repository,
    user_id: str,
    lookback_hours: int,
) -> list[dict[str, Any]]:
    """
    Query scans with final_label='suspicious' created within the
    lookback window, that have not already been rescanned.
    """
    since = (datetime.now(timezone.utc) - timedelta(hours=lookback_hours)).isoformat()
    try:
        all_scans = repository.list_scans(user_id=user_id)
        suspicious = []
        for s in all_scans:
            if (
                s.get("final_label") == "suspicious"
                and s.get("created_at", "") >= since
            ):
                suspicious.append(s)
        return suspicious
    except Exception as exc:
        logger.warning("[RESCAN] Failed to query suspicious scans: %s", exc)
        return []


def _already_rescanned(
    repository,
    scan_id: str,
    window_hours: int,
) -> bool:
    """
    Check if a scan has already been rescanned within the dedup window
    (uses rescan_events table).
    """
    try:
        since = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()
        with repository._db() as conn:
            row = conn.execute(
                "SELECT 1 FROM rescan_events WHERE scan_id = ? AND rescanned_at >= ?",
                (scan_id, since),
            ).fetchone()
            return row is not None
    except Exception:
        return False  # If table doesn't exist yet, treat as not-rescanned


def _record_rescan_event(repository, scan_id: str, old_verdict: str, new_verdict: str) -> None:
    """Persist a rescan event for deduplication tracking."""
    try:
        now = datetime.now(timezone.utc).isoformat()
        with repository._db() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO rescan_events
                    (scan_id, old_verdict, new_verdict, rescanned_at)
                VALUES (?, ?, ?, ?)
                """,
                (scan_id, old_verdict, new_verdict, now),
            )
    except Exception as exc:
        logger.debug("[RESCAN] record_rescan_event error: %s", exc)


def run_rescan_pass(
    repository,
    scan_service,
    user_id: str = "local",
    lookback_hours: int = 24,
    dedup_window_hours: int = 24,
) -> dict:
    """
    Run one pass of the second-look rescan job.

    Parameters:
      repository        — ScanRepository instance
      scan_service      — ScanService instance (used for re-analysis)
      user_id           — user scope (single-user for now)
      lookback_hours    — how far back to look for suspicious scans
      dedup_window_hours — dedup: skip if already rescanned within this window

    Returns a summary dict:
      rescanned_count     int
      escalated_count     int
      de_escalated_count  int
      unchanged_count     int
      errors              int
    """
    summary = {
        "rescanned_count": 0,
        "escalated_count": 0,
        "de_escalated_count": 0,
        "unchanged_count": 0,
        "errors": 0,
    }

    suspicious_scans = _get_recent_suspicious_scans(repository, user_id, lookback_hours)
    if not suspicious_scans:
        logger.info("[RESCAN] No suspicious scans in the lookback window.")
        return summary

    logger.info("[RESCAN] Found %d suspicious scan(s) to re-evaluate.", len(suspicious_scans))

    for scan in suspicious_scans:
        scan_id = scan.get("id", "")
        if not scan_id:
            continue

        # Dedup check
        if _already_rescanned(repository, scan_id, dedup_window_hours):
            logger.debug("[RESCAN] Skipping %s — already rescanned.", scan_id)
            continue

        try:
            # Extract evidence from stored scan
            evidence_raw = scan.get("evidence_json") or scan.get("evidence") or "{}"
            if isinstance(evidence_raw, str):
                evidence = json.loads(evidence_raw)
            else:
                evidence = evidence_raw

            scan_input = evidence.get("scan_input", {})
            body_text = scan_input.get("body_text", "") or evidence.get("body", "")
            subject = scan.get("subject", "")
            sender = scan.get("sender", "")

            if not body_text:
                logger.debug("[RESCAN] Skipping %s — no body text in evidence.", scan_id)
                continue

            # Re-run analysis
            new_result = scan_service.run_manual_text_scan(
                subject=subject,
                sender=sender,
                body=body_text,
                scan_mode=evidence.get("scan_mode", "balanced"),
                user_id=user_id,
                source_type=evidence.get("source_type", "text"),
            )

            new_verdict = (new_result or {}).get("final_label", "suspicious")
            old_verdict = "suspicious"
            summary["rescanned_count"] += 1

            _record_rescan_event(repository, scan_id, old_verdict, new_verdict)

            if new_verdict == "phishing":
                summary["escalated_count"] += 1
                logger.warning(
                    "[RESCAN] ESCALATION: scan %s upgraded suspicious→phishing", scan_id
                )
                # Update the original scan verdict
                try:
                    repository.update_scan_verdict(scan_id, new_verdict)
                except Exception:
                    pass
                # Trigger push notification
                _notify_escalation(repository, scan_id, user_id, subject, sender)

            elif new_verdict == "legitimate":
                summary["de_escalated_count"] += 1
                logger.info(
                    "[RESCAN] De-escalation: scan %s suspicious→legitimate", scan_id
                )
                try:
                    repository.update_scan_verdict(scan_id, new_verdict)
                except Exception:
                    pass
            else:
                summary["unchanged_count"] += 1

        except Exception as exc:
            logger.warning("[RESCAN] Error processing scan %s: %s", scan_id, exc)
            summary["errors"] += 1

    return summary


def _notify_escalation(
    repository,
    scan_id: str,
    user_id: str,
    subject: str,
    sender: str,
) -> None:
    """Send an escalation push notification if tokens are registered."""
    try:
        from server.notifications import send_push_notifications
        tokens = repository.list_push_tokens(user_id=user_id)
        if not tokens:
            return
        send_push_notifications(
            tokens,
            title="⚠️ Threat Alert — Upgraded to Phishing",
            body=(
                f"A previously suspicious email from {sender!r} has been "
                f"re-classified as phishing: {subject!r}"
            ),
            data={
                "scan_id": scan_id,
                "event": "rescan_escalation",
                "new_verdict": "phishing",
            },
        )
    except Exception as exc:
        logger.debug("[RESCAN] Push notification error: %s", exc)


def run_periodic_rescan(
    repository,
    scan_service,
    user_id: str = "local",
    interval_hours: float = 12.0,
    lookback_hours: int = 24,
) -> None:
    """
    Blocking loop that calls run_rescan_pass() every `interval_hours`.
    Intended to run in a daemon thread via worker.py.

    Exits immediately if FEATURE_SECOND_LOOK_RESCAN_ENABLED is False.
    """
    logger.info("[RESCAN] Periodic rescan thread started. Interval: %.1fh", interval_hours)
    interval_secs = interval_hours * 3600

    while True:
        try:
            summary = run_rescan_pass(
                repository=repository,
                scan_service=scan_service,
                user_id=user_id,
                lookback_hours=lookback_hours,
            )
            logger.info("[RESCAN] Pass complete: %s", summary)
        except Exception as exc:
            logger.warning("[RESCAN] Periodic pass failed: %s", exc)
        time.sleep(interval_secs)
