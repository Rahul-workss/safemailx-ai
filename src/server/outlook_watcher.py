"""Outlook label-watcher: enqueue messages tagged 'SafeMail X Scan'.

Mirrors the gmail_watcher.enqueue_labeled_gmail_messages() pattern exactly:
- CLAIM FIRST: swap Scan → Queued BEFORE creating the scan DB row
- Stale rescue: also process Queued messages older than 15 minutes
- Job payload: message IDs only (no body text in Redis)
- Redis down: daemon thread fallback
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any

from server.outlook_categories import SAFEMAILX_CATEGORIES, set_message_category
from server.settings import OUTLOOK_AUTO_POLL_ENABLED, OUTLOOK_POLL_INTERVAL_SECONDS

logger = logging.getLogger("outlook_watcher")

_SCAN_LABEL = SAFEMAILX_CATEGORIES["scan"][0]      # "SafeMail X Scan"
_QUEUED_LABEL = SAFEMAILX_CATEGORIES["queued"][0]  # "SafeMail X Queued"

# Stale claim threshold — Queued items older than this get rescued
_STALE_MINUTES = 15


def _search_messages_by_category(client: Any, category_name: str, limit: int = 10) -> list[dict]:
    """Return up to *limit* message stubs (id + receivedDateTime) with a given category."""
    filter_expr = f"categories/any(c:c eq '{category_name}')"
    try:
        resp = client.get(
            f"/me/messages?$filter={filter_expr}"
            f"&$select=id,receivedDateTime,categories&$top={limit}&$orderby=receivedDateTime asc"
        )
        return resp.get("value", [])
    except Exception as exc:
        logger.warning("Outlook category search for %r failed: %s", category_name, exc)
        return []


def _enqueue_message(
    *,
    msg: dict,
    user_id: str,
    client: Any,
    repository: Any,
    scan_queue: Any,
) -> bool:
    """Claim a single message and enqueue it. Returns True if enqueued."""
    message_id = msg["id"]

    # 1. CLAIM FIRST: swap category Scan/Queued → Queued (atomic-ish via Graph PATCH)
    try:
        set_message_category(client, message_id, "queued")
    except Exception as exc:
        logger.warning("Could not claim message %s (category swap): %s", message_id, exc)
        return False

    # 2. Create a queued scan row in DB
    scan_id = repository.create_queued_scan(
        subject=f"Outlook scan [{message_id[:8]}]",
        sender="outlook_category_app",
        user_id=user_id,
        evidence={"status": "queued", "source": "outlook_category_app"},
    )

    # 3. Push job to Redis scan queue (ID only — no body text)
    job = {
        "type": "outlook_category_message",
        "scan_id": scan_id,
        "user_id": user_id,
        "outlook_message_id": message_id,
        "scan_mode": "balanced",
    }

    try:
        from server.queue import QueueUnavailable
        scan_queue.enqueue(job)
        logger.info("Enqueued Outlook message %s as scan %s", message_id, scan_id)
        return True
    except Exception as exc:
        logger.warning(
            "Redis unavailable for Outlook message %s — processing in daemon thread: %s",
            message_id, exc,
        )
        # Fallback: daemon thread (mirrors gmail_watcher behaviour)
        def _fallback():
            try:
                from server.worker import process_scan_job
                from server.repository import ScanRepository
                repo = ScanRepository()
                process_scan_job(job, repository=repo)
            except Exception as fe:
                logger.error("Outlook daemon fallback failed for %s: %s", message_id, fe)

        threading.Thread(target=_fallback, daemon=True, name=f"outlook-fallback-{message_id[:8]}").start()
        return True


def enqueue_labeled_outlook_messages(
    *,
    user_id: str,
    repository: Any,
    scan_queue: Any,
    client: Any | None = None,
    limit: int = 10,
) -> int:
    """Scan for Outlook messages tagged 'SafeMail X Scan' and enqueue them.

    Returns the number of messages enqueued.
    """
    if client is None:
        from server.outlook_graph import GraphClient
        client = GraphClient(user_id, repository)

    enqueued = 0

    # --- Primary: messages tagged 'SafeMail X Scan' ---
    scan_msgs = _search_messages_by_category(client, _SCAN_LABEL, limit=limit)
    for msg in scan_msgs:
        if _enqueue_message(msg=msg, user_id=user_id, client=client, repository=repository, scan_queue=scan_queue):
            enqueued += 1

    # --- Stale rescue: messages stuck in 'SafeMail X Queued' for > 15 min ---
    queued_msgs = _search_messages_by_category(client, _QUEUED_LABEL, limit=limit)
    stale_cutoff = time.time() - (_STALE_MINUTES * 60)
    for msg in queued_msgs:
        try:
            import datetime
            received_str = msg.get("receivedDateTime", "")
            if received_str:
                dt = datetime.datetime.fromisoformat(received_str.replace("Z", "+00:00"))
                msg_time = dt.timestamp()
            else:
                msg_time = 0
        except Exception:
            msg_time = 0

        if msg_time < stale_cutoff:
            logger.info("Rescuing stale Outlook Queued message %s", msg["id"])
            if _enqueue_message(msg=msg, user_id=user_id, client=client, repository=repository, scan_queue=scan_queue):
                enqueued += 1

    return enqueued


def run_outlook_auto_poller() -> None:
    """Auto-poll ALL connected Outlook users in a single loop.

    Runs as a daemon thread when OUTLOOK_AUTO_POLL_ENABLED=true.
    Spaces out per-user calls by 0.5 s to avoid Graph burst limits.
    """
    from server.repository import ScanRepository
    from server.queue import ScanQueue

    logger.info("[OUTLOOK POLLER] Starting auto-poller (interval=%ds)", OUTLOOK_POLL_INTERVAL_SECONDS)

    while True:
        try:
            repository = ScanRepository()
            scan_queue = ScanQueue()
            if OUTLOOK_AUTO_POLL_ENABLED:
                user_ids = repository.list_outlook_user_ids(active_only=True)
                for user_id in user_ids:
                    try:
                        count = enqueue_labeled_outlook_messages(user_id=user_id, repository=repository, scan_queue=scan_queue)
                        if count: logger.info("[OUTLOOK POLLER] user=%s enqueued=%d", user_id, count)
                    except Exception as exc:
                        logger.warning("[OUTLOOK POLLER] user=%s error: %s", user_id, exc)
                    time.sleep(0.5)

            # Per-account automatic protection is separate from the legacy
            # user-selected category poller above.
            for user_id in repository.list_outlook_protection_users():
                try:
                    conn = repository.get_outlook_connection(user_id) or {}
                    cursor = conn.get("delta_link")
                    if not cursor: continue
                    client = __import__("server.outlook_graph", fromlist=["GraphClient"]).GraphClient(user_id, repository)
                    page_url = cursor
                    final_link = cursor
                    while page_url:
                        resp = client.get(page_url)
                        for msg in resp.get("value", []):
                            mid = msg.get("id")
                            if not mid or "@removed" in msg: continue
                            sid = repository.claim_automatic_scan("outlook", user_id, mid)
                            if sid:
                                try:
                                    scan_queue.enqueue({"type":"outlook_automatic_message","user_id":user_id,"scan_id":sid,"outlook_message_id":mid})
                                except Exception:
                                    repository.release_automatic_scan_claim("outlook", user_id, mid)
                                    raise
                        page_url = resp.get("@odata.nextLink")
                        final_link = resp.get("@odata.deltaLink", final_link)
                    if final_link != cursor:
                        repository.update_outlook_delta_link(user_id, final_link)
                except Exception as exc:
                    try:
                        from server.outlook_graph import GraphError, GraphClient
                        if isinstance(exc, GraphError) and (exc.status == 410 or exc.code.lower() in {"syncstatenotfound", "resyncrequired"}):
                            client = GraphClient(user_id, repository)
                            from server.outlook_graph import initialize_inbox_delta_cursor
                            latest = initialize_inbox_delta_cursor(client)
                            if latest: repository.update_outlook_delta_link(user_id, latest)
                    except Exception:
                        pass
                    logger.warning("[OUTLOOK POLLER] automatic sync failed for account=%s error=%s", user_id[:8], type(exc).__name__)

        except Exception as exc:
            logger.error("[OUTLOOK POLLER] Loop error: %s", exc)

        time.sleep(OUTLOOK_POLL_INTERVAL_SECONDS)
