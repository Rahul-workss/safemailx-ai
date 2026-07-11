import json
import time
import threading

import redis

from forwarding_bot import send_reply_email
from server.gmail_oauth import build_gmail_service_from_blob
from server.gmail_labels import apply_result_label, ensure_safemailx_label_ids
from server.notifications import send_push_notifications
from server.queue import QUEUE_NAME
from server.repository import ScanRepository
from server.scan_service import ScanService
from server.settings import REDIS_URL
from utils.content_processor import clean_extracted_text
from utils.email_parser import parse_email
from utils.gmail_fetcher import get_gmail_service

# Feature 3: Offline safe-browsing periodic sync
try:
    from utils.config import FEATURE_OFFLINE_SAFEBROWSING_ENABLED, OFFLINE_HASH_FEED_URL, OFFLINE_HASH_SYNC_INTERVAL_HOURS
    from engines.offline_sync import run_periodic_sync
    _OFFLINE_SYNC_AVAILABLE = True
except ImportError:
    FEATURE_OFFLINE_SAFEBROWSING_ENABLED = False
    OFFLINE_HASH_FEED_URL = ""
    OFFLINE_HASH_SYNC_INTERVAL_HOURS = 6
    _OFFLINE_SYNC_AVAILABLE = False

# Feature 6: Second-Look Rescan
try:
    from utils.config import FEATURE_SECOND_LOOK_RESCAN_ENABLED, RESCAN_INTERVAL_HOURS, RESCAN_LOOKBACK_HOURS
    from server.rescan_job import run_periodic_rescan
    _RESCAN_AVAILABLE = True
except ImportError:
    FEATURE_SECOND_LOOK_RESCAN_ENABLED = False
    RESCAN_INTERVAL_HOURS = 12
    RESCAN_LOOKBACK_HOURS = 24
    _RESCAN_AVAILABLE = False
    def run_periodic_rescan(*a, **k): pass  # type: ignore[misc]




def _extract_email_address(value: str | None) -> str:
    if not value:
        return ""
    if "<" in value and ">" in value:
        return value.split("<", 1)[1].split(">", 1)[0].strip()
    return value.strip()


def run_worker() -> None:
    repository = ScanRepository()
    service = ScanService(repository)
    print("[WORKER] SafeMail X scan worker started.")

    # Feature 3: Start offline safe-browsing sync thread (daemon, starts once)
    if FEATURE_OFFLINE_SAFEBROWSING_ENABLED and _OFFLINE_SYNC_AVAILABLE:
        _sync_thread = threading.Thread(
            target=run_periodic_sync,
            args=(OFFLINE_HASH_FEED_URL, OFFLINE_HASH_SYNC_INTERVAL_HOURS),
            daemon=True,
            name="offline-safebrowsing-sync",
        )
        _sync_thread.start()
        print(
            f"[WORKER] Offline safe-browsing sync thread started. "
            f"Feed: {OFFLINE_HASH_FEED_URL or '(unset — sync will no-op)'} | "
            f"Interval: {OFFLINE_HASH_SYNC_INTERVAL_HOURS}h"
        )

    # Feature 6: Start second-look rescan thread (daemon, starts once)
    if FEATURE_SECOND_LOOK_RESCAN_ENABLED and _RESCAN_AVAILABLE:
        _rescan_thread = threading.Thread(
            target=run_periodic_rescan,
            kwargs={
                "repository": repository,
                "scan_service": service,
                "user_id": "local",
                "interval_hours": RESCAN_INTERVAL_HOURS,
                "lookback_hours": RESCAN_LOOKBACK_HOURS,
            },
            daemon=True,
            name="second-look-rescan",
        )
        _rescan_thread.start()
        print(
            f"[WORKER] Second-look rescan thread started. "
            f"Interval: {RESCAN_INTERVAL_HOURS}h | Lookback: {RESCAN_LOOKBACK_HOURS}h"
        )


    while True:
        scan_id = None
        job = None
        # Recreate the Redis client each iteration so a dropped
        # Render/cloud Redis connection never permanently stalls the worker.
        try:
            client = redis.from_url(REDIS_URL, socket_connect_timeout=10, socket_timeout=10)
        except Exception as exc:
            print(f"[WORKER] Redis connect failed: {exc}. Retrying in 5s...")
            time.sleep(5)
            continue

        try:
            result = client.blpop(QUEUE_NAME, timeout=5)
            if not result:
                continue
            _, raw_job = result

            job = json.loads(raw_job)
            scan_id = job.get("scan_id")
            user_id = job.get("user_id", "local")
            job_type = job.get("type")
            if job_type == "manual_text":
                result = service.run_manual_text_scan(
                    subject=job.get("subject", "Queued SafeMail X Scan"),
                    sender=job.get("sender", "queued_input"),
                    body=job.get("body", ""),
                    scan_mode=job.get("scan_mode", "balanced"),
                    scan_id=scan_id,
                    user_id=user_id,
                    metadata=job.get("metadata"),
                    source_type=job.get("source_type", "email"),
                )
                print(f"[WORKER] Completed scan {result['id']}")
                send_push_notifications(
                    repository.list_push_tokens(user_id=user_id),
                    title="SafeMail X scan complete",
                    body=f"{result['subject']}: {result['final_label']}",
                    data={"scan_id": result["id"], "final_label": result["final_label"]},
                )
                if job.get("source") in {"gmail", "web_forwarding"}:
                    reply_to = _extract_email_address(job.get("reply_to"))
                    report_pdf = result.get("report_pdf")
                    gmail_service = None
                    if job.get("source") == "web_forwarding":
                        gmail_service = get_gmail_service()
                    else:
                        token_blob = repository.get_gmail_token(user_id)
                        if token_blob:
                            gmail_service = build_gmail_service_from_blob(token_blob)
                    if reply_to and report_pdf and gmail_service:
                        send_reply_email(
                            gmail_service,
                            reply_to,
                            result["subject"],
                            result["final_label"],
                            int(result["final_score"] * 100),
                            report_pdf,
                            attachment_findings=(
                                result.get("evidence", {})
                                .get("attachment_analysis", {})
                                .get("findings", [])
                            ),
                        )
                        print(f"[WORKER] Sent Gmail reply for scan {result['id']} to {reply_to}")
            elif job_type == "gmail_label_message":
                token_blob = repository.get_gmail_token(user_id)
                if not token_blob:
                    raise RuntimeError("Gmail is not connected")
                gmail_service = build_gmail_service_from_blob(token_blob)
                label_ids = ensure_safemailx_label_ids(gmail_service)
                message_id = job.get("gmail_message_id")
                if not message_id:
                    raise RuntimeError("Missing Gmail message id")

                message_data = gmail_service.users().messages().get(
                    userId="me",
                    id=message_id,
                    format="full",
                ).execute()
                parsed = parse_email(gmail_service, message_id, message_data)
                body = clean_extracted_text(parsed.get("body", "")) or (
                    "Gmail label-selected message contained no extractable text."
                )
                attachments = parsed.get("attachments") or None
                result = service.run_manual_text_scan(
                    subject=parsed.get("subject", "Gmail label scan"),
                    sender=parsed.get("sender", "gmail_label_app"),
                    body=body,
                    scan_mode=job.get("scan_mode", "balanced"),
                    scan_id=scan_id,
                    user_id=user_id,
                    attachments=attachments,
                    link_details_override=parsed.get("links"),
                    source_type="email",
                    metadata={
                        "source": "gmail_label_app",
                        "gmail": {
                            "source": "gmail_label_app",
                            "permission": "user_applied_label",
                            "privacy_mode": "label_only",
                            "message_id": message_id,
                            "attachment_count": len(parsed.get("attachments", [])),
                            "image_count": len(parsed.get("images", [])),
                        },
                    },
                    security_headers_override=parsed.get("security_headers") or {},
                    auth_context_override="original_headers",
                    original_sender_override=parsed.get("sender"),
                )
                apply_result_label(gmail_service, message_id, result["final_label"], label_ids)
                print(f"[WORKER] Completed labeled Gmail scan {result['id']}")
                send_push_notifications(
                    repository.list_push_tokens(user_id=user_id),
                    title="SafeMail X Gmail scan complete",
                    body=f"{result['subject']}: {result['final_label']}",
                    data={"scan_id": result["id"], "final_label": result["final_label"]},
                )
            else:
                print(f"[WORKER] Unknown job type: {job_type}")
                if scan_id:
                    repository.fail_scan(scan_id, f"Unknown job type: {job_type}")
        except redis.exceptions.TimeoutError:
            # Expected in some environments when blpop hits the 5s timeout
            pass
        except redis.RedisError as exc:
            print(f"[WORKER] Redis error: {exc}")
            time.sleep(5)
        except Exception as exc:
            print(f"[WORKER] Job failed: {exc}")
            if scan_id:
                repository.fail_scan(scan_id, str(exc))
            if job and job.get("source") == "gmail_label_app" and job.get("gmail_message_id"):
                try:
                    token_blob = repository.get_gmail_token(job.get("user_id", "local"))
                    if token_blob:
                        gmail_service = build_gmail_service_from_blob(token_blob)
                        label_ids = ensure_safemailx_label_ids(gmail_service)
                        apply_result_label(gmail_service, job["gmail_message_id"], "failed", label_ids)
                except Exception as label_exc:
                    print(f"[WORKER] Failed to apply Gmail failure label: {label_exc}")
            time.sleep(2)


if __name__ == "__main__":
    run_worker()
