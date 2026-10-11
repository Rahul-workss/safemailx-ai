import time
from typing import Any

from server.queue import ScanQueue
from server.repository import ScanRepository
from server.settings import GMAIL_POLL_INTERVAL_SECONDS
from server.gmail_oauth import build_gmail_service_from_blob
from server.gmail_labels import ensure_safemailx_label_ids, move_message_to_queued_label
from utils.content_processor import clean_extracted_text
from utils.email_parser import parse_email
from utils.forwarding_parser import extract_forwarded_payload
from utils.gmail_fetcher import get_gmail_service


def _is_forwarded_subject(subject: str) -> bool:
    normalized = str(subject or "").strip().lower()
    return normalized.startswith(("fwd:", "fw:"))


def _mark_read(service: Any, message_id: str) -> None:
    service.users().messages().modify(
        userId="me",
        id=message_id,
        body={"removeLabelIds": ["UNREAD"]},
    ).execute()


def enqueue_unread_forwarded_messages(
    *,
    service: Any | None = None,
    repository: ScanRepository | None = None,
    scan_queue: ScanQueue | None = None,
    limit: int = 10,
    user_id: str = "local",
) -> int:
    service = service or get_gmail_service()
    repository = repository or ScanRepository()
    scan_queue = scan_queue or ScanQueue()

    results = service.users().messages().list(
        userId="me",
        labelIds=["UNREAD"],
        q="",
        maxResults=limit,
    ).execute()
    messages = results.get("messages", [])

    if not messages:
        print("[GMAIL WATCHER] No unread messages found.")
        return 0

    enqueued = 0
    for msg in messages:
        message_id = msg["id"]
        message_data = service.users().messages().get(
            userId="me",
            id=message_id,
            format="full",
        ).execute()
        parsed = parse_email(service, message_id, message_data)
        subject = parsed.get("subject", "Forwarded Scan Request")
        sender = parsed.get("sender", "Unknown")

        if not _is_forwarded_subject(subject):
            print(f"[GMAIL WATCHER] Ignoring non-forwarded email: {subject!r}")
            _mark_read(service, message_id)
            continue

        forwarded_text = clean_extracted_text(
            extract_forwarded_payload(parsed.get("body", ""))
        )
        if not forwarded_text:
            print(f"[GMAIL WATCHER] Forwarded email had no scannable body: {message_id}")
            _mark_read(service, message_id)
            continue

        scan_id = repository.create_queued_scan(
            subject=subject,
            sender=sender,
            user_id=user_id,
            evidence={
                "status": "queued",
                "source": "web_forwarding",
                "legacy_source": "gmail",
                "gmail_message_id": message_id,
                "forwarder": sender,
                "attachment_count": len(parsed.get("attachments", [])),
                "image_count": len(parsed.get("images", [])),
            },
        )
        fwd_job = {
            "type": "manual_text",
            "source": "web_forwarding",
            "scan_id": scan_id,
            "user_id": user_id,
            "gmail_message_id": message_id,
            "reply_to": sender,
            "subject": subject,
            "sender": sender,
            "body": forwarded_text,
            "scan_mode": "balanced",
        }
        enqueued_to_redis = False
        try:
            scan_queue.enqueue(fwd_job)
            enqueued_to_redis = True
        except Exception as q_exc:
            print(f"[GMAIL WATCHER] Redis unavailable for forwarded scan ({q_exc}); running in background thread")

        if not enqueued_to_redis:
            import threading
            from server.worker import process_scan_job
            threading.Thread(
                target=process_scan_job,
                args=(fwd_job,),
                daemon=True,
                name=f"fwd-worker-{scan_id[:8]}",
            ).start()
            print(f"[GMAIL WATCHER] Started in-process thread for forwarded scan {scan_id}")

        _mark_read(service, message_id)
        enqueued += 1
        print(f"[GMAIL WATCHER] Enqueued Gmail scan {scan_id} for message {message_id}")

    return enqueued


def enqueue_labeled_gmail_messages(
    *,
    service: Any,
    repository: ScanRepository | None = None,
    scan_queue: ScanQueue | None = None,
    limit: int = 10,
    user_id: str = "local",
) -> int:
    repository = repository or ScanRepository()
    scan_queue = scan_queue or ScanQueue()
    label_ids = ensure_safemailx_label_ids(service)

    # 1. Search for messages with the active scan label
    messages: list[dict[str, Any]] = []
    seen_message_ids: set[str] = set()

    try:
        results = service.users().messages().list(
            userId="me",
            labelIds=[label_ids["scan"]],
            maxResults=limit,
        ).execute()
        for m in results.get("messages", []):
            if m["id"] not in seen_message_ids:
                messages.append(m)
                seen_message_ids.add(m["id"])
    except Exception as exc:
        print(f"[GMAIL WATCHER] Could not list messages for scan label: {exc}")

    # 2. Rescue check: also look for messages that have the 'queued' label
    # but were never resolved to a final verdict (e.g. from an interrupted worker run)
    queued_lbl_id = label_ids.get("queued")
    if queued_lbl_id and len(messages) < limit:
        try:
            q_results = service.users().messages().list(
                userId="me",
                labelIds=[queued_lbl_id],
                maxResults=limit - len(messages),
            ).execute()
            for m in q_results.get("messages", []):
                if m["id"] not in seen_message_ids:
                    messages.append(m)
                    seen_message_ids.add(m["id"])
        except Exception as exc:
            print(f"[GMAIL WATCHER] Could not check queued label: {exc}")

    # 3. Check legacy label names ('TrustMail Scan', 'TrustMail Queued')
    if len(messages) < limit:
        try:
            from server.gmail_labels import list_gmail_labels
            for lbl in list_gmail_labels(service):
                lname = (lbl.get("name") or "").lower()
                if lname in {"trustmail scan", "trustmail queued"} and lbl.get("id"):
                    legacy_res = service.users().messages().list(
                        userId="me",
                        labelIds=[lbl["id"]],
                        maxResults=limit - len(messages),
                    ).execute()
                    for lm in legacy_res.get("messages", []):
                        if lm["id"] not in seen_message_ids:
                            messages.append(lm)
                            seen_message_ids.add(lm["id"])
        except Exception as exc:
            print(f"[GMAIL WATCHER] Could not check legacy labels: {exc}")

    if not messages:
        print("[GMAIL WATCHER] No SafeMail X-labeled messages found.")
        return 0

    enqueued = 0
    processed_threads = set()

    # Known terminal result label IDs
    result_label_ids = {
        label_ids.get("safe"),
        label_ids.get("suspicious"),
        label_ids.get("phishing"),
        label_ids.get("failed"),
    } - {None}

    for msg in messages:
        thread_id = msg.get("threadId")

        # Deduplicate by thread when thread metadata exists.
        if thread_id and thread_id in processed_threads:
            continue
        if thread_id:
            processed_threads.add(thread_id)

        try:
            thread_messages = []
            message_id = msg["id"]

            threads_resource = getattr(service.users(), "threads", None)
            if thread_id and callable(threads_resource):
                thread_data = threads_resource().get(userId="me", id=thread_id).execute()
                thread_messages = thread_data.get("messages", [])
                if thread_messages:
                    message_id = thread_messages[0]["id"]

            # Check if this message already has a final verdict label applied
            msg_meta = service.users().messages().get(
                userId="me",
                id=message_id,
                format="minimal",
            ).execute()
            current_labels = set(msg_meta.get("labelIds", []))
            if current_labels & result_label_ids:
                # Already analyzed and labeled with a final verdict; remove queued/scan tags
                try:
                    to_remove = [l for l in [label_ids.get("scan"), label_ids.get("queued")] if l and l in current_labels]
                    if to_remove:
                        service.users().messages().modify(
                            userId="me", id=message_id, body={"removeLabelIds": to_remove}
                        ).execute()
                except Exception:
                    pass
                continue

            scan_id = repository.create_queued_scan(
                subject="Gmail label scan",
                sender="gmail_label_app",
                user_id=user_id,
                evidence={
                    "status": "queued",
                    "source": "gmail_label_app",
                    "permission": "user_applied_label",
                    "privacy_mode": "label_only",
                    "gmail_message_id": message_id,
                    "thread_id": thread_id,
                },
            )

            job = {
                "type": "gmail_label_message",
                "source": "gmail_label_app",
                "scan_id": scan_id,
                "user_id": user_id,
                "gmail_message_id": message_id,
            }

            enqueued_to_redis = False
            try:
                scan_queue.enqueue(job)
                enqueued_to_redis = True
            except Exception as q_exc:
                print(f"[GMAIL WATCHER] Redis enqueue unavailable ({q_exc}); running in background thread")

            # CRITICAL FALLBACK: If Redis is offline (e.g. Railway) or enqueue failed,
            # execute in a background daemon thread right now so the scan never gets stuck!
            if not enqueued_to_redis:
                import threading
                from server.worker import process_scan_job
                threading.Thread(
                    target=process_scan_job,
                    args=(job,),
                    daemon=True,
                    name=f"gmail-worker-{scan_id[:8]}",
                ).start()
                print(f"[GMAIL WATCHER] Started in-process background worker for scan {scan_id}")

            if thread_messages:
                for t_msg in thread_messages:
                    try:
                        move_message_to_queued_label(service, t_msg["id"], label_ids)
                    except Exception:
                        pass
            else:
                move_message_to_queued_label(service, message_id, label_ids)

            enqueued += 1
            print(f"[GMAIL WATCHER] Enqueued labeled Gmail scan {scan_id} for original message {message_id} in thread {thread_id}")

        except Exception as exc:
            print(f"[GMAIL WATCHER] Failed to process thread {thread_id}: {exc}")

    return enqueued


def run_gmail_watcher() -> None:
    """
    24/7 Gmail watcher entrypoint.
    Only checks for forwarded emails sent to the bot.
    Label scanning for App Connect is strictly manual via the App REST API.
    """
    print("[GMAIL WATCHER] Started.")
    repository = ScanRepository()
    scan_queue = ScanQueue()
    while True:
        try:
            count = enqueue_unread_forwarded_messages(repository=repository, scan_queue=scan_queue)
            print(f"[GMAIL WATCHER] Poll complete. Enqueued {count} scan(s).")
        except KeyboardInterrupt:
            print("[GMAIL WATCHER] Shutting down gracefully.")
            break
        except Exception as exc:
            print(f"[GMAIL WATCHER] Poll failed: {exc}")
            
        time.sleep(GMAIL_POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    run_gmail_watcher()
