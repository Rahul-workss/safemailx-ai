import time
from typing import Any

from server.queue import ScanQueue
from server.repository import ScanRepository
from server.settings import GMAIL_POLL_INTERVAL_SECONDS
from server.gmail_oauth import build_gmail_service_from_blob
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
                "source": "gmail",
                "gmail_message_id": message_id,
                "forwarder": sender,
                "attachment_count": len(parsed.get("attachments", [])),
                "image_count": len(parsed.get("images", [])),
            },
        )
        scan_queue.enqueue({
            "type": "manual_text",
            "source": "gmail",
            "scan_id": scan_id,
            "user_id": user_id,
            "gmail_message_id": message_id,
            "reply_to": sender,
            "subject": subject,
            "sender": sender,
            "body": forwarded_text,
            "scan_mode": "balanced",
        })
        _mark_read(service, message_id)
        enqueued += 1
        print(f"[GMAIL WATCHER] Enqueued Gmail scan {scan_id} for message {message_id}")

    return enqueued


def run_gmail_watcher() -> None:
    """
    24/7 Gmail watcher entrypoint.

    Poll unread Gmail messages and push forwarded scan requests onto Redis.
    """
    print("[GMAIL WATCHER] Started.")
    repository = ScanRepository()
    scan_queue = ScanQueue()
    while True:
        try:
            user_ids = repository.list_gmail_user_ids()
            if user_ids:
                count = 0
                for user_id in user_ids:
                    token_blob = repository.get_gmail_token(user_id)
                    if not token_blob:
                        continue
                    service = build_gmail_service_from_blob(token_blob)
                    count += enqueue_unread_forwarded_messages(
                        service=service,
                        repository=repository,
                        scan_queue=scan_queue,
                        user_id=user_id,
                    )
            else:
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
