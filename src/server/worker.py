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


def process_scan_job(
    job: dict,
    service: ScanService | None = None,
    repository: ScanRepository | None = None,
) -> dict | None:
    repository = repository or ScanRepository()
    service = service or ScanService(repository)

    scan_id = job.get("scan_id")
    user_id = job.get("user_id", "local")
    job_type = job.get("type")

    try:
        if job_type in {"gmail_automatic_message", "outlook_automatic_message"}:
            provider = "gmail" if job_type.startswith("gmail") else "outlook"
            # OFF is authoritative even for jobs already sitting in Redis.
            state = repository.get_gmail_protection(user_id) if provider == "gmail" else repository.get_outlook_connection(user_id) or {}
            # auto_protect may be int (0/1) or bool depending on DB column type;
            # always normalise to bool before checking.
            auto_protect_on = bool(state.get("auto_protect"))
            if not auto_protect_on:
                print(f"[WORKER] {job_type}: automatic protection is OFF for user {user_id[:8]}. Dropping job (scan_id={scan_id}).")
                if scan_id:
                    # Remove the queued row entirely — a disabled-protection job
                    # should not appear as a FAILED scan in the user's history.
                    try:
                        with repository._db() as _c:
                            ph = "%s" if repository.is_postgres else "?"
                            _c.execute(f"DELETE FROM scans WHERE id={ph} AND user_id={ph}", (scan_id, user_id))
                            if repository.is_postgres:
                                _c.execute(f"DELETE FROM automatic_scan_claims WHERE scan_id={ph}", (scan_id,))
                    except Exception:
                        repository.fail_scan(scan_id, "automatic protection disabled")
                return None
            message_id = job.get("gmail_message_id") or job.get("outlook_message_id")
            if not message_id: raise RuntimeError("Missing provider message id")
            if provider == "gmail":
                token_blob = repository.get_gmail_token(user_id)
                if not token_blob: raise RuntimeError("Gmail is not connected")
                client = build_gmail_service_from_blob(token_blob, repository=repository, user_id=user_id)
                from server.gmail_labels import SAFEMAILX_LABELS, list_gmail_labels
                by_name={x.get("name"):x.get("id") for x in list_gmail_labels(client)}
                labels={key:by_name.get(name) for key,name in SAFEMAILX_LABELS.items()}
                labels_ready = all(labels.get(key) for key in ("safe","suspicious","phishing","failed","queued"))
                if not labels_ready:
                    # Labels not initialized yet — scan the email anyway but skip Gmail labeling.
                    # The scan result will still appear in SafeMail X history.
                    print(f"[WORKER] gmail_automatic_message: classification labels not initialized for user "
                          f"{user_id[:8]}. Scan will proceed without Gmail mailbox labeling.")
                msg = client.users().messages().get(userId="me", id=message_id, format="full").execute()
                parsed = parse_email(client, message_id, msg)
                # Recheck after network fetch to honor a concurrent OFF request.
                if not repository.get_gmail_protection(user_id).get("auto_protect"): return None
                result = service.run_manual_text_scan(subject=parsed.get("subject", ""), sender=parsed.get("sender", ""), body=parsed.get("body", ""), attachments=parsed.get("attachments") or None, link_details_override=parsed.get("links"), security_headers_override=parsed.get("security_headers") or {}, auth_context_override="original_headers", original_sender_override=parsed.get("sender"), source_type="email", scan_id=scan_id, user_id=user_id, retain_content=False, metadata={"source":"automatic_protection","provider":"gmail","message_id":message_id})
                if repository.get_gmail_protection(user_id).get("auto_protect"):
                    if labels_ready:
                        try:
                            apply_result_label(client, message_id, result.get("final_label", "failed"), labels)
                        except Exception as label_exc:
                            # The analysis result is already persisted. A mailbox
                            # write failure must not turn a completed scan into a
                            # zero-score FAILED record.
                            print(f"[WORKER] Gmail automatic classification update failed: {type(label_exc).__name__}")
                    else:
                        print(f"[WORKER] Skipped Gmail label update for {message_id[:12]} — labels not initialized")
            else:
                conn = repository.get_outlook_connection(user_id)
                if not conn: raise RuntimeError("Outlook is not connected")
                from server.outlook_graph import GraphClient
                from server.outlook_categories import set_message_category
                from utils.outlook_parser import parse_mime_message
                client = GraphClient(user_id, repository)
                parsed = parse_mime_message(client.get_mime(message_id))
                if not (repository.get_outlook_connection(user_id) or {}).get("auto_protect"): return None
                result = service.run_manual_text_scan(subject=parsed.get("subject", ""), sender=parsed.get("sender", ""), body=parsed.get("body", ""), attachments=parsed.get("attachments") or None, link_details_override=parsed.get("links"), security_headers_override=parsed.get("security_headers") or {}, auth_context_override="original_headers", original_sender_override=parsed.get("sender"), source_type="email", scan_id=scan_id, user_id=user_id, retain_content=False, metadata={"source":"automatic_protection","provider":"outlook","message_id":message_id})
                if (repository.get_outlook_connection(user_id) or {}).get("auto_protect"):
                    key={"legitimate":"safe","suspicious":"suspicious","phishing":"phishing"}.get(result.get("final_label"), "failed")
                    try:
                        set_message_category(client, message_id, key)
                    except Exception as category_exc:
                        print(f"[WORKER] Outlook automatic classification update failed: {type(category_exc).__name__}")
            return result
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
            return result
        elif job_type == "outlook_category_message":
            conn = repository.get_outlook_connection(user_id)
            if not conn:
                raise RuntimeError("Outlook is not connected")
            message_id = job.get("outlook_message_id")
            if not message_id:
                raise RuntimeError("Missing Outlook message id")
            from server.outlook_graph import GraphClient, GraphError
            from server.outlook_categories import set_message_category
            from utils.outlook_parser import parse_mime_message
            # NOTE: clean_extracted_text is already imported at module level.
            # Do NOT re-import it here — a local import shadows the module-level
            # name and causes UnboundLocalError in every other branch of this
            # function (Python treats the name as local to the entire function).
            client = GraphClient(user_id, repository)
            raw_mime = client.get_mime(message_id)
            parsed = parse_mime_message(raw_mime)
            body = clean_extracted_text(parsed.get("body", "")) or (
                "Outlook category-selected message contained no extractable text."
            )
            attachments = parsed.get("attachments") or None
            result = service.run_manual_text_scan(
                subject=parsed.get("subject", "Outlook category scan"),
                sender=parsed.get("sender", "outlook_category_app"),
                body=body,
                scan_mode=job.get("scan_mode", "balanced"),
                scan_id=scan_id,
                user_id=user_id,
                attachments=attachments,
                link_details_override=parsed.get("links"),
                source_type="email",
                metadata={
                    "source": "outlook_category_app",
                    "outlook": {
                        "source": "outlook_category_app",
                        "permission": "user_applied_category",
                        "privacy_mode": "category_only",
                        "message_id": message_id,
                        "attachment_count": len(parsed.get("attachments") or []),
                        "image_count": len(parsed.get("images") or []),
                    },
                },
                security_headers_override=parsed.get("security_headers") or {},
                auth_context_override="original_headers",
                original_sender_override=parsed.get("sender"),
            )
            verdict = result.get("final_label", "failed")
            verdict_key = {
                "legitimate": "safe",
                "suspicious": "suspicious",
                "phishing": "phishing",
            }.get(verdict, "failed")
            try:
                set_message_category(client, message_id, verdict_key)
            except Exception as cat_exc:
                print(f"[WORKER] Non-fatal: could not set Outlook category for {message_id}: {cat_exc}")
            print(f"[WORKER] Completed Outlook category scan {result['id']}")
            send_push_notifications(
                repository.list_push_tokens(user_id=user_id),
                title="SafeMail X Outlook scan complete",
                body=f"{result['subject']}: {result['final_label']}",
                data={"scan_id": result["id"], "final_label": result["final_label"]},
            )
            return result
        elif job_type == "gmail_label_message":
            token_blob = repository.get_gmail_token(user_id)
            if not token_blob:
                raise RuntimeError("Gmail is not connected")
            gmail_service = build_gmail_service_from_blob(
                token_blob, repository=repository, user_id=user_id
            )
            # ensure_safemailx_label_ids can raise on API failures or token
            # expiry. Treat failure as "labels unavailable" rather than a hard
            # scan failure — the scan result still appears in SafeMail X.
            try:
                label_ids = ensure_safemailx_label_ids(gmail_service)
                label_ids_ready = bool(label_ids)
            except Exception as lbl_exc:
                print(f"[WORKER] gmail_label_message: label setup failed ({type(lbl_exc).__name__}: {lbl_exc}). "
                      f"Scan will proceed without Gmail mailbox labeling.")
                label_ids = {}
                label_ids_ready = False
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
            if label_ids_ready:
                try:
                    apply_result_label(gmail_service, message_id, result["final_label"], label_ids)
                except Exception as label_exc:
                    # Keep the completed verdict visible in SafeMail X even if
                    # Gmail rejects the optional mailbox label update.
                    print(f"[WORKER] Gmail label update failed: {type(label_exc).__name__}")
            else:
                print(f"[WORKER] Skipped Gmail label update for {message_id[:12]} — labels not ready")
            print(f"[WORKER] Completed labeled Gmail scan {result['id']}")
            send_push_notifications(
                repository.list_push_tokens(user_id=user_id),
                title="SafeMail X Gmail scan complete",
                body=f"{result['subject']}: {result['final_label']}",
                data={"scan_id": result["id"], "final_label": result["final_label"]},
            )
            return result
        else:
            print(f"[WORKER] Unknown job type: {job_type}")
            if scan_id:
                repository.fail_scan(scan_id, f"Unknown job type: {job_type}")
            return None
    except Exception as exc:
        import traceback
        exc_detail = f"{type(exc).__name__}: {exc}"
        tb_str = traceback.format_exc()
        print(f"[WORKER] Job failed ({job_type}, user={user_id[:8] if user_id else '?'}, scan={scan_id}): {exc_detail}")
        print(f"[WORKER] Traceback:\n{tb_str}")
        if scan_id:
            repository.fail_scan(scan_id, str(exc))
        if job and job.get("type") in {"gmail_automatic_message", "outlook_automatic_message"}:
            attempts = int(job.get("attempt", 0))
            if attempts < 3:
                retry_job = dict(job, attempt=attempts + 1)
                try:
                    from server.queue import ScanQueue
                    ScanQueue().enqueue(retry_job)
                except Exception:
                    # Leave the claim in place; reconciliation will not create
                    # duplicates. Surface the failed scan for explicit recovery.
                    pass
            else:
                try:
                    if job["type"] == "gmail_automatic_message" and repository.get_gmail_protection(user_id).get("auto_protect"):
                        blob = repository.get_gmail_token(user_id)
                        if blob:
                            svc = build_gmail_service_from_blob(blob, repository=repository, user_id=user_id)
                            apply_result_label(svc, job["gmail_message_id"], "failed", ensure_safemailx_label_ids(svc))
                    elif job["type"] == "outlook_automatic_message" and (repository.get_outlook_connection(user_id) or {}).get("auto_protect"):
                        from server.outlook_graph import GraphClient
                        from server.outlook_categories import set_message_category
                        set_message_category(GraphClient(user_id, repository), job["outlook_message_id"], "failed")
                except Exception:
                    pass
        if job and job.get("source") == "gmail_label_app" and job.get("gmail_message_id"):
            try:
                token_blob = repository.get_gmail_token(job.get("user_id", "local"))
                if token_blob:
                    gmail_service = build_gmail_service_from_blob(token_blob)
                    label_ids = ensure_safemailx_label_ids(gmail_service)
                    apply_result_label(gmail_service, job["gmail_message_id"], "failed", label_ids)
            except Exception as label_exc:
                print(f"[WORKER] Failed to apply Gmail failure label: {label_exc}")
        # Outlook: best-effort failure category on exception
        if job and job.get("type") == "outlook_category_message" and job.get("outlook_message_id"):
            try:
                from server.outlook_graph import GraphClient
                from server.outlook_categories import set_message_category
                _oc = GraphClient(job.get("user_id", "local"), repository)
                set_message_category(_oc, job["outlook_message_id"], "failed")
            except Exception as _oexc:
                print(f"[WORKER] Non-fatal: could not set Outlook failure category: {_oexc}")
        # IMPORTANT: Do NOT re-raise here — caller may be a daemon thread.
        # Re-raising would kill the thread and prevent future scans from processing.
        return None


def run_worker() -> None:
    repository = ScanRepository()
    service = ScanService(repository)

    # ── Startup banner — shows environment so stale workers are immediately visible ──
    import sys as _sys
    import os as _os
    try:
        from engines.llm_analyzer import _get_live_config as _glc
        _cfg = _glc()
        _model_line = f"model={_cfg['model']!r}  max_tokens={_cfg['max_tokens']}  thinking={_cfg['thinking']}"
    except Exception as _e:
        _model_line = f"(could not read: {_e})"
    print("=" * 60)
    print("[WORKER] SafeMail X scan worker started.")
    print(f"[WORKER] Python : {_sys.executable}")
    print(f"[WORKER] CWD    : {_os.getcwd()}")
    print(f"[WORKER] LLM    : {_model_line}")
    print("=" * 60)

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
            process_scan_job(job, service=service, repository=repository)
        except redis.exceptions.TimeoutError:
            # Expected in some environments when blpop hits the 5s timeout
            pass
        except redis.RedisError as exc:
            print(f"[WORKER] Redis error: {exc}")
            time.sleep(5)
        except Exception as exc:
            print(f"[WORKER] Job loop error: {exc}")
            time.sleep(2)


if __name__ == "__main__":
    run_worker()
