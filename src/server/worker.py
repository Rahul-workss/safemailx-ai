import json
import time

import redis

from forwarding_bot import send_reply_email
from server.notifications import send_push_notifications
from server.queue import QUEUE_NAME
from server.repository import ScanRepository
from server.scan_service import ScanService
from server.settings import REDIS_URL
from utils.gmail_fetcher import get_gmail_service


def _extract_email_address(value: str | None) -> str:
    if not value:
        return ""
    if "<" in value and ">" in value:
        return value.split("<", 1)[1].split(">", 1)[0].strip()
    return value.strip()


def run_worker() -> None:
    repository = ScanRepository()
    service = ScanService(repository)
    print("[WORKER] TrustMail scan worker started.")

    while True:
        scan_id = None
        try:
            client = redis.from_url(REDIS_URL)
            _, raw_job = client.blpop(QUEUE_NAME, timeout=5) or (None, None)
            if not raw_job:
                continue
            job = json.loads(raw_job)
            scan_id = job.get("scan_id")
            user_id = job.get("user_id", "local")
            job_type = job.get("type")
            if job_type == "manual_text":
                result = service.run_manual_text_scan(
                    subject=job.get("subject", "Queued TrustMail Scan"),
                    sender=job.get("sender", "queued_input"),
                    body=job.get("body", ""),
                    scan_mode=job.get("scan_mode", "balanced"),
                    scan_id=scan_id,
                    user_id=user_id,
                )
                print(f"[WORKER] Completed scan {result['id']}")
                send_push_notifications(
                    repository.list_push_tokens(user_id=user_id),
                    title="TrustMail scan complete",
                    body=f"{result['subject']}: {result['final_label']}",
                    data={"scan_id": result["id"], "final_label": result["final_label"]},
                )
                if job.get("source") == "gmail":
                    reply_to = _extract_email_address(job.get("reply_to"))
                    report_pdf = result.get("report_pdf")
                    if reply_to and report_pdf:
                        gmail_service = get_gmail_service()
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
            else:
                print(f"[WORKER] Unknown job type: {job_type}")
                if scan_id:
                    repository.fail_scan(scan_id, f"Unknown job type: {job_type}")
        except redis.RedisError as exc:
            print(f"[WORKER] Redis unavailable: {exc}")
            time.sleep(5)
        except Exception as exc:
            print(f"[WORKER] Job failed: {exc}")
            if scan_id:
                repository.fail_scan(scan_id, str(exc))
            time.sleep(2)


if __name__ == "__main__":
    run_worker()
