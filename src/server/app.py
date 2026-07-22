from pathlib import Path
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile, WebSocket
from fastapi.responses import FileResponse

from server.auth import create_access_token, create_refresh_token, create_signed_token, require_auth, validate_login, verify_access_token
from server.gmail_watcher import enqueue_unread_forwarded_messages
from server.gmail_oauth import build_authorization_url, build_gmail_service_from_blob, encode_credentials, exchange_code_for_token
try:
    from server.gmail_labels import SAFEMAILX_LABELS, ensure_safemailx_labels
except ImportError:
    SAFEMAILX_LABELS = {"scan": "SafeMail X Scan", "queued": "SafeMail X Queued", "safe": "SafeMail X Safe", "suspicious": "SafeMail X Suspicious", "phishing": "SafeMail X Phishing", "failed": "SafeMail X Failed"}
    ensure_safemailx_labels = None
from server.health import build_health, check_llm_health
from server.mailer import send_password_reset_email
from server.persistence_checks import check_database_persistence
from google.auth.exceptions import RefreshError
from server.queue import QueueUnavailable, ScanQueue
from server.readiness import build_readiness
from server.repository import ScanRepository
from server.scan_service import SCAN_STAGES, ScanService
from server.schemas import (
    DashboardResponse,
    ForgotPasswordRequest,
    GmailOAuthStartResponse,
    GmailOAuthStatusResponse,
    GmailLabelsResponse,
    HealthResponse,
    LoginRequest,
    ManualScanRequest,
    ManualSmsScanRequest,
    NotificationPreferences,
    PushTokenRequest,
    PushTokenResponse,
    ReadinessResponse,
    RefreshRequest,
    ReportDownloadLinkResponse,
    ResetPasswordRequest,
    ScanFeedbackRequest,
    ScanFeedbackResponse,
    ScanDetail,
    ScanSummary,
    SettingsResponse, SettingsUpdateRequest,
    TokenResponse,
    UrlScanRequest,
    InstantSmsScanRequest,
    InstantUrlScanRequest,
    InstantScanResult,
)
from server.inline_scan_service import InlineScanService
try:
    from server.settings import GMAIL_OAUTH_REDIRECT_URI, MAX_UPLOAD_BYTES
except ImportError:
    from server.settings import MAX_UPLOAD_BYTES
    GMAIL_OAUTH_REDIRECT_URI = ""
from server.settings import DATABASE_URL, FEATURE_REFRESH_TOKEN_ENABLED
from server.uploads import SUPPORTED_UPLOAD_EXTENSIONS, extract_upload_text
from server.uploads import IMAGE_EXTENSIONS
try:
    from utils.config import SIGNIN_CREDENTIALS_PATH
except ImportError:
    SIGNIN_CREDENTIALS_PATH = None

# Feature 5: Adaptive Trust Baseline
try:
    from utils.config import FEATURE_ADAPTIVE_TRUST_ENABLED, ADAPTIVE_TRUST_MIN_SCANS
    from engines.adaptive_trust_engine import (
        list_baseline_summary,
        clear_all_baseline_data,
    )
    _ADAPTIVE_TRUST_APP_AVAILABLE = True
except ImportError:
    FEATURE_ADAPTIVE_TRUST_ENABLED = False
    ADAPTIVE_TRUST_MIN_SCANS = 3
    _ADAPTIVE_TRUST_APP_AVAILABLE = False
    def list_baseline_summary(user_id, **kw): return []  # type: ignore[misc]
    def clear_all_baseline_data(user_id, **kw): return 0  # type: ignore[misc]



from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="SafeMail X AI API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://192.168.56.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
import threading
import time
from server.worker import run_worker
from server.gmail_watcher import run_gmail_watcher


def _resilient_thread(name: str, target_fn):
    """Wraps a worker function in an infinite restart loop so
    the thread NEVER permanently dies â€” it auto-restarts after
    any crash with a 5-second backoff."""
    def wrapper():
        while True:
            try:
                print(f"[APP] {name} thread starting...")
                target_fn()
            except Exception as exc:
                print(f"[APP] {name} thread crashed: {exc}. Restarting in 5s...")
            time.sleep(5)
    return wrapper


@app.on_event("startup")
def startup_event():
    print("[APP] Starting background worker threads...")
    persistence_warning = check_database_persistence(DATABASE_URL)
    if persistence_warning:
        print(persistence_warning)
    threading.Thread(
        target=_resilient_thread("Worker", run_worker),
        daemon=True,
        name="scan-worker",
    ).start()
    threading.Thread(
        target=_resilient_thread("GmailWatcher", run_gmail_watcher),
        daemon=True,
        name="gmail-watcher",
    ).start()

repository = ScanRepository()
scan_service = ScanService(repository)
inline_scan_service = InlineScanService(repository)
scan_queue = ScanQueue()
settings_state = SettingsResponse()


def _user_id(auth_payload) -> str:
    if not auth_payload:
        return "local"
    return auth_payload.get("uid") or "local"


@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    user = validate_login(repository, payload.email, payload.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return TokenResponse(
        access_token=create_access_token(user["email"], user["id"]),
        refresh_token=create_refresh_token(user["email"], user["id"]),
    )

import random
from datetime import datetime, timedelta, timezone

from server.auth import hash_password
from server.schemas import RegisterRequest, SendOtpRequest
from server.mailer import send_otp_email

@app.post("/auth/send-otp")
def send_otp(payload: SendOtpRequest):
    existing_user = repository.get_user_by_email(payload.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    otp = "".join(random.choices("0123456789", k=6))
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    
    repository.store_otp(payload.email, otp, expires_at)
    
    try:
        send_otp_email(payload.email, otp)
    except Exception as exc:
        print(f"[MAIL ERROR] Failed sending OTP email to {payload.email}: {exc}")
    return {"status": "OTP sent"}

@app.post("/auth/register", response_model=TokenResponse)
def register(payload: RegisterRequest):
    existing_user = repository.get_user_by_email(payload.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
        
    otp_record = repository.get_otp(payload.email)
    if not otp_record:
        raise HTTPException(status_code=400, detail="No OTP requested or OTP expired")
        
    expires_at = otp_record["expires_at"]
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="OTP has expired")
        
    if str(otp_record["otp"]) != str(payload.otp):
        raise HTTPException(status_code=400, detail="Invalid OTP")
        
    repository.delete_otp(payload.email)
    
    password_hash, salt = hash_password(payload.password)
    user_id = repository.create_user(
        email=payload.email,
        password_hash=password_hash,
        salt=salt
    )
    return TokenResponse(
        access_token=create_access_token(payload.email, user_id),
        refresh_token=create_refresh_token(payload.email, user_id),
    )


@app.post("/auth/refresh", response_model=TokenResponse)
def refresh_token(payload: RefreshRequest):
    if not FEATURE_REFRESH_TOKEN_ENABLED:
        raise HTTPException(status_code=404, detail="Refresh token flow disabled")

    decoded = verify_access_token(payload.refresh_token)
    if decoded.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Not a refresh token")

    user = repository.get_user_by_id(decoded.get("uid", ""))
    if not user:
        raise HTTPException(status_code=401, detail="Account no longer exists")

    return TokenResponse(
        access_token=create_access_token(user["email"], user["id"]),
        refresh_token=create_refresh_token(user["email"], user["id"]),
    )


@app.post("/auth/forgot-password")
def forgot_password(payload: ForgotPasswordRequest):
    user = repository.get_user_by_email(payload.email)
    if user:
        from datetime import datetime, timedelta, timezone
        import uuid
        token = str(uuid.uuid4())
        expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        repository.create_password_reset_token(token, user["id"], expires)
        try:
            send_password_reset_email(payload.email, token)
        except Exception as exc:
            print(f"[MAIL ERROR] Failed sending reset email to {payload.email}: {exc}")
    # Always return 200 to prevent email enumeration
    return {"status": "If an account with that email exists, a password reset link has been sent."}


@app.post("/auth/reset-password")
def reset_password(payload: ResetPasswordRequest):
    reset_record = repository.get_password_reset_token(payload.token)
    if not reset_record:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    
    from datetime import datetime, timezone
    # SQLite returns text, Postgres might return datetime
    expires_at = reset_record["expires_at"]
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at)
        
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Reset token has expired")

    from server.auth import hash_password
    password_hash, salt = hash_password(payload.new_password)
    repository.update_user_password(reset_record["user_id"], password_hash, salt)
    repository.delete_password_reset_token(payload.token)
    return {"status": "Password has been successfully reset"}


@app.get("/api/health", response_model=HealthResponse)
def health():
    redis_status = "online" if scan_queue.ping() else "offline"
    database_status = "online" if repository.ping() else "offline"
    return build_health(redis_status=redis_status, database_status=database_status)


@app.get("/api/health/llm")
def llm_health():
    status, detail = check_llm_health()
    return {"status": status, **detail}


@app.get("/api/readiness", response_model=ReadinessResponse)
def readiness(_auth=Depends(require_auth)):
    return build_readiness()


@app.get("/api/dashboard", response_model=DashboardResponse)
def dashboard(_auth=Depends(require_auth)):
    counts = repository.dashboard_counts(user_id=_user_id(_auth))
    redis_status = "online" if scan_queue.ping() else "offline"
    database_status = "online" if repository.ping() else "offline"
    return DashboardResponse(
        **counts,
        health=HealthResponse(**build_health(redis_status=redis_status, database_status=database_status)),
    )


@app.get("/api/scans", response_model=list[ScanSummary])
def list_scans(_auth=Depends(require_auth)):
    return repository.list_scans(user_id=_user_id(_auth))


@app.get("/api/scans/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: str, _auth=Depends(require_auth)):
    scan = repository.get_scan(scan_id, user_id=_user_id(_auth))
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.post("/api/scans/{scan_id}/feedback", response_model=ScanFeedbackResponse)
def set_scan_feedback(scan_id: str, payload: ScanFeedbackRequest, _auth=Depends(require_auth)):
    stored = repository.set_scan_feedback(
        scan_id,
        user_id=_user_id(_auth),
        feedback=payload.feedback,
        note=payload.note,
    )
    if stored is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    evidence = stored.get("evidence", {})
    review = evidence.get("review_feedback", {})
    return ScanFeedbackResponse(
        scan_id=scan_id,
        feedback=review.get("feedback", payload.feedback),
        note=review.get("note", payload.note),
        updated_at=review.get("updated_at", "")
    )


@app.post("/api/scans/manual", response_model=ScanDetail)
def manual_scan(payload: ManualScanRequest, _auth=Depends(require_auth)):
    return scan_service.run_manual_text_scan(
        subject=payload.subject,
        sender=payload.sender,
        body=payload.body,
        scan_mode=payload.scan_mode,
        user_id=_user_id(_auth),
    )


@app.post("/api/scans/manual/queue", response_model=ScanDetail, status_code=202)
def queue_manual_scan(payload: ManualScanRequest, _auth=Depends(require_auth)):
    user_id = _user_id(_auth)
    scan_id = repository.create_queued_scan(
        subject=payload.subject,
        sender=payload.sender,
        user_id=user_id,
        evidence={
            "status": "queued",
            "scan_mode": payload.scan_mode,
            "source": "manual_text",
        },
    )
    try:
        scan_queue.enqueue({
            "type": "manual_text",
            "scan_id": scan_id,
            "user_id": user_id,
            "subject": payload.subject,
            "sender": payload.sender,
            "body": payload.body,
            "scan_mode": payload.scan_mode,
        })
    except QueueUnavailable as exc:
        repository.fail_scan(scan_id, f"Redis queue unavailable: {exc}")
        raise HTTPException(status_code=503, detail="Scan queue unavailable") from exc

    scan = repository.get_scan(scan_id, user_id=user_id)
    if scan is None:
        raise HTTPException(status_code=500, detail="Queued scan was not persisted")
    return scan


@app.post("/api/scans/upload", response_model=ScanDetail)
@app.post("/api/scans/screenshot", response_model=ScanDetail)
async def upload_scan(
    file: UploadFile = File(...),
    subject: str = Form("Uploaded SafeMail X Scan"),
    sender: str = Form("uploaded_file"),
    scan_mode: str = Form("balanced"),
    _auth=Depends(require_auth),
):
    user_id = _user_id(_auth)
    filename = file.filename or "upload.bin"
    suffix = Path(filename).suffix.lower()
    if suffix not in SUPPORTED_UPLOAD_EXTENSIONS:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported upload type: {suffix or 'unknown'}",
        )
    if scan_mode not in {"strict", "balanced", "fast"}:
        raise HTTPException(status_code=422, detail="Invalid scan_mode")

    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    if len(file_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Uploaded file exceeds size limit")

    result = inline_scan_service.scan_file(
        filename,
        file.content_type or "application/octet-stream",
        file_bytes,
        user_id,
        subject=subject,
        sender=sender,
        scan_mode=scan_mode,
    )
    
    scan_id = result.scan_id
    scan = repository.get_scan(scan_id, user_id=user_id)
    if scan is not None:
        evidence = dict(scan.get("evidence") or {})
        evidence["upload"] = {
            "filename": filename,
            "content_type": file.content_type or "application/octet-stream",
            "size_bytes": len(file_bytes),
            "source": "screenshot" if suffix in IMAGE_EXTENSIONS else "upload",
        }
        scan["evidence"] = evidence
    return scan


@app.post("/api/scans/{scan_id}/rescan")
def rescan(scan_id: str, _auth=Depends(require_auth)):
    user_id = _user_id(_auth)
    scan = repository.get_scan(scan_id, user_id=user_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    body = scan.get("evidence", {}).get("scan_input", {}).get("body_text")
    if not body:
        raise HTTPException(status_code=409, detail="Original scan text is not available for rescan")
    queued_id = repository.create_queued_scan(
        subject=scan["subject"],
        sender=scan["sender"],
        user_id=user_id,
        evidence={"status": "queued", "source": "rescan", "source_scan_id": scan_id},
    )
    try:
        scan_queue.enqueue({
            "type": "manual_text",
            "scan_id": queued_id,
            "user_id": user_id,
            "subject": scan["subject"],
            "sender": scan["sender"],
            "body": body,
            "scan_mode": settings_state.scan_mode,
        })
    except QueueUnavailable as exc:
        repository.fail_scan(queued_id, f"Redis queue unavailable: {exc}")
        raise HTTPException(status_code=503, detail="Scan queue unavailable") from exc

    queued_scan = repository.get_scan(queued_id, user_id=user_id)
    if queued_scan is None:
        raise HTTPException(status_code=500, detail="Queued rescan was not persisted")
    return queued_scan


@app.get("/api/scans/{scan_id}/report.pdf")
def report_pdf(scan_id: str, _auth=Depends(require_auth)):
    scan = repository.get_scan(scan_id, user_id=_user_id(_auth))
    if not scan or not scan.get("report_pdf"):
        raise HTTPException(status_code=404, detail="PDF report not found")
    path = Path(scan["report_pdf"])
    if not path.exists():
        raise HTTPException(status_code=404, detail="PDF file missing")
    return FileResponse(path, media_type="application/pdf", filename=path.name)


@app.get("/api/scans/{scan_id}/evidence.json")
def report_json(scan_id: str, _auth=Depends(require_auth)):
    scan = repository.get_scan(scan_id, user_id=_user_id(_auth))
    if not scan or not scan.get("report_json"):
        raise HTTPException(status_code=404, detail="Evidence JSON not found")
    path = Path(scan["report_json"])
    if not path.exists():
        raise HTTPException(status_code=404, detail="Evidence file missing")
    return FileResponse(path, media_type="application/json", filename=path.name)


@app.post("/api/scans/{scan_id}/report-link", response_model=ReportDownloadLinkResponse)
def report_download_link(
    scan_id: str,
    request: Request,
    kind: str = Query("pdf", pattern="^(pdf|json)$"),
    _auth=Depends(require_auth),
):
    user_id = _user_id(_auth)
    scan = repository.get_scan(scan_id, user_id=user_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    report_key = "report_pdf" if kind == "pdf" else "report_json"
    if not scan.get(report_key):
        raise HTTPException(status_code=404, detail=f"{kind.upper()} report not found")

    expires_minutes = 10
    token = create_signed_token(
        {"sub": _auth.get("sub", "local"), "uid": user_id, "sid": scan_id, "kind": kind, "purpose": "report_download"},
        expires_minutes=expires_minutes,
    )
    absolute_url = f"{request.url_for('download_report_with_token')}?token={token}"
    return ReportDownloadLinkResponse(url=absolute_url, expires_in_seconds=expires_minutes * 60)


@app.get("/api/reports/download", name="download_report_with_token")
def download_report_with_token(token: str = Query(...)):
    payload = verify_access_token(token)
    if payload.get("purpose") != "report_download":
        raise HTTPException(status_code=401, detail="Invalid report download token")
    scan_id = payload.get("sid")
    user_id = payload.get("uid")
    kind = payload.get("kind")
    if kind not in {"pdf", "json"} or not scan_id or not user_id:
        raise HTTPException(status_code=401, detail="Invalid report download token")

    scan = repository.get_scan(scan_id, user_id=user_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    report_key = "report_pdf" if kind == "pdf" else "report_json"
    path_value = scan.get(report_key)
    if not path_value:
        raise HTTPException(status_code=404, detail=f"{kind.upper()} report not found")
    path = Path(path_value)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report file missing")

    media_type = "application/pdf" if kind == "pdf" else "application/json"
    return FileResponse(path, media_type=media_type, filename=path.name)


@app.post("/api/gmail/connect")
def gmail_connect(_auth=Depends(require_auth)):
    return {
        "status": "oauth_available",
        "message": "Use /api/gmail/oauth/start to connect Gmail for this user.",
    }


@app.get("/api/gmail/oauth/status", response_model=GmailOAuthStatusResponse)
def gmail_oauth_status(_auth=Depends(require_auth)):
    token = repository.get_gmail_token(_user_id(_auth))
    connected = token is not None
    return GmailOAuthStatusResponse(
        connected=connected,
        privacy_mode="label_only",
        scan_label="SafeMail X Scan",
        queued_label="SafeMail X Queued",
        result_labels={"safe": "SafeMail X Safe", "suspicious": "SafeMail X Suspicious", "phishing": "SafeMail X Phishing", "failed": "SafeMail X Failed"}
    )



@app.post("/api/gmail/run-once")
def gmail_run_once(_auth=Depends(require_auth)):
    user_id = _user_id(_auth)
    token_blob = repository.get_gmail_token(user_id)
    if not token_blob:
        raise HTTPException(status_code=400, detail="Gmail not connected")
        
    try:
        from server.gmail_watcher import enqueue_labeled_gmail_messages
        service = build_gmail_service_from_blob(token_blob)
        count = enqueue_labeled_gmail_messages(
            service=service,
            repository=repository,
            scan_queue=scan_queue,
            user_id=user_id,
        )
    except QueueUnavailable as exc:
        raise HTTPException(status_code=503, detail="Scan queue unavailable") from exc
    except RefreshError as exc:
        repository.delete_gmail_token(user_id)
        raise HTTPException(status_code=401, detail="Gmail connection expired. Please reconnect.") from exc
    except Exception as exc:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=502, detail=f"Gmail polling failed: {exc}") from exc
    return {"status": "ok", "enqueued": count, "scanned_label": "SafeMail X Scan"}


@app.get("/api/settings", response_model=SettingsResponse)
def get_settings(_auth=Depends(require_auth)):
    user_id = _user_id(_auth)
    rules = repository.get_trust_rules(user_id)
    if rules:
        return SettingsResponse(
            auto_trust_contacts=rules["auto_trust_contacts"],
            whitelist=rules["whitelist"],
            blacklist=rules["blacklist"]
        )
    return SettingsResponse()


@app.post("/api/settings", response_model=SettingsResponse)
def update_settings(payload: SettingsUpdateRequest, _auth=Depends(require_auth)):
    user_id = _user_id(_auth)
    rules = repository.get_trust_rules(user_id) or {
        "auto_trust_contacts": False,
        "whitelist": [],
        "blacklist": []
    }
    
    if payload.auto_trust_contacts is not None:
        rules["auto_trust_contacts"] = payload.auto_trust_contacts
    if payload.whitelist is not None:
        rules["whitelist"] = payload.whitelist
    if payload.blacklist is not None:
        rules["blacklist"] = payload.blacklist
        
    repository.save_trust_rules(
        user_id,
        rules["auto_trust_contacts"],
        rules["whitelist"],
        rules["blacklist"]
    )
    
    return SettingsResponse(
        auto_trust_contacts=rules["auto_trust_contacts"],
        whitelist=rules["whitelist"],
        blacklist=rules["blacklist"]
    )


# â”€â”€ Feature 5: Adaptive Trust Baseline API Endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.get("/api/settings/adaptive-trust/data")
def get_adaptive_trust_data(_auth=Depends(require_auth)):
    """Return a summary of all trusted sender domains for the current user."""
    user_id = _user_id(_auth)
    if not FEATURE_ADAPTIVE_TRUST_ENABLED or not _ADAPTIVE_TRUST_APP_AVAILABLE:
        return {"enabled": False, "trusted_domains": [], "count": 0}
    entries = list_baseline_summary(user_id)
    return {"enabled": True, "trusted_domains": entries, "count": len(entries)}


@app.delete("/api/settings/adaptive-trust/data")
def clear_adaptive_trust_data(_auth=Depends(require_auth)):
    """Delete all adaptive trust baseline data for the current user."""
    user_id = _user_id(_auth)
    if not FEATURE_ADAPTIVE_TRUST_ENABLED or not _ADAPTIVE_TRUST_APP_AVAILABLE:
        return {"deleted": 0, "message": "Adaptive trust is disabled"}
    deleted = clear_all_baseline_data(user_id)
    return {"deleted": deleted, "message": f"Cleared {deleted} trusted domain record(s)"}


@app.post("/api/notifications/register", response_model=PushTokenResponse)
def register_push_token(payload: PushTokenRequest, _auth=Depends(require_auth)):
    user_id = _user_id(_auth)
    repository.upsert_push_token(payload.token, payload.platform, user_id=user_id)
    return PushTokenResponse(status="registered", token_count=len(repository.list_push_tokens(user_id=user_id)))


@app.websocket("/api/scans/{scan_id}/events")
async def scan_events(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    for stage in SCAN_STAGES:
        await websocket.send_json({
            "scan_id": scan_id,
            "event": "stage_completed",
            "stage": stage,
            "message": f"{stage.replace('_', ' ').title()} completed",
            "payload": {},
        })
    await websocket.send_json({"scan_id": scan_id, "event": "scan_completed"})
    await websocket.close()


def _oauth_redirect_uri_for_request(request: Request) -> str:
    configured = GMAIL_OAUTH_REDIRECT_URI
    configured_host = urlparse(configured).hostname if configured else None
    if configured_host not in {"127.0.0.1", "localhost"}:
        return configured
    return str(request.base_url).rstrip("/") + "/api/gmail/oauth/callback"


@app.get("/api/gmail/oauth/start", response_model=GmailOAuthStartResponse)
def gmail_oauth_start(request: Request, return_url: str | None = Query(None), _auth=Depends(require_auth)):
    redirect_uri = _oauth_redirect_uri_for_request(request)
    state = create_signed_token({
        "sub": _auth.get("sub", "local"),
        "uid": _user_id(_auth),
        "oauth_redirect_uri": redirect_uri,
        "purpose": "gmail",
        "return_url": return_url,
    })
    return GmailOAuthStartResponse(
        authorization_url=build_authorization_url(state, redirect_uri=redirect_uri),
        redirect_uri=redirect_uri,
    )


@app.get("/api/auth/google/start")
def auth_google_start(request: Request, return_url: str | None = Query(None)):
    base_uri = _oauth_redirect_uri_for_request(request).replace("/api/gmail/oauth/callback", "")
    redirect_uri = f"{base_uri}/api/auth/google/callback"
    state = create_signed_token({
        "sub": "guest",
        "uid": "temp_guest",
        "oauth_redirect_uri": redirect_uri,
        "purpose": "auth",
        "return_url": return_url,
    })
    auth_scopes = [
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
    ]
    auth_url = build_authorization_url(state, redirect_uri=redirect_uri, scopes=auth_scopes, credentials_path=SIGNIN_CREDENTIALS_PATH, force_consent=False)
    return {"authorization_url": auth_url, "redirect_uri": redirect_uri}


@app.get("/api/gmail/oauth/callback")
@app.get("/api/auth/google/callback")
def auth_google_callback(code: str = Query(...), state: str = Query(...)):
    payload = verify_access_token(state)
    user_id = payload.get("uid")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid OAuth state")

    purpose = payload.get("purpose", "auth")
    redirect_uri = payload.get("oauth_redirect_uri") or GMAIL_OAUTH_REDIRECT_URI

    backup_scopes = [
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/drive.file",
    ]

    auth_scopes = [
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
    ]

    try:
        if purpose == "backup":
            creds = exchange_code_for_token(code, state, redirect_uri=redirect_uri, scopes=backup_scopes)
        elif purpose == "auth":
            creds = exchange_code_for_token(code, state, redirect_uri=redirect_uri, scopes=auth_scopes, credentials_path=SIGNIN_CREDENTIALS_PATH)
        else:
            creds = exchange_code_for_token(code, state, redirect_uri=redirect_uri)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"OAuth token exchange failed: {exc}") from exc

    if purpose == "gmail":
        # Gmail-only tokens don't have userinfo scopes, just store the token directly
        repository.store_gmail_token(user_id, encode_credentials(creds))
        email = payload.get("sub", "")
        name = "User"
    elif purpose in ("backup", "auth"):
        from googleapiclient.discovery import build
        user_info_service = build("oauth2", "v2", credentials=creds)
        user_info = user_info_service.userinfo().get().execute()
        email = user_info.get("email")
        name = user_info.get("name", "User")

        user = repository.get_user_by_email(email)
        if not user:
            import uuid
            print(
                f"[AUTH] Creating new user record for {email} via Google OAuth "
                f"(no existing record found - this is expected for new users, "
                f"but check for a database reset if this email should already exist)"
            )
            user_id = repository.create_user(
                email=email,
                password_hash="google-oauth-user-" + str(uuid.uuid4()),
                salt="google"
            )
        else:
            user_id = user["id"]

        if purpose == "backup":
            # Store backup token in database
            repository.store_backup_token(user_id, email, name, encode_credentials(creds))
            
            # Trigger initial sync in the background
            from server.google_backup import GoogleBackupService
            import threading
            backup_svc = GoogleBackupService(repository)
            threading.Thread(target=backup_svc.sync_scans_to_drive, args=(user_id,), daemon=True).start()

    access_token = create_access_token(email, user_id, name)
    refresh_token_value = create_refresh_token(email, user_id)
    deep_link_base = payload.get("return_url") or "safemailxai://oauth-callback"
    join_char = "&" if "?" in deep_link_base else "?"
    
    base_params = f"token={access_token}&email={email}&name={name}"
    if refresh_token_value:
        base_params += f"&refresh_token={refresh_token_value}"
    
    if purpose == "auth":
        deep_link_url = f"{deep_link_base}{join_char}{base_params}"
        title_text = "SafeMail X AI Authenticated"
        header_text = "Signed In Successfully!"
        body_text = f"Welcome, {name}! You have successfully signed in as {email}."
    elif purpose == "backup":
        deep_link_url = f"{deep_link_base}{join_char}{base_params}&status=connected&service=backup"
        title_text = "SafeMail X AI Cloud Backup"
        header_text = "Backup Activated!"
        body_text = f"Welcome, {name}! Your SafeMail X AI reports and analysis history are now securely synced to {email}."
    else: # gmail
        deep_link_url = f"{deep_link_base}{join_char}{base_params}&status=connected&service=gmail"
        title_text = "SafeMail X AI Gmail Sync"
        header_text = "Gmail Connected!"
        body_text = f"Welcome, {name}! SafeMail X AI is now successfully configured to scan and secure your Gmail inbox at {email}."

    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{title_text}</title>
        <style>
            body {{
                background-color: #000000;
                color: #f2eafd;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }}
            .card {{
                background: rgba(255, 255, 255, 0.03);
                border: 1px solid rgba(0, 240, 255, 0.16);
                border-radius: 20px;
                padding: 40px;
                text-align: center;
                max-width: 400px;
                box-shadow: 0 16px 20px rgba(0,0,0,0.8);
                backdrop-filter: blur(20px);
            }}
            .icon {{
                font-size: 48px;
                color: #6fd9b8;
                margin-bottom: 20px;
            }}
            h1 {{
                font-size: 22px;
                margin-bottom: 10px;
                font-weight: 700;
                letter-spacing: 0.5px;
            }}
            p {{
                color: #83808c;
                font-size: 14px;
                line-height: 1.6;
                margin-bottom: 30px;
            }}
            .btn {{
                background: #3b41bf;
                color: white;
                border: none;
                padding: 12px 30px;
                border-radius: 12px;
                font-weight: 600;
                cursor: pointer;
                text-decoration: none;
                display: inline-block;
            }}
        </style>
    </head>
    <body>
        <div class="card">
            <div class="icon">&#10004;</div>
            <h1>{header_text}</h1>
            <p>{body_text}</p>
            <p style="color: #6fd9b8; font-size: 12px; margin-top: -15px; margin-bottom: 25px;">Redirecting back to app...</p>
            <a class="btn" href="{deep_link_url}" id="redirect-link">Return to App</a>
        </div>
        <script>
            window.onload = function() {{
                setTimeout(function() {{
                    var link = document.getElementById('redirect-link');
                    if (link) link.click();
                }}, 800);
            }};
        </script>
    </body>
    </html>
    """)


@app.post("/api/gmail/labels/ensure")
def gmail_labels_ensure(_auth=Depends(require_auth)):
    user_id = _user_id(_auth)
    token_blob = repository.get_gmail_token(user_id)
    if not token_blob:
        raise HTTPException(status_code=400, detail="Gmail is not connected")
    service = build_gmail_service_from_blob(token_blob)
    if ensure_safemailx_labels is None:
        raise HTTPException(status_code=501, detail="Gmail labels module not available")
    labels = ensure_safemailx_labels(service)
    return {
        "privacy_mode": "label_only",
        "labels": {key: value["name"] for key, value in labels.items()},
    }


@app.post("/api/scans/sms", response_model=ScanDetail)
def scan_sms(payload: ManualSmsScanRequest, _auth=Depends(require_auth)):
    user_id = _user_id(_auth)
    sender = payload.sender_number or "Unknown"
    subject = f"SMS from {sender}"
    body_text = payload.text
    queued_id = repository.create_queued_scan(
        subject=subject, sender=sender, user_id=user_id,
        evidence={"status": "queued", "source": "sms"},
    )
    try:
        scan_queue.enqueue({
            "type": "manual_text",
            "scan_id": queued_id,
            "user_id": user_id,
            "subject": subject,
            "sender": sender,
            "body": body_text,
            "source_type": "sms",
            "scan_mode": settings_state.scan_mode,
        })
    except QueueUnavailable as exc:
        repository.fail_scan(queued_id, f"Redis queue unavailable: {exc}")
        raise HTTPException(status_code=503, detail="Scan queue unavailable") from exc
    scan = repository.get_scan(queued_id, user_id=user_id)
    if scan is None:
        raise HTTPException(status_code=500, detail="Queued SMS scan was not persisted")
    return scan


@app.post("/api/scans/url", response_model=ScanDetail)
def scan_url(payload: UrlScanRequest, _auth=Depends(require_auth)):
    user_id = _user_id(_auth)
    url_str = str(payload.url)
    subject = f"URL Scan: {url_str[:80]}"
    sender = "url_checker"
    queued_id = repository.create_queued_scan(
        subject=subject, sender=sender, user_id=user_id,
        evidence={"status": "queued", "source": "url"},
    )
    try:
        scan_queue.enqueue({
            "type": "manual_text",
            "scan_id": queued_id,
            "user_id": user_id,
            "subject": subject,
            "sender": sender,
            "body": f"Please analyze this URL for threats: {url_str}",
            "source_type": "url",
            "scan_mode": settings_state.scan_mode,
        })
    except QueueUnavailable as exc:
        repository.fail_scan(queued_id, f"Redis queue unavailable: {exc}")
        raise HTTPException(status_code=503, detail="Scan queue unavailable") from exc
    scan = repository.get_scan(queued_id, user_id=user_id)
    if scan is None:
        raise HTTPException(status_code=500, detail="Queued URL scan was not persisted")
    return scan


@app.get("/api/notifications/preferences", response_model=NotificationPreferences)
def get_notification_preferences(_auth=Depends(require_auth)):
    prefs = repository.get_notification_preferences(_user_id(_auth))
    if prefs is None:
        return NotificationPreferences(critical_alerts=True, weekly_summary=True)
    return NotificationPreferences(**prefs)


@app.put("/api/notifications/preferences", response_model=NotificationPreferences)
def update_notification_preferences(payload: NotificationPreferences, _auth=Depends(require_auth)):
    user_id = _user_id(_auth)
    repository.upsert_notification_preferences(
        user_id=user_id,
        critical_alerts=payload.critical_alerts,
        weekly_summary=payload.weekly_summary,
    )
    prefs = repository.get_notification_preferences(user_id)
    if prefs is None:
        return NotificationPreferences(critical_alerts=True, weekly_summary=True)
    return NotificationPreferences(**prefs)


@app.post("/api/instant/sms", response_model=InstantScanResult)
def instant_scan_sms(payload: InstantSmsScanRequest, _auth=Depends(require_auth)):
    return inline_scan_service.scan_sms(payload, _user_id(_auth))

@app.post("/api/instant/url", response_model=InstantScanResult)
def instant_scan_url(payload: InstantUrlScanRequest, _auth=Depends(require_auth)):
    return inline_scan_service.scan_url(payload, _user_id(_auth))

@app.post("/api/instant/file", response_model=InstantScanResult)
async def instant_scan_file(
    file: UploadFile = File(...),
    scan_mode: str = Form("balanced"),
    _auth=Depends(require_auth)
):
    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    if len(file_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Uploaded file exceeds size limit")
    return inline_scan_service.scan_file(
        file.filename or "upload.bin",
        file.content_type or "application/octet-stream",
        file_bytes,
        _user_id(_auth),
        scan_mode=scan_mode,
    )


import urllib.request
import xml.etree.ElementTree as ET

@app.get("/api/threat-bulletin")
def get_threat_bulletin():
    try:
        url = "https://feeds.feedburner.com/TheHackersNews"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            xml_data = response.read()
        root = ET.fromstring(xml_data)
        items = []
        for item in root.findall('.//item')[:10]:
            title = item.findtext('title', '')
            link = item.findtext('link', '')
            if title and link:
                items.append({"title": title, "link": link})
        return {"items": items}
    except Exception:
        return {"items": []}


@app.get("/api/backup/oauth/status")
def backup_oauth_status(_auth=Depends(require_auth)):
    user_id = _user_id(_auth)
    token = repository.get_backup_token(user_id) if hasattr(repository, 'get_backup_token') else None
    if token:
        return {"connected": True, "email": token.get("email"), "name": token.get("name"), "last_sync": token.get("last_sync")}
    return {"connected": False, "email": None, "name": None, "last_sync": None}


@app.get("/api/backup/oauth/start", response_model=GmailOAuthStartResponse)
def backup_oauth_start(request: Request, return_url: str | None = Query(None), _auth=Depends(require_auth)):
    base_uri = _oauth_redirect_uri_for_request(request).replace("/api/gmail/oauth/callback", "")
    redirect_uri = f"{base_uri}/api/auth/google/callback"
    state = create_signed_token({
        "sub": _auth.get("sub", "local"),
        "uid": _user_id(_auth),
        "oauth_redirect_uri": redirect_uri,
        "purpose": "backup",
        "return_url": return_url,
    })
    backup_scopes = [
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/drive.file",
    ]
    return GmailOAuthStartResponse(
        authorization_url=build_authorization_url(
            state,
            redirect_uri=redirect_uri,
            scopes=backup_scopes,
            credentials_path=SIGNIN_CREDENTIALS_PATH,
            force_consent=True,
        ),
        redirect_uri=redirect_uri,
    )


@app.post("/api/backup/sync")
def backup_sync(_auth=Depends(require_auth)):
    user_id = _user_id(_auth)
    token = repository.get_backup_token(user_id) if hasattr(repository, "get_backup_token") else None
    if not token:
        raise HTTPException(status_code=400, detail="Google Drive backup is not connected")
    from server.google_backup import GoogleBackupService
    backup_svc = GoogleBackupService(repository)
    return backup_svc.sync_scans_to_drive(user_id)


@app.post("/api/backup/oauth/disconnect")
def backup_oauth_disconnect(_auth=Depends(require_auth)):
    user_id = _user_id(_auth)
    if hasattr(repository, "delete_backup_token"):
        repository.delete_backup_token(user_id)
    return {"status": "disconnected"}


from server.google_contacts import exchange_code_for_token as gc_exchange_code_for_token, fetch_user_info, fetch_contacts, router as contacts_router
app.include_router(contacts_router)

@app.get("/api/auth/google-contacts/callback")
async def google_contacts_callback(code: str, state: str = None):
    # This callback doesn't have the user's JWT because it's a redirect from Google
    # For a real implementation, 'state' would contain the JWT or session token to identify the user.
    # In this local version, we assume user_id="local" or extract it from state if we set it.
    user_id = "local"
    if state and state.startswith("user_"):
        user_id = state.replace("user_", "")
        
    try:
        token_data = await gc_exchange_code_for_token(code)
        access_token = token_data.get("access_token")
        
        # Get user profile
        user_info = await fetch_user_info(access_token)
        email = user_info.get("email", "")
        name = user_info.get("name", "User")
        
        # Store the token (in a real app, securely encrypt it!)
        import json
        repository.store_google_contacts_token(user_id, email, name, json.dumps(token_data))
        
        # We can also fetch their contacts immediately to populate the cache/whitelist
        # but that can be done asynchronously. For now we just return success.
        
        return fastapi.responses.RedirectResponse(url="http://localhost:3000/settings?contacts_connected=true")
    except Exception as exc:
        return fastapi.responses.RedirectResponse(url=f"http://localhost:3000/settings?contacts_error=failed")

@app.delete("/api/auth/google-contacts")
def disconnect_google_contacts(_auth=Depends(require_auth)):
    user_id = _user_id(_auth)
    repository.delete_google_contacts_token(user_id)
    return {"status": "ok"}

@app.get("/api/auth/google-contacts/status")
def google_contacts_status(_auth=Depends(require_auth)):
    user_id = _user_id(_auth)
    record = repository.get_google_contacts_token(user_id)
    return {"connected": record is not None, "email": record["email"] if record else None}


# ===========================================================================
# Feature: SMS Bot Integration — WhatsApp (Twilio) + Telegram Webhooks
# All new routes are /api/webhooks/* and are fully additive.
# Existing routes are untouched.
# ===========================================================================

try:
    from server.sms_webhook_handler import handle_whatsapp_webhook, handle_telegram_webhook, register_telegram_webhook
    from server.settings import FEATURE_WHATSAPP_BOT_ENABLED, FEATURE_TELEGRAM_BOT_ENABLED, BACKEND_URL
    _SMS_BOT_AVAILABLE = True
except ImportError:
    _SMS_BOT_AVAILABLE = False
    FEATURE_WHATSAPP_BOT_ENABLED = False
    FEATURE_TELEGRAM_BOT_ENABLED = False


@app.on_event("startup")
def _register_telegram_webhook_on_startup():
    """Register Telegram webhook URL with BotFather on every cold start."""
    if not _SMS_BOT_AVAILABLE or not FEATURE_TELEGRAM_BOT_ENABLED:
        return
    import threading as _threading
    _threading.Thread(
        target=register_telegram_webhook,
        args=(BACKEND_URL,),
        daemon=True,
        name="telegram-webhook-reg",
    ).start()


@app.post("/api/webhooks/whatsapp", include_in_schema=False)
async def whatsapp_webhook(request: Request):
    """
    Inbound WhatsApp messages via Twilio.
    Twilio sends application/x-www-form-urlencoded POST.
    Always returns TwiML XML (200 OK) — never 4xx/5xx to Twilio.
    """
    from fastapi.responses import Response as _Response
    if not _SMS_BOT_AVAILABLE or not FEATURE_WHATSAPP_BOT_ENABLED:
        return _Response(
            content='<?xml version="1.0"?><Response></Response>',
            media_type="application/xml",
        )
    form_data = dict(await request.form())
    form_str = {k: str(v) for k, v in form_data.items()}
    x_sig = request.headers.get("X-Twilio-Signature", "")
    webhook_url = str(request.url)
    twiml = handle_whatsapp_webhook(
        form_data=form_str,
        x_twilio_signature=x_sig,
        webhook_url=webhook_url,
        inline_scan_service=inline_scan_service,
    )
    return _Response(content=twiml, media_type="application/xml")


@app.post("/api/webhooks/telegram", include_in_schema=False)
async def telegram_webhook(request: Request):
    """
    Inbound Telegram updates via webhook.
    Telegram requires a 200 OK response immediately.
    Actual reply is sent asynchronously via Telegram Bot API.
    """
    if not _SMS_BOT_AVAILABLE or not FEATURE_TELEGRAM_BOT_ENABLED:
        return {"ok": True}
    try:
        update = await request.json()
    except Exception:
        return {"ok": True}
    x_secret = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
    import asyncio as _asyncio
    import concurrent.futures as _cf
    loop = _asyncio.get_event_loop()
    loop.run_in_executor(
        None,
        handle_telegram_webhook,
        update,
        x_secret,
        inline_scan_service,
    )
    return {"ok": True}
