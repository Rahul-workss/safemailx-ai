from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, UploadFile, WebSocket
from fastapi.responses import FileResponse

from server.auth import create_access_token, require_auth, validate_login, verify_access_token
from server.gmail_watcher import enqueue_unread_forwarded_messages
from server.gmail_oauth import build_authorization_url, encode_credentials, exchange_code_for_token
from server.health import build_health, check_llm_health
from server.mailer import send_password_reset_email
from server.queue import QueueUnavailable, ScanQueue
from server.readiness import build_readiness
from server.repository import ScanRepository
from server.scan_service import SCAN_STAGES, ScanService
from server.schemas import (
    DashboardResponse,
    ForgotPasswordRequest,
    GmailOAuthStartResponse,
    GmailOAuthStatusResponse,
    HealthResponse,
    LoginRequest,
    ManualScanRequest,
    PushTokenRequest,
    PushTokenResponse,
    ReadinessResponse,
    ResetPasswordRequest,
    ScanDetail,
    ScanSummary,
    SettingsResponse,
    TokenResponse,
)
from server.settings import MAX_UPLOAD_BYTES
from server.uploads import SUPPORTED_UPLOAD_EXTENSIONS, extract_upload_text


app = FastAPI(title="TrustMail AI API", version="0.1.0")
repository = ScanRepository()
scan_service = ScanService(repository)
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
    return TokenResponse(access_token=create_access_token(user["email"], user["id"]))


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
async def upload_scan(
    file: UploadFile = File(...),
    subject: str = Form("Uploaded TrustMail Scan"),
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

    extracted_text, extraction_notes = extract_upload_text(filename, file_bytes)
    body = extracted_text or f"Uploaded attachment {filename} contained no extractable text."
    scan = scan_service.run_manual_text_scan(
        subject=subject or filename,
        sender=sender or "uploaded_file",
        body=body,
        scan_mode=scan_mode,
        user_id=user_id,
        attachments=[{"filename": filename, "bytes": file_bytes}],
        metadata={
            "upload": {
                "filename": filename,
                "content_type": file.content_type,
                "size_bytes": len(file_bytes),
                "extraction_notes": extraction_notes,
                "extracted_text_length": len(extracted_text),
            }
        },
    )
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


@app.post("/api/gmail/connect")
def gmail_connect(_auth=Depends(require_auth)):
    return {
        "status": "oauth_available",
        "message": "Use /api/gmail/oauth/start to connect Gmail for this user.",
    }


@app.get("/api/gmail/oauth/status", response_model=GmailOAuthStatusResponse)
def gmail_oauth_status(_auth=Depends(require_auth)):
    return GmailOAuthStatusResponse(connected=repository.get_gmail_token(_user_id(_auth)) is not None)


@app.get("/api/gmail/oauth/start", response_model=GmailOAuthStartResponse)
def gmail_oauth_start(_auth=Depends(require_auth)):
    state = create_access_token(_auth.get("sub", "local"), _user_id(_auth))
    return GmailOAuthStartResponse(authorization_url=build_authorization_url(state))


@app.get("/api/gmail/oauth/callback")
def gmail_oauth_callback(code: str = Query(...), state: str = Query(...)):
    payload = verify_access_token(state)
    user_id = payload.get("uid")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid OAuth state")
    creds = exchange_code_for_token(code, state)
    repository.store_gmail_token(user_id, encode_credentials(creds))
    return {"status": "connected"}


@app.post("/api/gmail/run-once")
def gmail_run_once(_auth=Depends(require_auth)):
    try:
        count = enqueue_unread_forwarded_messages(
            repository=repository,
            scan_queue=scan_queue,
            user_id=_user_id(_auth),
        )
    except QueueUnavailable as exc:
        raise HTTPException(status_code=503, detail="Scan queue unavailable") from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Gmail polling failed: {exc}") from exc
    return {"status": "ok", "enqueued": count}


@app.get("/api/settings", response_model=SettingsResponse)
def get_settings(_auth=Depends(require_auth)):
    return settings_state


@app.post("/api/settings", response_model=SettingsResponse)
def update_settings(payload: SettingsResponse, _auth=Depends(require_auth)):
    global settings_state
    settings_state = payload
    return settings_state


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
