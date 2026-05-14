from typing import Any, Literal

from pydantic import BaseModel, Field


Verdict = Literal["legitimate", "suspicious", "phishing", "queued", "failed"]
ScanMode = Literal["strict", "balanced", "fast"]


class LoginRequest(BaseModel):
    email: str
    password: str


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ManualScanRequest(BaseModel):
    subject: str = "Manual TrustMail Scan"
    sender: str = "manual_input"
    body: str = Field(..., min_length=1)
    scan_mode: ScanMode = "balanced"


class ScanSummary(BaseModel):
    id: str
    subject: str
    sender: str
    final_label: Verdict
    final_score: float
    llm_used: bool = False
    degraded: bool = False
    created_at: str


class ScanDetail(ScanSummary):
    evidence: dict[str, Any] = Field(default_factory=dict)
    report_pdf: str | None = None
    report_json: str | None = None


class HealthResponse(BaseModel):
    api: str
    database: str
    redis: str
    ocr: str
    llm: str
    gmail_watcher: str


class ReadinessItem(BaseModel):
    key: str
    status: Literal["ready", "warning", "missing"]
    message: str


class ReadinessResponse(BaseModel):
    environment: Literal["local", "production"]
    ready: bool
    items: list[ReadinessItem]


class DashboardResponse(BaseModel):
    total_scans: int
    safe_count: int
    suspicious_count: int
    phishing_count: int
    latest_scan: ScanSummary | None = None
    health: HealthResponse


class SettingsResponse(BaseModel):
    scan_mode: ScanMode = "balanced"
    retention_days: int | None = None
    notifications_enabled: bool = True
    debug_enabled: bool = False


class PushTokenRequest(BaseModel):
    token: str = Field(..., min_length=10)
    platform: str = "unknown"


class PushTokenResponse(BaseModel):
    status: str
    token_count: int


class GmailOAuthStartResponse(BaseModel):
    authorization_url: str


class GmailOAuthStatusResponse(BaseModel):
    connected: bool


class ScanEvent(BaseModel):
    scan_id: str
    event: str
    stage: str | None = None
    message: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
