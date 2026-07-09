from typing import Any, Literal

from pydantic import BaseModel, Field


Verdict = Literal["legitimate", "suspicious", "phishing", "queued", "failed"]
ScanMode = Literal["strict", "balanced", "fast"]
ScanFeedbackChoice = Literal["correct", "false_positive", "false_negative"]


class LoginRequest(BaseModel):
    email: str
    password: str


class SendOtpRequest(BaseModel):
    email: str


class RegisterRequest(BaseModel):
    email: str
    name: str = "User"
    password: str = Field(..., min_length=8)
    otp: str = Field(..., min_length=6, max_length=6)


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ManualScanRequest(BaseModel):
    subject: str = "Manual SafeMail X Scan"
    sender: str = "manual_input"
    body: str = Field(..., min_length=1)
    scan_mode: ScanMode = "balanced"


class ManualSmsScanRequest(BaseModel):
    text: str = Field(..., min_length=1)
    sender_number: str | None = None
    scan_mode: ScanMode = "balanced"


class ScanSummary(BaseModel):
    id: str
    subject: str
    sender: str
    final_label: Verdict
    final_score: float
    llm_used: bool = False
    degraded: bool = False
    report_pdf: str | None = None
    report_json: str | None = None
    created_at: str


class ScanDetail(ScanSummary):
    evidence: dict[str, Any] = Field(default_factory=dict)


class ScanFeedbackRequest(BaseModel):
    feedback: ScanFeedbackChoice
    note: str | None = Field(default=None, max_length=500)


class ScanFeedbackResponse(BaseModel):
    scan_id: str
    feedback: ScanFeedbackChoice
    note: str | None = None
    updated_at: str


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
    auto_trust_contacts: bool = False
    whitelist: list[str] = Field(default_factory=list)
    blacklist: list[str] = Field(default_factory=list)


class SettingsUpdateRequest(BaseModel):
    auto_trust_contacts: bool | None = None
    whitelist: list[str] | None = None
    blacklist: list[str] | None = None


class PushTokenRequest(BaseModel):
    token: str = Field(..., min_length=10)
    platform: str = "unknown"

class PushTokenResponse(BaseModel):
    status: str
    token_count: int


class ReportDownloadLinkResponse(BaseModel):
    url: str
    expires_in_seconds: int


class GmailOAuthStartResponse(BaseModel):
    authorization_url: str
    redirect_uri: str


class GmailOAuthStatusResponse(BaseModel):
    connected: bool
    privacy_mode: str = "label_only"
    scan_label: str = ""
    queued_label: str = ""
    result_labels: dict[str, str] = {}


class ScanEvent(BaseModel):
    scan_id: str
    event: str
    stage: str | None = None
    message: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)

class GmailLabelsResponse(BaseModel):
    privacy_mode: str = "label_only"
    labels: dict[str, str]


class UrlScanRequest(BaseModel):
    url: str = Field(..., min_length=8)
    scan_mode: ScanMode = "balanced"


class NotificationPreferences(BaseModel):
    critical_alerts: bool = True
    weekly_summary: bool = True


class InstantSmsScanRequest(BaseModel):
    text: str = Field(..., min_length=1)
    sender_number: str | None = None
    scan_mode: ScanMode = "balanced"

class InstantUrlScanRequest(BaseModel):
    url: str = Field(..., min_length=8)
    scan_mode: ScanMode = "balanced"

class InstantFileScanRequest(BaseModel):
    filename: str
    content_type: str = "application/octet-stream"
    scan_mode: ScanMode = "balanced"

class QuickScanSignal(BaseModel):
    name: str
    description: str
    severity: Literal["low", "medium", "high", "critical"]
    confidence: float

class QuickScanArtifacts(BaseModel):
    urls: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    phone_numbers: list[str] = Field(default_factory=list)
    email_addresses: list[str] = Field(default_factory=list)
    sender_id: str | None = None
    sender_type: str | None = None
    brand_claims: list[str] = Field(default_factory=list)
    urgency_markers: list[str] = Field(default_factory=list)
    intent_markers: list[str] = Field(default_factory=list)
    submitted_url: str | None = None
    normalized_url: str | None = None
    final_url: str | None = None
    final_domain: str | None = None
    detected_type: str | None = None
    detected_file_type: str | None = None
    filename: str | None = None
    extraction_method: str | None = None
    parser_quality: str | None = None
    redirect_chain: list[str] = Field(default_factory=list)
    landing_page_title: str | None = None
    reputation_hits: list[str] = Field(default_factory=list)
    extracted_urls: list[str] = Field(default_factory=list)
    document_malware_risk: float | None = None
    social_engineering_risk: float | None = None
    embedded_active_content: list[str] = Field(default_factory=list)
    attachment_names: list[str] = Field(default_factory=list)

class InstantScanResult(BaseModel):
    scan_id: str
    channel: Literal["sms", "url", "file"]
    verdict: Verdict
    risk_score: float
    confidence: float
    summary: str
    top_signals: list[QuickScanSignal] = Field(default_factory=list)
    artifacts: QuickScanArtifacts = Field(default_factory=QuickScanArtifacts)
    recommended_action: str
    degraded: bool = False
    saved_to_history: bool = True
    llm_reasoning: str | None = None
    evidence_quality: Literal["high", "medium", "low"] = "medium"
    analysis_mode: Literal["local_only", "hybrid_cloud"] = "local_only"
    external_checks_used: list[str] = Field(default_factory=list)
    external_checks_failed: list[str] = Field(default_factory=list)
    degraded_reasons: list[str] = Field(default_factory=list)
    privacy_notice: str | None = None
    scan_category: str | None = None
    structural_score: float | None = None
    reputation_score: float | None = None
    llm_score: float | None = None
