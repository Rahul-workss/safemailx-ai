import { getAuthToken, setAuthToken } from "./auth";

let apiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8080";
const DEFAULT_TIMEOUT_MS = 12000;

async function apiFetch(path: string, options: RequestInit = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  const headers = {
    "Bypass-Tunnel-Reminder": "true",
    ...(options.headers || {})
  } as HeadersInit;

  try {
    const response = await fetch(`${apiBaseUrl}${path}`, {
      ...options,
      headers,
      signal: controller.signal
    });
    
    if (response.status === 401) {
      if (typeof window !== "undefined") {
        localStorage.removeItem("safemail_token");
        if (!window.location.pathname.startsWith("/auth")) {
          window.location.href = "/auth/login";
        }
      }
    }
    
    return response;
  } catch (error: any) {
    if (error?.name === "AbortError") {
      throw new Error(`Request timed out. Check the API server URL: ${apiBaseUrl}`);
    }
    throw new Error(`Network request failed. Check the API server URL: ${apiBaseUrl}`);
  } finally {
    clearTimeout(timeoutId);
  }
}

function authHeaders(extra: Record<string, string> = {}) {
  const headers: Record<string, string> = {
    "Bypass-Tunnel-Reminder": "true",
    ...extra
  };
  const token = getAuthToken();
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

// Re-export types from the mobile app
export type Health = {
  api: string;
  database: string;
  redis: string;
  ocr: string;
  llm: string;
  gmail_watcher: string;
};

export type ScanSummary = {
  id: string;
  subject: string;
  sender: string;
  final_label: "legitimate" | "suspicious" | "phishing" | "queued" | "failed";
  final_score: number;
  llm_used: boolean;
  degraded: boolean;
  report_pdf?: string | null;
  report_json?: string | null;
  created_at: string;
};

export type QuickScanSignal = {
  name: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  confidence: number;
};

export type QuickScanArtifacts = {
  urls?: string[];
  domains?: string[];
  phone_numbers?: string[];
  email_addresses?: string[];
  sender_id?: string | null;
  sender_type?: string | null;
  brand_claims?: string[];
  urgency_markers?: string[];
  intent_markers?: string[];
  submitted_url?: string | null;
  normalized_url?: string | null;
  final_url?: string | null;
  final_domain?: string | null;
  detected_type?: string | null;
  detected_file_type?: string | null;
  filename?: string | null;
  extraction_method?: string | null;
  parser_quality?: string | null;
  redirect_chain?: string[];
  landing_page_title?: string | null;
  reputation_hits?: string[];
  extracted_urls?: string[];
  document_malware_risk?: number | null;
  social_engineering_risk?: number | null;
  embedded_active_content?: string[];
  attachment_names?: string[];
};

export type InstantScanResult = {
  scan_id: string;
  channel: "sms" | "url" | "file";
  verdict: "legitimate" | "suspicious" | "phishing";
  risk_score: number;
  confidence: number;
  summary: string;
  top_signals: QuickScanSignal[];
  artifacts: QuickScanArtifacts;
  recommended_action: string;
  degraded: boolean;
  saved_to_history: boolean;
  llm_reasoning?: string;
  evidence_quality?: "high" | "medium" | "low";
  analysis_mode?: "local_only" | "hybrid_cloud";
  external_checks_used?: string[];
  external_checks_failed?: string[];
  degraded_reasons?: string[];
  privacy_notice?: string | null;
  scan_category?: string | null;
  structural_score?: number | null;
  reputation_score?: number | null;
  llm_score?: number | null;
};

export type ScanFeedbackChoice = "correct" | "false_positive" | "false_negative";

export type ScanFeedbackResult = {
  scan_id: string;
  feedback: ScanFeedbackChoice;
  note?: string | null;
  updated_at: string;
};

export type ScanDetail = ScanSummary & {
  evidence: Record<string, any>;
};

export type GmailStatus = {
  connected: boolean;
  privacy_mode: string;
  scan_label: string;
  queued_label: string;
  result_labels: Record<string, string>;
};

export type NotificationPreferences = {
  critical_alerts: boolean;
  weekly_summary: boolean;
};

export async function fetchHealth(): Promise<Health> {
  const response = await apiFetch("/api/health", {}, 6000);
  if (!response.ok) throw new Error("Health check failed");
  return response.json();
}

export async function login(email: string, password: string): Promise<string> {
  const response = await apiFetch("/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password })
  }, 10000);
  if (!response.ok) throw new Error("Login failed");
  const payload = await response.json();
  setAuthToken(payload.access_token);
  return payload.access_token;
}

export async function sendRegistrationOtp(email: string): Promise<void> {
  const response = await apiFetch("/auth/send-otp", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email })
  }, 10000);
  
  if (!response.ok) {
    let errMsg = "Failed to send OTP";
    try {
        const errorData = await response.json();
        if (errorData.detail) {
          errMsg = Array.isArray(errorData.detail) 
            ? errorData.detail.map((e: any) => e.msg).join(", ")
            : typeof errorData.detail === "string" ? errorData.detail : JSON.stringify(errorData.detail);
        }
    } catch (e) {}
    throw new Error(errMsg);
  }
}

export async function register(email: string, name: string, password: string, otp: string): Promise<string> {
  const response = await apiFetch("/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, name, password, otp })
  }, 10000);
  
  if (!response.ok) {
    let errMsg = "Registration failed";
    try {
        const errorData = await response.json();
        if (errorData.detail) {
          errMsg = Array.isArray(errorData.detail) 
            ? errorData.detail.map((e: any) => e.msg).join(", ")
            : typeof errorData.detail === "string" ? errorData.detail : JSON.stringify(errorData.detail);
        }
    } catch (e) {}
    throw new Error(errMsg);
  }
  
  const payload = await response.json();
  setAuthToken(payload.access_token);
  return payload.access_token;
}

export async function requestPasswordReset(email: string): Promise<void> {
  const response = await apiFetch("/auth/forgot-password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email })
  }, 10000);
  if (!response.ok) throw new Error("Password reset request failed");
}

export async function confirmPasswordReset(token: string, newPassword: string): Promise<void> {
  const response = await apiFetch("/auth/reset-password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, new_password: newPassword })
  }, 10000);
  if (!response.ok) {
    let errMsg = "Password reset failed";
    try {
      const errorData = await response.json();
      if (typeof errorData.detail === "string") {
        errMsg = errorData.detail;
      }
    } catch {}
    throw new Error(errMsg);
  }
}

export async function fetchScans(): Promise<ScanSummary[]> {
  const response = await apiFetch("/api/scans", {
    headers: authHeaders()
  });
  if (!response.ok) throw new Error("Scan list failed");
  return response.json();
}

export async function fetchScanDetail(scanId: string): Promise<ScanDetail> {
  const response = await apiFetch(`/api/scans/${scanId}`, {
    headers: authHeaders()
  });
  if (!response.ok) throw new Error("Failed to fetch scan detail");
  return response.json();
}

export async function submitScanFeedback(
  scanId: string,
  feedback: ScanFeedbackChoice,
  note?: string
): Promise<ScanFeedbackResult> {
  const response = await apiFetch(`/api/scans/${scanId}/feedback`, {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ feedback, note: note || null })
  }, 10000);
  if (!response.ok) throw new Error("Failed to save scan feedback");
  return response.json();
}

export async function createManualScan(body: string): Promise<ScanSummary> {
  const payload = {
    subject: "Web Manual Scan",
    sender: "web-app",
    body,
    scan_mode: "balanced"
  };

  let response = await apiFetch("/api/scans/manual/queue", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(payload)
  }, 15000);

  if (response.status === 503) {
    response = await apiFetch("/api/scans/manual", {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify(payload)
    }, 45000);
  }

  if (!response.ok) throw new Error("Manual scan failed");
  return response.json();
}

export async function scanSms(text: string, senderNumber?: string): Promise<InstantScanResult> {
  const payload = {
    text,
    sender_number: senderNumber || null,
    scan_mode: "balanced"
  };

  const response = await apiFetch("/api/instant/sms", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(payload)
  }, 15000);

  if (!response.ok) throw new Error("SMS scan failed");
  return response.json();
}

export async function uploadScanFile(file: File): Promise<ScanSummary> {
  return uploadMultipartScan("/api/scans/upload", file, "Uploaded file");
}

export async function scanInstantFile(file: File): Promise<InstantScanResult> {
  const form = new FormData();
  form.append("file", file);
  form.append("scan_mode", "balanced");

  const response = await apiFetch("/api/instant/file", {
    method: "POST",
    headers: authHeaders(),
    body: form
  }, 60000);
  if (!response.ok) throw new Error("File scan failed");
  return response.json();
}

export async function scanScreenshot(file: File): Promise<InstantScanResult> {
  const detail = await uploadMultipartScan("/api/scans/screenshot", file, "Screenshot Scan");
  const response = await apiFetch(`/api/scans/${detail.id}`, {
    headers: authHeaders()
  }, 30000);
  if (!response.ok) throw new Error("Screenshot scan detail lookup failed");
  const fullDetail: ScanDetail = await response.json();
  return toInlineResult(fullDetail, "file");
}

async function uploadMultipartScan(path: string, file: File, subjectPrefix: string): Promise<ScanSummary> {
  const form = new FormData();
  form.append("subject", `${subjectPrefix}: ${file.name}`);
  form.append("sender", "web-upload");
  form.append("file", file);

  const response = await apiFetch(path, {
    method: "POST",
    headers: authHeaders(),
    body: form
  }, 60000);
  if (!response.ok) throw new Error("Upload scan failed");
  return response.json();
}

export async function scanUrl(url: string): Promise<InstantScanResult> {
  const response = await apiFetch("/api/instant/url", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ url, scan_mode: "balanced" })
  }, 20000);
  if (!response.ok) throw new Error("URL scan failed");
  return response.json();
}

function toInlineResult(detail: ScanDetail, channel: "sms" | "url" | "file"): InstantScanResult {
  const evidence = detail.evidence || {};
  return {
    scan_id: detail.id,
    channel,
    verdict: detail.final_label === "queued" || detail.final_label === "failed" ? "suspicious" : detail.final_label,
    risk_score: Math.round((detail.final_score || 0) * 100),
    confidence: typeof evidence.confidence === "number" ? evidence.confidence : 0.8,
    summary: evidence.summary || "Analysis complete.",
    top_signals: Array.isArray(evidence.top_signals) ? evidence.top_signals : [],
    artifacts: evidence.artifacts || {},
    recommended_action: evidence.recommended_action || "Review the extracted evidence before taking action.",
    degraded: Boolean(detail.degraded),
    saved_to_history: true,
    llm_reasoning: evidence.llm_reasoning || undefined,
    evidence_quality: evidence.evidence_quality || undefined,
    analysis_mode: evidence.analysis_mode || undefined,
    external_checks_used: Array.isArray(evidence.external_checks_used) ? evidence.external_checks_used : [],
    external_checks_failed: Array.isArray(evidence.external_checks_failed) ? evidence.external_checks_failed : [],
    degraded_reasons: Array.isArray(evidence.degraded_reasons) ? evidence.degraded_reasons : [],
    privacy_notice: typeof evidence.privacy_notice === "string" ? evidence.privacy_notice : undefined,
    scan_category: typeof evidence.scan_category === "string" ? evidence.scan_category : undefined,
  };
}

export async function startGoogleAuthLogin(returnUrl?: string): Promise<string> {
  const url = returnUrl ? `/api/auth/google/start?return_url=${encodeURIComponent(returnUrl)}` : "/api/auth/google/start";
  const response = await apiFetch(url);
  if (!response.ok) throw new Error("Google Sign-In start failed");
  const payload = await response.json();
  return payload.authorization_url;
}

export async function exchangeOAuthCode(code: string): Promise<string> {
  const response = await apiFetch("/auth/oauth/exchange", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code }),
  }, 10000);
  if (!response.ok) throw new Error("OAuth code exchange failed");
  const payload = await response.json();
  setAuthToken(payload.access_token);
  return payload.access_token;
}

export async function fetchThreatBulletin(): Promise<{ title: string; link: string }[]> {
  const response = await apiFetch("/api/threat-bulletin");
  if (!response.ok) throw new Error("Failed to fetch threat bulletin");
  const payload = await response.json();
  return payload.items || [];
}

export async function fetchGmailOAuthStatus(): Promise<GmailStatus> {
  const response = await apiFetch("/api/gmail/oauth/status", {
    headers: authHeaders()
  });
  if (!response.ok) throw new Error("Gmail status failed");
  return response.json();
}

export async function startGmailOAuth(returnUrl?: string): Promise<string> {
  const url = returnUrl ? `/api/gmail/oauth/start?return_url=${encodeURIComponent(returnUrl)}` : "/api/gmail/oauth/start";
  const response = await apiFetch(url, {
    headers: authHeaders()
  });
  if (!response.ok) throw new Error("Gmail OAuth start failed");
  const payload = await response.json();
  return payload.authorization_url;
}

export async function ensureGmailLabels(): Promise<Record<string, string>> {
  const response = await apiFetch("/api/gmail/labels/ensure", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: "{}"
  }, 20000);
  if (!response.ok) throw new Error("Gmail label setup failed");
  const payload = await response.json();
  return payload.labels;
}

export async function runGmailLabelScan(): Promise<{ status: string; enqueued: number; scanned_label: string }> {
  const response = await apiFetch("/api/gmail/run-once", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: "{}"
  }, 20000);
  
  if (!response.ok) {
    let msg = "Gmail label scan failed";
    try {
      const errData = await response.json();
      if (errData && errData.detail) msg = errData.detail;
    } catch (e) {}
    throw new Error(msg);
  }
  return response.json();
}

export async function fetchNotificationPreferences(): Promise<NotificationPreferences> {
  const response = await apiFetch("/api/notifications/preferences", {
    headers: authHeaders()
  });
  if (!response.ok) throw new Error("Notification preferences fetch failed");
  return response.json();
}

export async function saveNotificationPreferences(preferences: NotificationPreferences): Promise<NotificationPreferences> {
  const response = await apiFetch("/api/notifications/preferences", {
    method: "PUT",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(preferences)
  });
  if (!response.ok) throw new Error("Notification preferences update failed");
  return response.json();
}

export async function getReportDownloadUrl(scanId: string, kind: "pdf" | "json"): Promise<string> {
  const response = await apiFetch(`/api/scans/${scanId}/report-link?kind=${kind}`, {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: "{}"
  });
  if (!response.ok) throw new Error(`${kind.toUpperCase()} report is not available yet`);
  const payload = await response.json();
  return payload.url;
}

export type GoogleBackupStatus = {
  connected: boolean;
  email: string | null;
  name: string | null;
  last_sync: string | null;
};

export async function fetchGoogleBackupStatus(): Promise<GoogleBackupStatus> {
  return { connected: false, email: null, name: null, last_sync: null };
}

export async function startGoogleBackupOAuth(returnUrl?: string): Promise<string> {
  throw new Error("Google Backup is not implemented on the backend yet.");
}

export async function triggerGoogleBackupSync(): Promise<any> {
  throw new Error("Google Backup is not implemented on the backend yet.");
}

export async function disconnectGoogleBackup(): Promise<any> {
  throw new Error("Google Backup is not implemented on the backend yet.");
}


export async function analyzeCall(orgClaimed: string, actionsRequested: string[], warningPhrases: string[]) {
  const form = new FormData();
  form.append('input_mode', 'structured');
  form.append('org_claimed', orgClaimed);
  form.append('actions_requested', JSON.stringify(actionsRequested));
  form.append('warning_phrases', JSON.stringify(warningPhrases));

  const response = await apiFetch('/api/voice/analyze-call', {
    method: 'POST',
    body: form,
    headers: authHeaders(),
  }, 30000);

  if (!response.ok) {
    throw new Error('Call analysis failed');
  }
  return response.json();
}
