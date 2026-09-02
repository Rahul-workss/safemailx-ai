import { loadRefreshToken, loadSession, saveSession, triggerSessionExpired } from "./session";

const configuredApiBaseUrl = process.env.EXPO_PUBLIC_API_BASE_URL || "https://safemailx-ai.onrender.com";
let apiBaseUrl = configuredApiBaseUrl;

let accessToken = "";
const DEFAULT_TIMEOUT_MS = 20000;
let refreshPromise: Promise<boolean> | null = null;

export type AuthTokenSet = {
  accessToken: string;
  refreshToken?: string | null;
  email?: string | null;
};

// ─── Typed error classes ──────────────────────────────────────────────────────
/** Thrown when the server returns HTTP 401. Triggers the global logout flow. */
export class UnauthorizedError extends Error {
  constructor(message = "Session expired. Please sign in again.") {
    super(message);
    this.name = "UnauthorizedError";
  }
}

/** Thrown when the request never gets a response (timeout, no internet, etc). */
export class NetworkError extends Error {
  constructor(message = "Network request failed.") {
    super(message);
    this.name = "NetworkError";
  }
}

async function attemptSilentRefresh(): Promise<boolean> {
  if (refreshPromise) return refreshPromise;

  refreshPromise = (async () => {
    try {
      const storedRefreshToken = await loadRefreshToken();
      if (!storedRefreshToken) return false;

      const session = await loadSession();
      const storedEmail = session?.email || "";
      const response = await fetch(`${apiBaseUrl}/auth/refresh`, {
        method: "POST",
        headers: {
          "Bypass-Tunnel-Reminder": "true",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ refresh_token: storedRefreshToken }),
      });
      if (!response.ok) return false;

      const payload = await response.json();
      setAccessToken(payload.access_token);
      await saveSession(payload.access_token, storedEmail, payload.refresh_token || null);
      return true;
    } catch {
      return false;
    } finally {
      refreshPromise = null;
    }
  })();

  return refreshPromise;
}

async function apiFetch(path: string, options: RequestInit = {}, timeoutMs = DEFAULT_TIMEOUT_MS, allowRefresh = true) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  const isPublicAuthEndpoint = new Set([
    "/auth/login",
    "/auth/register",
    "/auth/send-otp",
    "/auth/forgot-password",
    "/auth/reset-password",
    "/auth/refresh",
    "/auth/oauth/exchange",
  ]).has(path);

  const headers = {
    "Bypass-Tunnel-Reminder": "true",
    ...(options.headers || {})
  } as Record<string, string>;
  if (!isPublicAuthEndpoint && accessToken) {
    headers["Authorization"] = `Bearer ${accessToken}`;
  }

  let response: Response;
  try {
    response = await fetch(`${apiBaseUrl}${path}`, {
      ...options,
      headers,
      signal: controller.signal
    });
  } catch (error: any) {
    clearTimeout(timeoutId);
    if (error?.name === "AbortError") {
      throw new NetworkError(`Request timed out. Check the API server URL: ${apiBaseUrl}`);
    }
    throw new NetworkError(`Network request failed. Check the API server URL: ${apiBaseUrl}`);
  } finally {
    clearTimeout(timeoutId);
  }

  // 401 — token is invalid or expired. Trigger exactly-once logout flow.
  // EXCEPT for auth endpoints where 401 means "wrong credentials", not "expired session".
  if (response.status === 401 && !isPublicAuthEndpoint) {
    if (allowRefresh) {
      const refreshed = await attemptSilentRefresh();
      if (refreshed) {
        return apiFetch(path, options, timeoutMs, false);
      }
    }
    triggerSessionExpired();
    throw new UnauthorizedError();
  }

  return response;
}

export function getApiBaseUrl() {
  return apiBaseUrl;
}

export function setApiBaseUrl(url: string): boolean {
  // Release builds use the EAS-provided API only. Developer builds can still
  // point at a local LAN server for testing, but never silently downgrade a
  // release build to an attacker-controlled endpoint.
  if (!__DEV__) return false;
  try {
    const parsed = new URL(url.trim());
    if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash) {
      return false;
    }
    apiBaseUrl = parsed.toString().replace(/\/+$/, "");
    return true;
  } catch {
    return false;
  }
}

export function setAccessToken(token: string) {
  accessToken = token;
}

export async function logoutSession(): Promise<void> {
  if (!accessToken) return;
  try {
    await apiFetch("/auth/logout", { method: "POST", headers: authHeaders() }, 10000, false);
  } catch {
    // Local cleanup still runs if the network is unavailable.
  }
}

function authHeaders(extra: Record<string, string> = {}) {
  const headers: Record<string, string> = {
    "Bypass-Tunnel-Reminder": "true",
    ...extra
  };
  if (accessToken) {
    headers["Authorization"] = `Bearer ${accessToken}`;
  }
  return headers;
}

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

export async function login(email: string, password: string): Promise<AuthTokenSet> {
  const response = await apiFetch("/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password })
  }, 20000);
  if (!response.ok) throw new Error("Login failed");
  const payload = await response.json();
  setAccessToken(payload.access_token);
  return {
    accessToken: payload.access_token,
    refreshToken: payload.refresh_token || null,
  };
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

export async function register(email: string, name: string, password: string, otp: string): Promise<AuthTokenSet> {
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
  setAccessToken(payload.access_token);
  return {
    accessToken: payload.access_token,
    refreshToken: payload.refresh_token || null,
  };
}

export async function requestPasswordReset(email: string): Promise<void> {
  const response = await apiFetch("/auth/forgot-password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email })
  });
  if (!response.ok) throw new Error("Password reset request failed");
}

export async function confirmPasswordReset(token: string, newPassword: string): Promise<void> {
  const response = await apiFetch("/auth/reset-password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, new_password: newPassword })
  });
  if (!response.ok) throw new Error("Password reset confirmation failed");
}

export async function exchangeOAuthCode(code: string): Promise<AuthTokenSet> {
  const response = await apiFetch("/auth/oauth/exchange", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code }),
  });
  if (!response.ok) throw new Error("OAuth sign-in link expired");
  const payload = await response.json();
  return {
    accessToken: payload.access_token,
    refreshToken: payload.refresh_token || null,
    email: payload.email || null,
  };
}

export async function fetchScans(): Promise<ScanSummary[]> {
  const response = await apiFetch("/api/scans", {
    headers: authHeaders()
  });
  if (!response.ok) throw new Error("Scan list failed");
  return response.json();
}

export async function createManualScan(body: string): Promise<ScanSummary> {
  const payload = {
    subject: "Mobile Manual Scan",
    sender: "mobile-app",
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

export async function uploadScanFile(file: {
  uri: string;
  name: string;
  mimeType?: string;
}): Promise<ScanSummary> {
  return uploadMultipartScan("/api/scans/upload", file, "Uploaded file");
}

export async function uploadScreenshot(file: {
  uri: string;
  name: string;
  mimeType?: string;
}): Promise<ScanSummary> {
  return uploadMultipartScan("/api/scans/screenshot", file, "Screenshot scan");
}

async function uploadMultipartScan(
  path: string,
  file: {
    uri: string;
    name: string;
    mimeType?: string;
  },
  subjectPrefix: string
): Promise<ScanSummary> {
  const form = new FormData();
  form.append("subject", `${subjectPrefix}: ${file.name}`);
  form.append("sender", "mobile-upload");
  form.append("file", {
    uri: file.uri,
    name: file.name,
    type: file.mimeType || "application/octet-stream"
  } as unknown as Blob);

  const response = await apiFetch(path, {
    method: "POST",
    headers: authHeaders(),
    body: form
  }, 60000);
  if (!response.ok) throw new Error("Upload scan failed");
  return response.json();
}

export async function scanInstantFile(file: {
  uri: string;
  name: string;
  mimeType?: string;
}): Promise<InstantScanResult> {
  const form = new FormData();
  form.append("file", {
    uri: file.uri,
    name: file.name,
    type: file.mimeType || "application/octet-stream"
  } as unknown as Blob);
  form.append("scan_mode", "balanced");

  const response = await apiFetch("/api/instant/file", {
    method: "POST",
    headers: authHeaders(),
    body: form
  }, 60000);
  if (!response.ok) throw new Error("File scan failed");
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

export async function registerPushToken(token: string, platform: string): Promise<void> {
  const response = await apiFetch("/api/notifications/register", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ token, platform })
  });
  if (!response.ok) throw new Error("Push token registration failed");
}

export async function fetchNotificationPreferences(): Promise<NotificationPreferences> {
  const response = await apiFetch("/api/notifications/preferences", {
    headers: authHeaders()
  });
  if (!response.ok) throw new Error("Notification preferences fetch failed");
  return response.json();
}

export async function saveNotificationPreferences(
  preferences: NotificationPreferences
): Promise<NotificationPreferences> {
  const response = await apiFetch("/api/notifications/preferences", {
    method: "PUT",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(preferences)
  });
  if (!response.ok) throw new Error("Notification preferences update failed");
  return response.json();
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

export async function startGoogleAuthLogin(returnUrl?: string): Promise<string> {
  const url = returnUrl ? `/api/auth/google/start?return_url=${encodeURIComponent(returnUrl)}` : "/api/auth/google/start";
  const response = await apiFetch(url);
  if (!response.ok) throw new Error("Google Sign-In start failed");
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
  if (!response.ok) throw new Error("Gmail label scan failed");
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

export async function fetchThreatBulletin(): Promise<{ title: string; link: string }[]> {
  const response = await apiFetch("/api/threat-bulletin");
  if (!response.ok) throw new Error("Failed to fetch threat bulletin");
  const payload = await response.json();
  return payload.items || [];
}

export type GoogleBackupStatus = {
  connected: boolean;
  email: string | null;
  name: string | null;
  last_sync: string | null;
};

export async function fetchGoogleBackupStatus(): Promise<GoogleBackupStatus> {
  const response = await apiFetch("/api/backup/oauth/status", {
    headers: authHeaders()
  });
  if (!response.ok) throw new Error("Google backup status failed");
  return response.json();
}

export async function startGoogleBackupOAuth(returnUrl?: string): Promise<string> {
  const url = returnUrl ? `/api/backup/oauth/start?return_url=${encodeURIComponent(returnUrl)}` : "/api/backup/oauth/start";
  const response = await apiFetch(url, {
    headers: authHeaders()
  });
  if (!response.ok) throw new Error("Google Backup start failed");
  const payload = await response.json();
  return payload.authorization_url;
}

export async function triggerGoogleBackupSync(): Promise<any> {
  const response = await apiFetch("/api/backup/sync", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: "{}"
  });
  if (!response.ok) throw new Error("Google Backup Sync failed");
  return response.json();
}

export async function disconnectGoogleBackup(): Promise<void> {
  const response = await apiFetch("/api/backup/oauth/disconnect", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: "{}"
  });
  if (!response.ok) throw new Error("Google Backup disconnect failed");
}

export type CallAnalysisResult = {
  final_score: number;
  risk_band: 'SAFE' | 'SUSPICIOUS' | 'CRITICAL';
  score_display: number;
  org_claimed: string;
  purpose_detected: string;
  why_flagged: string[];
  recommended_action: string;
  official_callback_number: string;
  report_url: string;
  signals_fired: string[];
  hard_floors_triggered: string[];
  full_explanation: string;
  composite_score: number;
  floor_score: number;
  layer_results: Record<string, any>;
};

export async function analyzeCall(params: {
  inputMode: 'voice' | 'structured';
  audioUri?: string;
  orgClaimed?: string;
  actionsRequested?: string[];
  warningPhrases?: string[];
}): Promise<CallAnalysisResult> {
  const form = new FormData();
  form.append('input_mode', params.inputMode);

  if (params.inputMode === 'voice' && params.audioUri) {
    form.append('audio', {
      uri: params.audioUri,
      name: 'description.wav',
      type: 'audio/wav',
    } as any);
  } else {
    form.append('org_claimed', params.orgClaimed || '');
    form.append('actions_requested', JSON.stringify(params.actionsRequested || []));
    form.append('warning_phrases', JSON.stringify(params.warningPhrases || []));
  }

  const response = await apiFetch('/api/voice/analyze-call', {
    method: 'POST',
    body: form,
    headers: authHeaders(),
  }, 30000); // 30s timeout for audio transcription

  if (!response.ok) {
    let msg = 'Call analysis failed';
    try {
      const err = await response.json();
      if (err.detail) msg = err.detail;
    } catch (e) {}
    throw new Error(msg);
  }

  return response.json();
}
