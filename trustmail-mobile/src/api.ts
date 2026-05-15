let apiBaseUrl = process.env.EXPO_PUBLIC_API_BASE_URL || "http://localhost:8080";

let accessToken = "";

export function getApiBaseUrl() {
  return apiBaseUrl;
}

export function setApiBaseUrl(url: string) {
  apiBaseUrl = url.replace(/\/+$/, "");
}

export function setAccessToken(token: string) {
  accessToken = token;
}

function authHeaders(extra: Record<string, string> = {}) {
  return accessToken ? { ...extra, Authorization: `Bearer ${accessToken}` } : extra;
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
  created_at: string;
};

export async function fetchHealth(): Promise<Health> {
  const response = await fetch(`${apiBaseUrl}/api/health`);
  if (!response.ok) throw new Error("Health check failed");
  return response.json();
}

export async function login(email: string, password: string): Promise<string> {
  const response = await fetch(`${apiBaseUrl}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password })
  });
  if (!response.ok) throw new Error("Login failed");
  const payload = await response.json();
  setAccessToken(payload.access_token);
  return payload.access_token;
}

export async function requestPasswordReset(email: string): Promise<void> {
  const response = await fetch(`${apiBaseUrl}/auth/forgot-password`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email })
  });
  if (!response.ok) throw new Error("Password reset request failed");
}

export async function confirmPasswordReset(token: string, newPassword: string): Promise<void> {
  const response = await fetch(`${apiBaseUrl}/auth/reset-password`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, new_password: newPassword })
  });
  if (!response.ok) throw new Error("Password reset confirmation failed");
}

export async function fetchScans(): Promise<ScanSummary[]> {
  const response = await fetch(`${apiBaseUrl}/api/scans`, {
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

  let response = await fetch(`${apiBaseUrl}/api/scans/manual/queue`, {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(payload)
  });

  if (response.status === 503) {
    response = await fetch(`${apiBaseUrl}/api/scans/manual`, {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify(payload)
    });
  }

  if (!response.ok) throw new Error("Manual scan failed");
  return response.json();
}

export async function uploadScanFile(file: {
  uri: string;
  name: string;
  mimeType?: string;
}): Promise<ScanSummary> {
  const form = new FormData();
  form.append("subject", `Uploaded file: ${file.name}`);
  form.append("sender", "mobile-upload");
  form.append("file", {
    uri: file.uri,
    name: file.name,
    type: file.mimeType || "application/octet-stream"
  } as unknown as Blob);

  const response = await fetch(`${apiBaseUrl}/api/scans/upload`, {
    method: "POST",
    headers: authHeaders(),
    body: form
  });
  if (!response.ok) throw new Error("Upload scan failed");
  return response.json();
}

export async function registerPushToken(token: string, platform: string): Promise<void> {
  const response = await fetch(`${apiBaseUrl}/api/notifications/register`, {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ token, platform })
  });
  if (!response.ok) throw new Error("Push token registration failed");
}

export async function fetchGmailOAuthStatus(): Promise<boolean> {
  const response = await fetch(`${apiBaseUrl}/api/gmail/oauth/status`, {
    headers: authHeaders()
  });
  if (!response.ok) throw new Error("Gmail status failed");
  const payload = await response.json();
  return Boolean(payload.connected);
}

export async function startGmailOAuth(): Promise<string> {
  const response = await fetch(`${apiBaseUrl}/api/gmail/oauth/start`, {
    headers: authHeaders()
  });
  if (!response.ok) throw new Error("Gmail OAuth start failed");
  const payload = await response.json();
  return payload.authorization_url;
}

export async function getReportDownloadUrl(scanId: string, kind: "pdf" | "json"): Promise<string> {
  const response = await fetch(`${apiBaseUrl}/api/scans/${scanId}/report-link?kind=${kind}`, {
    method: "POST",
    headers: authHeaders()
  });
  if (!response.ok) throw new Error(`${kind.toUpperCase()} report is not available yet`);
  const payload = await response.json();
  return payload.url;
}
