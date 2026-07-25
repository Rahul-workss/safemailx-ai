"use client";

import { useEffect, useState } from "react";
import {
  createManualScan,
  ensureGmailLabels,
  fetchGmailOAuthStatus,
  GmailStatus,
  runGmailLabelScan,
  startGmailOAuth,
} from "@/lib/api";
import { useRouter } from "next/navigation";
import ScanProgressModal from "./ScanProgressModal";

export default function EmailTab() {
  const router = useRouter();
  const [gmailStatus, setGmailStatus] = useState<GmailStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [manualText, setManualText] = useState("");

  const refreshStatus = async () => {
    try {
      const status = await fetchGmailOAuthStatus();
      setGmailStatus(status);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // Handle Gmail OAuth callback redirect from Google
    const params = new URLSearchParams(window.location.search);
    const service = params.get("service");
    const status = params.get("status");
    const oauthError = params.get("error");

    // Clean up all OAuth params from the URL regardless of outcome
    const cleanUrl = new URL(window.location.href);
    cleanUrl.searchParams.delete("code");
    cleanUrl.searchParams.delete("status");
    cleanUrl.searchParams.delete("service");
    cleanUrl.searchParams.delete("error");
    window.history.replaceState({}, "", cleanUrl.toString());

    if (oauthError) {
      setError(`Gmail connection failed: ${oauthError}`);
      refreshStatus();
      return;
    }

    // Gmail connect callback: ?service=gmail&status=connected
    // The user is ALREADY logged in. The Gmail token was stored server-side
    // by the backend callback. DO NOT call exchangeOAuthCode here — that is
    // the login-flow endpoint and calling it risks a 401 that wipes the
    // user's existing JWT and triggers an auto-logout.
    if (service === "gmail" && status === "connected") {
      setSuccess("Gmail connected successfully!");
      refreshStatus();
      return;
    }

    // No OAuth params — normal page load
    refreshStatus();
  }, []);

  const handleConnectGmail = async () => {
    setBusy(true);
    setError("");
    try {
      const returnUrl = `${window.location.origin}/scan?tab=email`;
      const url = await startGmailOAuth(returnUrl);
      window.location.href = url;
    } catch (err: any) {
      setError(err.message || "Failed to start Gmail connection");
      setBusy(false);
    }
  };

  const handleSetupLabels = async () => {
    setBusy(true);
    setError("");
    setSuccess("");
    try {
      await ensureGmailLabels();
      setSuccess("Gmail labels configured successfully.");
      await refreshStatus();
    } catch (err: any) {
      setError(err.message || "Label setup failed");
    } finally {
      setBusy(false);
    }
  };

  const handleRunScan = async () => {
    setIsScanning(true);
    setBusy(true);
    setError("");
    setSuccess("");
    try {
      const response = await runGmailLabelScan();
      setSuccess(`Scan started. ${response.enqueued} email(s) added to the queue.`);
      setTimeout(() => router.push("/scans"), 2500);
    } catch (err: any) {
      setError(err.message || "Scan failed to start");
      setIsScanning(false);
    } finally {
      setBusy(false);
    }
  };

  const [activeScanId, setActiveScanId] = useState<string | null>(null);

  const handleManualScan = async () => {
    if (!manualText.trim()) return;
    setBusy(true);
    setError("");
    setSuccess("");
    try {
      const summary = await createManualScan(manualText);
      setActiveScanId(summary.id);
    } catch (err: any) {
      setError(err.message || "Manual scan failed");
      setBusy(false);
    }
  };

  return (
    <div style={{ animation: "fadeInUp 0.3s ease-out both" }}>

      {error && (
        <div style={{ backgroundColor: "rgba(224,138,174,0.15)", padding: 12, borderRadius: 8, marginBottom: 16 }}>
          <p style={{ color: "var(--rose)", fontSize: 13, margin: 0 }}>{error}</p>
        </div>
      )}

      {success && (
        <div style={{ backgroundColor: "rgba(0,243,255,0.15)", padding: 12, borderRadius: 8, marginBottom: 16 }}>
          <p style={{ color: "var(--cyan)", fontSize: 13, margin: 0 }}>{success}</p>
        </div>
      )}

      <div className="scan-grid" style={{ gap: 24 }}>
        <div className="glass-box" style={{ padding: 32, height: "100%", display: "flex", flexDirection: "column" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 20 }}>
              <span
                style={{
                  width: 44,
                  height: 44,
                  borderRadius: 12,
                  background: "linear-gradient(135deg, rgba(41,114,255,0.2), rgba(0,243,255,0.1))",
                  border: "1px solid rgba(41,114,255,0.3)",
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontSize: 13,
                  fontWeight: 800,
                  color: "#2972ff",
                  boxShadow: "inset 0 0 15px rgba(41,114,255,0.2), 0 0 20px rgba(41,114,255,0.1)"
                }}
              >
                GM
              </span>
              <h4 style={{ color: "#fff", fontSize: 18, fontWeight: 600, margin: 0, letterSpacing: 0.5 }}>Direct Gmail Scan</h4>
            </div>
            <p style={{ color: "var(--frost4)", fontSize: 13, lineHeight: 1.5, marginBottom: 24 }}>
              Connect Gmail, apply the SafeMail X labels, and run full queued analysis without uploading message
              content into the web client.
            </p>

            {loading ? (
              <p style={{ color: "var(--frost4)" }}>Checking connection...</p>
            ) : !gmailStatus?.connected ? (
              <button
                onClick={handleConnectGmail}
                disabled={busy}
                className="btn-liquid primary"
                style={{
                  width: "100%",
                  marginTop: "auto",
                  padding: "16px",
                  borderRadius: 16,
                  fontSize: 14,
                  fontWeight: 700,
                  letterSpacing: 1
                }}
              >
                CONNECT GMAIL
              </button>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                <div
                  style={{
                    padding: 12,
                    backgroundColor: "rgba(0,243,255,0.1)",
                    borderRadius: 8,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 8,
                  }}
                >
                  <span style={{ color: "var(--cyan)", fontSize: 12, fontWeight: 600 }}>Connected</span>
                  <span style={{ color: "var(--frost4)", fontSize: 11 }}>
                    {gmailStatus.scan_label}
                    {" -> "}
                    {gmailStatus.queued_label}
                  </span>
                </div>

                <button className="btn-liquid"
                  onClick={handleSetupLabels}
                  disabled={busy}
                  style={{
                    width: "100%",
                    padding: "14px",
                    borderRadius: 16,
                    fontSize: 13,
                    cursor: busy ? "not-allowed" : "pointer",
                    opacity: busy ? 0.7 : 1,
                  }}
                >
                  Configure Labels
                </button>

                <button
                  onClick={handleRunScan}
                  disabled={busy}
                  className="btn-liquid primary"
                  style={{
                    width: "100%",
                    padding: "16px",
                    borderRadius: 16,
                    fontSize: 14,
                    fontWeight: 700,
                    letterSpacing: 1
                  }}
                >
                  RUN FULL SCAN
                </button>
              </div>
            )}
          </div>

        <div className="glass-box" style={{ padding: 32, height: "100%", display: "flex", flexDirection: "column" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 20 }}>
            <span
              style={{
                width: 44,
                height: 44,
                borderRadius: 12,
                background: "linear-gradient(135deg, rgba(255,255,255,0.05), rgba(255,255,255,0.01))",
                border: "1px solid rgba(255,255,255,0.1)",
                display: "inline-flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: 13,
                fontWeight: 800,
                color: "var(--frost)",
              }}
            >
              TXT
            </span>
            <h4 style={{ color: "#fff", fontSize: 18, fontWeight: 600, margin: 0, letterSpacing: 0.5 }}>Manual Analysis</h4>
          </div>
          <p style={{ color: "var(--frost4)", fontSize: 13, lineHeight: 1.5, marginBottom: 16 }}>
            Paste raw email headers or body text for a full forensic scan that appears in history and reports.
          </p>

          <textarea
            className="glass-input"
            value={manualText}
            onChange={(event) => setManualText(event.target.value)}
            placeholder="[SYSTEM_READY] Paste raw email headers or body text here for forensic analysis..."
            rows={8}
            disabled={busy}
            style={{
              marginBottom: 24,
              flexGrow: 1,
              fontFamily: "monospace",
              backgroundColor: "rgba(0,0,0,0.4)",
              color: "#5de4d8",
              lineHeight: 1.6
            }}
          />

          <button
            onClick={handleManualScan}
            disabled={busy || !manualText.trim()}
            className="btn-liquid primary"
            style={{
              width: "100%",
              padding: "16px",
              borderRadius: 16,
              fontSize: 14,
              fontWeight: 700,
              letterSpacing: 1
            }}
          >
            ANALYZE TEXT
          </button>
        </div>
      </div>
      {activeScanId && (
        <ScanProgressModal
          scanId={activeScanId}
          onComplete={() => router.push(`/scans/${activeScanId}`)}
        />
      )}

      {isScanning && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: "rgba(0,0,0,0.8)",
            backdropFilter: "blur(10px)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 9999,
            animation: "fadeInUp 0.3s ease-out both"
          }}
        >
          <div className="glass-box" style={{ width: "100%", maxWidth: 400, padding: 32, display: "flex", flexDirection: "column", alignItems: "center" }}>
            <div style={{ width: 48, height: 48, borderRadius: 24, border: "3px solid var(--violet-glow)", borderTopColor: "transparent", animation: "spin 1s linear infinite", marginBottom: 24 }} />
            <h3 style={{ color: "#fff", fontSize: 20, marginBottom: 8, textAlign: "center" }}>Initiating Global Scan</h3>
            <p style={{ color: "var(--cyan)", fontSize: 14, textAlign: "center", fontWeight: 500 }}>
              {success ? "Emails queued for AI Engine... Redirecting" : "Connecting to secure APIs..."}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
