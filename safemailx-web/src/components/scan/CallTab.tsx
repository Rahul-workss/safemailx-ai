"use client";

import { useState } from "react";
import { analyzeCall } from "@/lib/api";

export default function CallTab() {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState("");

  const [orgClaimed, setOrgClaimed] = useState("");
  const [actions, setActions] = useState<string[]>([]);
  const [warnings, setWarnings] = useState<string[]>([]);

  const toggleItem = (list: string[], setList: (l: string[]) => void, item: string) => {
    if (list.includes(item)) {
      setList(list.filter(i => i !== item));
    } else {
      setList([...list, item]);
    }
  };

  const handleScan = async () => {
    if (!orgClaimed && actions.length === 0 && warnings.length === 0) {
      setError("Please select at least one option.");
      return;
    }
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const data = await analyzeCall(orgClaimed, actions, warnings);
      setResult(data);
    } catch (err: any) {
      setError(err.message || "Call analysis failed");
    } finally {
      setBusy(false);
    }
  };

  const ORGS = ['SBI Bank', 'HDFC', 'ICICI', 'UIDAI', 'Police/CBI', 'Customs', 'Income Tax'];
  const ACTIONS = ['OTP or PIN', 'Card details / CVV', 'Aadhaar number', 'Transfer money', 'Install an app', 'Share screen'];
  const WARNINGS = ['Account will be blocked', 'Arrest warrant / FIR', "Don't tell anyone", "Stay on the line"];

  return (
    <div className="scan-grid" style={{ animation: "fadeInUp 0.3s ease-out both" }}>
      <div className="glass-box" style={{ padding: 32 }}>
        <h3 style={{ color: "#fff", fontSize: 18, marginBottom: 16 }}>Hold + Describe (Call Analyzer)</h3>
        <p style={{ color: "var(--frost4)", fontSize: 13, marginBottom: 24 }}>Describe what happened on the call using the options below.</p>
        
        {error && (
          <div style={{ backgroundColor: "rgba(224,138,174,0.15)", padding: 12, borderRadius: 8, marginBottom: 16 }}>
            <p style={{ color: "var(--rose)", fontSize: 13, margin: 0 }}>{error}</p>
          </div>
        )}

        <div style={{ marginBottom: 24 }}>
          <label style={{ display: "block", color: "var(--frost4)", fontSize: 11, textTransform: "uppercase", letterSpacing: 1, marginBottom: 12 }}>Who do they claim to be?</label>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {ORGS.map(org => (
              <button 
                key={org}
                onClick={() => setOrgClaimed(org === orgClaimed ? "" : org)}
                style={{
                  padding: "8px 16px",
                  borderRadius: 20,
                  backgroundColor: orgClaimed === org ? "rgba(0, 243, 255, 0.15)" : "rgba(255,255,255,0.05)",
                  border: "1px solid",
                  borderColor: orgClaimed === org ? "var(--cyan)" : "rgba(255,255,255,0.1)",
                  color: orgClaimed === org ? "var(--cyan)" : "var(--frost4)",
                  fontSize: 13,
                  cursor: "pointer"
                }}
              >
                {org}
              </button>
            ))}
          </div>
        </div>

        <div style={{ marginBottom: 24 }}>
          <label style={{ display: "block", color: "var(--frost4)", fontSize: 11, textTransform: "uppercase", letterSpacing: 1, marginBottom: 12 }}>What did they ask for?</label>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {ACTIONS.map(act => (
              <button 
                key={act}
                onClick={() => toggleItem(actions, setActions, act)}
                style={{
                  padding: "8px 16px",
                  borderRadius: 20,
                  backgroundColor: actions.includes(act) ? "rgba(0, 243, 255, 0.15)" : "rgba(255,255,255,0.05)",
                  border: "1px solid",
                  borderColor: actions.includes(act) ? "var(--cyan)" : "rgba(255,255,255,0.1)",
                  color: actions.includes(act) ? "var(--cyan)" : "var(--frost4)",
                  fontSize: 13,
                  cursor: "pointer"
                }}
              >
                {act}
              </button>
            ))}
          </div>
        </div>

        <div style={{ marginBottom: 32 }}>
          <label style={{ display: "block", color: "var(--frost4)", fontSize: 11, textTransform: "uppercase", letterSpacing: 1, marginBottom: 12 }}>Did they say any of these?</label>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {WARNINGS.map(warn => (
              <button 
                key={warn}
                onClick={() => toggleItem(warnings, setWarnings, warn)}
                style={{
                  padding: "8px 16px",
                  borderRadius: 20,
                  backgroundColor: warnings.includes(warn) ? "rgba(0, 243, 255, 0.15)" : "rgba(255,255,255,0.05)",
                  border: "1px solid",
                  borderColor: warnings.includes(warn) ? "var(--cyan)" : "rgba(255,255,255,0.1)",
                  color: warnings.includes(warn) ? "var(--cyan)" : "var(--frost4)",
                  fontSize: 13,
                  cursor: "pointer"
                }}
              >
                {warn}
              </button>
            ))}
          </div>
        </div>

        <button className="btn-liquid cyan" 
          onClick={handleScan}
          disabled={busy}
          style={{ width: "100%", padding: "16px", borderRadius: 16, fontSize: 14, fontWeight: 700, letterSpacing: 1, cursor: busy ? "not-allowed" : "pointer", opacity: busy ? 0.7 : 1 }}
        >
          {busy ? "ANALYZING..." : "ANALYZE CALL"}
        </button>
      </div>

      <div>
        {result ? (
          <div className="glass-box" style={{ padding: 24, animation: "fadeInUp 0.4s ease-out both" }}>
             <h4 style={{ color: result.risk_band === 'CRITICAL' ? 'var(--rose)' : (result.risk_band === 'SAFE' ? 'var(--green)' : 'var(--gold)'), fontSize: 20, marginTop: 0, marginBottom: 16 }}>
               {result.risk_band} — {result.score_display}/100
             </h4>
             <p style={{ color: 'white', fontSize: 14, lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>{result.full_explanation}</p>
             
             <div style={{ marginTop: 24, padding: 16, backgroundColor: 'rgba(255,255,255,0.05)', borderRadius: 12 }}>
               <h5 style={{ color: 'var(--cyan)', fontSize: 12, textTransform: 'uppercase', letterSpacing: 1, margin: '0 0 8px 0' }}>Recommendation</h5>
               <p style={{ color: 'white', fontSize: 14, margin: 0 }}>{result.recommended_action}</p>
             </div>
          </div>
        ) : (
          <div className="glass-box" style={{ padding: 40, height: "100%", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", textAlign: "center", border: "1px dashed rgba(255,255,255,0.1)", backgroundColor: "transparent" }}>
            <span style={{ fontSize: 24, opacity: 0.75, marginBottom: 16 }}>??</span>
            <h3 style={{ color: "var(--frost4)", fontSize: 16, margin: 0 }}>Awaiting Call Details</h3>
            <p style={{ color: "var(--frost4)", fontSize: 13, marginTop: 8, opacity: 0.7 }}>Select options on the left to analyze a suspicious call.</p>
          </div>
        )}
      </div>
    </div>
  );
}
