"use client";

import { useEffect, useState } from "react";
import EmailTab from "@/components/scan/EmailTab";
import SmsTab from "@/components/scan/SmsTab";
import UrlTab from "@/components/scan/UrlTab";
import FileTab from "@/components/scan/FileTab";
import ScreenshotTab from "@/components/scan/ScreenshotTab";

import CallTab from "@/components/scan/CallTab";

type TabMode = "email" | "sms" | "url" | "file" | "screenshot" | "call";

const TAB_CONFIG: Array<{ key: TabMode; label: string; icon: string; color: string; hex: string }> = [
  { key: "email", label: "Email / Gmail", icon: "Mail", color: "41, 114, 255", hex: "#2972ff" },
  { key: "sms", label: "SMS Message", icon: "SMS", color: "0, 243, 255", hex: "#00f3ff" },
  { key: "url", label: "URL Scan", icon: "URL", color: "140, 82, 255", hex: "#8c52ff" },
  { key: "file", label: "File Upload", icon: "File", color: "245, 166, 35", hex: "#f5a623" },
  { key: "screenshot", label: "Screenshot", icon: "Shot", color: "255, 61, 113", hex: "#ff3d71" },
  { key: "call", label: "Call Analyzer", icon: "Call", color: "52, 199, 89", hex: "#34c759" },
];

export default function ScanCenterPage() {
  const [activeTab, setActiveTab] = useState<TabMode>("email");

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const requestedTab = params.get("tab");
    if (TAB_CONFIG.some((tab) => tab.key === requestedTab)) {
      setActiveTab(requestedTab as TabMode);
    }
  }, []);

  return (
    <div style={{ paddingBottom: 40, animation: "fadeInUp 0.4s ease-out both" }}>
      <div style={{ marginBottom: 40 }}>
        <p style={{ color: "#2972ff", fontSize: 10, fontWeight: 700, letterSpacing: 2, textTransform: "uppercase", marginBottom: 8 }}>
          THREAT INTELLIGENCE
        </p>
        <h1 style={{ fontSize: 36, margin: "0 0 12px 0", color: "#fff", fontWeight: 400, letterSpacing: "-0.02em" }}>
          Unified <span className="font-serif" style={{ fontStyle: "italic", color: "#2972ff", filter: "drop-shadow(0 0 8px rgba(41,114,255,0.4))" }}>Scan Center.</span>
        </h1>
        <p style={{ color: "var(--muted)", fontSize: 13, margin: 0, maxWidth: 600, lineHeight: 1.5 }}>
          Run the same SafeMail X detection stack across email, SMS, links, files, and screenshots.
        </p>
      </div>

      <div style={{ display: "flex", gap: 12, overflowX: "auto", padding: "16px 8px", margin: "-16px -8px 24px -8px" }}>
        {TAB_CONFIG.map((tab) => (
          <TabButton
            key={tab.key}
            label={tab.label}
            icon={tab.icon}
            color={tab.color}
            hex={tab.hex}
            active={activeTab === tab.key}
            onClick={() => setActiveTab(tab.key)}
          />
        ))}
      </div>

      <div>
        {activeTab === "email" && <EmailTab />}
        {activeTab === "sms" && <SmsTab />}
        {activeTab === "url" && <UrlTab />}
        {activeTab === "file" && <FileTab />}
        {activeTab === "screenshot" && <ScreenshotTab />}
        {activeTab === "call" && <CallTab />}
      </div>
    </div>
  );
}

function TabButton({
  label,
  icon,
  active,
  color,
  hex,
  onClick,
}: {
  label: string;
  icon: string;
  active: boolean;
  color: string;
  hex: string;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      style={{
        display: "flex",
        alignItems: "center",
        gap: 12,
        padding: "16px 24px",
        borderRadius: 20,
        border: `1px solid ${active ? `rgba(${color}, 0.4)` : "rgba(255,255,255,0.05)"}`,
        backgroundColor: active ? `rgba(${color}, 0.1)` : "rgba(255,255,255,0.02)",
        backdropFilter: "blur(20px)",
        WebkitBackdropFilter: "blur(20px)",
        color: active ? "#fff" : "var(--frost4)",
        cursor: "pointer",
        transition: "all 0.3s cubic-bezier(0.25, 1, 0.5, 1)",
        whiteSpace: "nowrap",
        flex: 1,
        minWidth: 160,
        boxShadow: active ? `0 10px 20px rgba(0,0,0,0.2), inset 0 1px 1px rgba(255,255,255,0.1), inset 0 -10px 20px rgba(${color}, 0.05)` : "none",
        transform: active ? "translateY(-2px)" : "none"
      }}
    >
      <span
        style={{
          minWidth: 38,
          height: 28,
          borderRadius: 999,
          border: `1px solid ${active ? `rgba(${color}, 0.6)` : "rgba(255,255,255,0.08)"}`,
          display: "inline-flex",
          alignItems: "center",
          justifyContent: "center",
          fontSize: 10,
          fontWeight: 700,
          color: active ? hex : "inherit",
          backgroundColor: active ? `rgba(${color}, 0.15)` : "transparent",
          boxShadow: active ? `inset 0 0 10px rgba(${color}, 0.5)` : "none",
        }}
      >
        {icon}
      </span>
      <span style={{ fontSize: 14, fontWeight: active ? 600 : 500, letterSpacing: 0.5 }}>
        {label}
      </span>
    </button>
  );
}
