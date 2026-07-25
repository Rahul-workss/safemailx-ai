"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { exchangeOAuthCode } from "@/lib/api";

export default function AuthCallbackPage() {
  const router = useRouter();
  const [error, setError] = useState("");

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const err = params.get("error");

    if (err) {
      setError(`Authentication failed: ${err}`);
      return;
    }

    if (!code) {
      setError("No authentication code received from Google.");
      return;
    }

    // Exchange the short-lived code for a JWT access token
    exchangeOAuthCode(code)
      .then(() => {
        router.push("/dashboard");
      })
      .catch((e: any) => {
        setError(e.message || "Sign-in failed. Please try again.");
      });
  }, [router]);

  return (
    <div style={{ display: "flex", height: "100vh", width: "100vw", alignItems: "center", justifyContent: "center", backgroundColor: "#000" }}>
      {error ? (
        <div style={{ textAlign: "center" }}>
          <p style={{ color: "var(--rose)", marginBottom: 16 }}>{error}</p>
          <button
            onClick={() => router.push("/auth/login")}
            style={{ padding: "10px 20px", background: "rgba(255,255,255,0.1)", color: "#fff", borderRadius: 8, border: "none", cursor: "pointer" }}
          >
            Back to Login
          </button>
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
          <div style={{ width: 48, height: 48, borderRadius: 24, border: "2px solid #00f3ff", borderTopColor: "transparent", animation: "spin 1s linear infinite", marginBottom: 16 }} />
          <p style={{ color: "var(--frost4)", fontSize: 14, fontFamily: "var(--font-sans)", letterSpacing: 2, textTransform: "uppercase" }}>Completing Sign In</p>
        </div>
      )}
    </div>
  );
}
