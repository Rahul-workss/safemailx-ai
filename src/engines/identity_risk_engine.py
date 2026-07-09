def detect_identity_risk(text: str) -> list[dict]:
    lowered = text.lower()
    findings: list[dict] = []

    credential_terms = ["password", "login", "sign in", "verify account", "reset your password", "credentials"]
    if any(term in lowered for term in credential_terms) and any(term in lowered for term in ["click", "link", "portal", "account"]):
        findings.append({
            "category": "credential_theft",
            "score": 0.74,
            "signals": ["credential_or_login_collection_request"],
            "requested_actions": ["login"],
            "reporting_targets": ["employer IT"],
        })

    otp_terms = ["otp", "one time password", "one-time password", "verification code", "mfa code", "2fa code", "authenticator code"]
    if any(term in lowered for term in otp_terms) and any(term in lowered for term in ["share", "send", "reply", "provide", "confirm"]):
        findings.append({
            "category": "identity_takeover",
            "score": 0.90,
            "signals": ["otp_or_mfa_code_request"],
            "requested_actions": ["share_otp"],
            "reporting_targets": ["employer IT"],
        })

    oauth_terms = ["grant access", "approve access", "oauth", "consent", "permissions requested", "authorize this app"]
    if any(term in lowered for term in oauth_terms):
        findings.append({
            "category": "identity_takeover",
            "score": 0.72,
            "signals": ["oauth_or_consent_abuse_possible"],
            "requested_actions": ["login"],
            "reporting_targets": ["employer IT"],
        })

    session_terms = ["session cookie", "browser cookie", "export cookies", "recovery code", "backup code"]
    if any(term in lowered for term in session_terms):
        findings.append({
            "category": "identity_takeover",
            "score": 0.92,
            "signals": ["session_or_recovery_secret_request"],
            "requested_actions": ["share_otp"],
            "reporting_targets": ["employer IT"],
        })

    pii_terms = ["passport", "ssn", "social security number", "aadhaar", "pan card", "date of birth", "driver license"]
    if any(term in lowered for term in pii_terms) and any(term in lowered for term in ["upload", "send", "verify", "confirm"]):
        findings.append({
            "category": "identity_takeover",
            "score": 0.70,
            "signals": ["identity_document_or_pii_request"],
            "requested_actions": ["share_pii"],
            "reporting_targets": ["FTC", "employer IT"],
        })

    return findings
