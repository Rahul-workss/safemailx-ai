SOURCE_TYPES = {
    "email",
    "sms",
    "social_chat",
    "url",
    "document",
    "screenshot",
    "business_request",
    "domain",
}

PRIMARY_THREATS = {
    "phishing",
    "bec_payment_fraud",
    "investment_crypto_scam",
    "tech_support_scam",
    "romance_social_scam",
    "malware_delivery",
    "ransomware_risk",
    "credential_theft",
    "identity_takeover",
    "data_leak",
    "domain_exposure",
    "unknown",
}

REQUESTED_ACTIONS = {
    "money_transfer",
    "login",
    "file_open",
    "app_install",
    "call_number",
    "share_otp",
    "share_pii",
    "crypto_transfer",
    "none",
}

THREAT_PRIORITY = [
    "data_leak",
    "ransomware_risk",
    "malware_delivery",
    "bec_payment_fraud",
    "investment_crypto_scam",
    "credential_theft",
    "identity_takeover",
    "tech_support_scam",
    "romance_social_scam",
    "phishing",
    "domain_exposure",
    "unknown",
]

DEFAULT_REPORTING_TARGETS = {
    "bec_payment_fraud": ["IC3", "bank/card provider", "employer IT"],
    "investment_crypto_scam": ["IC3", "FTC", "bank/card provider"],
    "tech_support_scam": ["FTC", "bank/card provider"],
    "romance_social_scam": ["FTC", "IC3"],
    "malware_delivery": ["CISA", "employer IT"],
    "ransomware_risk": ["CISA", "employer IT"],
    "credential_theft": ["employer IT"],
    "identity_takeover": ["employer IT"],
    "data_leak": ["employer IT"],
    "domain_exposure": ["employer IT"],
    "phishing": ["IC3", "employer IT"],
    "unknown": [],
}

RECOMMENDATIONS = {
    "bec_payment_fraud": "Do not send money. Verify the request by calling a known trusted contact and alert finance or IT.",
    "investment_crypto_scam": "Do not transfer funds or crypto. Preserve screenshots, wallet addresses, and file an IC3/FTC report if money was sent.",
    "tech_support_scam": "Do not call the number or install remote access tools. Close the page and contact the vendor through its official site.",
    "romance_social_scam": "Pause the conversation and do not send money, gift cards, crypto, documents, or account codes.",
    "malware_delivery": "Do not open the file or download linked software. Preserve the message and scan the device if anything was opened.",
    "ransomware_risk": "Disconnect affected devices from the network if opened, preserve evidence, and contact IT before cleanup.",
    "credential_theft": "Do not sign in through the provided link. Go directly to the service, change passwords, and revoke active sessions if needed.",
    "identity_takeover": "Never share OTP, MFA, recovery codes, cookies, or OAuth approvals. Revoke sessions and enable phishing-resistant MFA.",
    "data_leak": "Rotate exposed secrets immediately and avoid sending sensitive keys, documents, or identity data to untrusted services.",
    "domain_exposure": "Fix missing domain protections such as SPF, DMARC, TLS, and browser security headers.",
    "phishing": "Do not click links or open attachments. Verify through an independent channel and report the message.",
    "unknown": "No specific cyber-risk category was confirmed. Continue with normal caution and verify unexpected requests.",
}


def normalize_source_type(value: str | None) -> str:
    normalized = (value or "email").strip().lower()
    return normalized if normalized in SOURCE_TYPES else "email"


def recommendation_for(threat: str) -> str:
    return RECOMMENDATIONS.get(threat, RECOMMENDATIONS["unknown"])


def reporting_targets_for(threat: str) -> list[str]:
    return list(DEFAULT_REPORTING_TARGETS.get(threat, []))
