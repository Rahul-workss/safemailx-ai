import re


def _has_any(text: str, terms: list[str]) -> bool:
    return any(term in text for term in terms)


def detect_fraud_scams(subject: str, body: str, sender: str = "") -> list[dict]:
    text = f"{subject}\n{body}\n{sender}".lower()
    findings: list[dict] = []

    money_terms = [
        "wire transfer", "bank transfer", "ach", "invoice", "payment",
        "remittance", "beneficiary", "account number", "iban", "swift",
        "routing number", "gift card", "pay now", "upi",
    ]
    bec_terms = [
        "change of bank", "new bank details", "updated bank details",
        "vendor payment", "supplier payment", "confidential", "do not call",
        "ceo", "cfo", "urgent payment", "settle this invoice",
    ]
    if _has_any(text, money_terms) and _has_any(text, bec_terms):
        findings.append({
            "category": "bec_payment_fraud",
            "score": 0.88,
            "signals": ["vendor_or_executive_payment_pretext", "bank_or_invoice_action"],
            "requested_actions": ["money_transfer"],
            "reporting_targets": ["IC3", "bank/card provider", "employer IT"],
        })

    crypto_terms = [
        "crypto", "bitcoin", "btc", "ethereum", "eth", "usdt", "wallet",
        "trading group", "investment group", "guaranteed return",
        "daily profit", "double your money", "mining pool",
    ]
    if _has_any(text, crypto_terms) and _has_any(text, ["invest", "profit", "return", "wallet", "deposit", "transfer"]):
        findings.append({
            "category": "investment_crypto_scam",
            "score": 0.86,
            "signals": ["crypto_or_investment_pretext", "profit_or_deposit_request"],
            "requested_actions": ["crypto_transfer"],
            "reporting_targets": ["IC3", "FTC", "bank/card provider"],
        })

    support_terms = [
        "windows support", "microsoft support", "apple support", "virus detected",
        "your computer is infected", "call support", "support number",
        "teamviewer", "anydesk", "ultraviewer", "remote access",
    ]
    if _has_any(text, support_terms) or (re.search(r"\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b", text) and "support" in text):
        findings.append({
            "category": "tech_support_scam",
            "score": 0.78,
            "signals": ["support_impersonation_or_remote_access"],
            "requested_actions": ["call_number", "app_install"],
            "reporting_targets": ["FTC", "bank/card provider"],
        })

    romance_terms = ["my love", "dear friend", "trust me", "emergency", "hospital", "customs", "gift card"]
    if _has_any(text, romance_terms) and _has_any(text, ["send money", "gift card", "crypto", "loan", "help me"]):
        findings.append({
            "category": "romance_social_scam",
            "score": 0.74,
            "signals": ["relationship_or_emergency_money_pretext"],
            "requested_actions": ["money_transfer"],
            "reporting_targets": ["FTC", "IC3"],
        })

    job_terms = ["remote job", "part time job", "task commission", "telegram", "whatsapp", "equipment check"]
    if _has_any(text, job_terms) and _has_any(text, ["deposit", "advance", "processing fee", "commission", "crypto"]):
        findings.append({
            "category": "investment_crypto_scam",
            "score": 0.70,
            "signals": ["job_or_task_scam_payment_pretext"],
            "requested_actions": ["money_transfer"],
            "reporting_targets": ["FTC", "IC3"],
        })

    recovery_terms = ["recover your lost funds", "refund agent", "chargeback expert", "asset recovery"]
    if _has_any(text, recovery_terms):
        findings.append({
            "category": "investment_crypto_scam",
            "score": 0.72,
            "signals": ["fund_recovery_scam_pretext"],
            "requested_actions": ["money_transfer", "share_pii"],
            "reporting_targets": ["FTC", "IC3"],
        })

    government_terms = ["irs", "tax department", "police", "court notice", "social security", "aadhaar", "pan card"]
    if _has_any(text, government_terms) and _has_any(text, ["pay fine", "arrest", "verify identity", "share otp", "gift card"]):
        findings.append({
            "category": "identity_takeover",
            "score": 0.76,
            "signals": ["government_impersonation_identity_or_payment_request"],
            "requested_actions": ["share_pii", "share_otp", "money_transfer"],
            "reporting_targets": ["FTC", "IC3"],
        })

    return findings
