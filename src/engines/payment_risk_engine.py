import re


CRYPTO_ADDRESS_PATTERNS = [
    re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b"),
    re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    re.compile(r"\bT[A-Za-z1-9]{33}\b"),
]


def detect_payment_risk(text: str) -> list[dict]:
    lowered = text.lower()
    findings: list[dict] = []
    actions: set[str] = set()
    signals: list[str] = []
    score = 0.0

    if any(term in lowered for term in ["wire transfer", "ach", "iban", "swift", "routing number", "bank account"]):
        actions.add("money_transfer")
        signals.append("bank_transfer_language")
        score = max(score, 0.62)

    if any(term in lowered for term in ["gift card", "steam card", "apple card", "google play card"]):
        actions.add("money_transfer")
        signals.append("gift_card_payment_request")
        score = max(score, 0.78)

    if any(term in lowered for term in ["upi", "paytm", "phonepe", "gpay", "cash app", "venmo", "zelle"]):
        actions.add("money_transfer")
        signals.append("instant_payment_app_request")
        score = max(score, 0.58)

    if any(pattern.search(text) for pattern in CRYPTO_ADDRESS_PATTERNS) or any(term in lowered for term in ["wallet address", "send usdt", "send bitcoin"]):
        actions.add("crypto_transfer")
        signals.append("crypto_wallet_or_transfer_request")
        score = max(score, 0.82)

    if "change" in lowered and any(term in lowered for term in ["bank detail", "account detail", "payment instruction"]):
        actions.add("money_transfer")
        signals.append("bank_detail_change_request")
        score = max(score, 0.86)

    if not signals:
        return []

    return [{
        "category": "bec_payment_fraud" if "bank_detail_change_request" in signals else "investment_crypto_scam" if "crypto_wallet_or_transfer_request" in signals else "phishing",
        "score": score,
        "signals": signals,
        "requested_actions": sorted(actions),
        "reporting_targets": ["IC3", "FTC", "bank/card provider"],
    }]
