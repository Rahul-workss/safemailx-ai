import re


SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    "openai_api_key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "credit_card_like": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "ssn_like": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
}


def detect_data_leak(text: str) -> list[dict]:
    signals: list[str] = []
    lowered = text.lower()

    for name, pattern in SECRET_PATTERNS.items():
        if pattern.search(text):
            signals.append(name)

    if any(term in lowered for term in ["seed phrase", "recovery phrase", "mnemonic phrase", "12 words", "24 words"]):
        signals.append("wallet_seed_or_recovery_phrase")

    if re.search(r"\b(password|passwd|pwd)\s*[:=]\s*\S{6,}", text, re.IGNORECASE):
        signals.append("password_literal")

    if not signals:
        return []

    severe = any(signal in signals for signal in [
        "private_key", "aws_access_key", "github_token", "slack_token",
        "google_api_key", "openai_api_key", "wallet_seed_or_recovery_phrase",
    ])

    return [{
        "category": "data_leak",
        "score": 0.95 if severe else 0.78,
        "signals": sorted(set(signals)),
        "requested_actions": ["share_pii"] if not severe else ["share_pii", "login"],
        "reporting_targets": ["employer IT"],
    }]
