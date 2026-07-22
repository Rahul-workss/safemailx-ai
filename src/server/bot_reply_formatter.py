# coding: utf-8
"""
bot_reply_formatter.py -- SafeMail X AI
Formats scan results into short, emoji-rich 2-line bot replies (Option A).
Anonymous mode: results are NOT saved to user history.
"""

_SIREN   = "🚨"   # red siren  -- phishing
_WARNING = "⚠️"  # warning    -- suspicious
_CHECK   = "✅"        # green tick -- legitimate
_WAVE    = "👋"   # wave       -- help greeting
_CROSS   = "❌"       # red cross  -- error

_INTENT_MAP = {
    "credential_theft": "Credential theft",
    "financial_fraud": "Financial fraud",
    "malware_delivery": "Malware delivery",
    "identity_theft": "Identity theft",
    "advance_fee": "Advance fee fraud",
    "sextortion": "Sextortion",
    "account_takeover": "Account takeover",
    "fake_prize": "Fake prize",
    "transactional": "Transactional (legit)",
    "otp": "OTP / Verification",
}


def _icon(verdict: str) -> str:
    if verdict == "phishing":
        return _SIREN
    if verdict == "suspicious":
        return _WARNING
    return _CHECK


def _category(result) -> str:
    cat = result.scan_category or ""
    return _INTENT_MAP.get(cat, cat.replace("_", " ").title() if cat else "Unknown")


def _second_line(verdict: str) -> str:
    if verdict == "phishing":
        return "Do NOT click any links or share personal details. Block this sender."
    if verdict == "suspicious":
        return "Treat with caution. Avoid clicking links until you can verify the sender."
    return "This message appears safe. Stay vigilant and scan anything uncertain."


def format_whatsapp_reply(result) -> str:
    """Two-line WhatsApp reply. Bold uses *text* (WhatsApp markdown)."""
    icon = _icon(result.verdict)
    line1 = f"{icon} *{result.verdict.upper()}* | Risk: {round(result.risk_score)}% | {_category(result)}"
    return f"{line1}\n{_second_line(result.verdict)}"


def format_telegram_reply(result) -> str:
    """Two-line Telegram reply. Bold uses <b>text</b> HTML (parse_mode=HTML)."""
    icon = _icon(result.verdict)
    line1 = f"{icon} <b>{result.verdict.upper()}</b> | Risk: {round(result.risk_score)}% | {_category(result)}"
    return f"{line1}\n{_second_line(result.verdict)}"


def format_help_message_whatsapp() -> str:
    return (
        f"{_WAVE} Welcome to *SafeMail X AI* -- your SMS phishing detector!\n\n"
        "How to use: Simply *forward* or paste any suspicious SMS text here.\n"
        "I will scan it instantly and tell you if it is safe or a scam.\n\n"
        "Privacy: Scans are anonymous. No data is stored or linked to you."
    )


def format_help_message_telegram() -> str:
    return (
        f"{_WAVE} Welcome to <b>SafeMail X AI</b> -- your SMS phishing detector!\n\n"
        "<b>How to use:</b> Simply <b>forward</b> or paste any suspicious SMS text here.\n"
        "I will scan it instantly and tell you if it is safe or a scam.\n\n"
        "<b>Privacy:</b> Scans are anonymous. No data is stored or linked to you."
    )


def format_error_reply() -> str:
    return (
        f"{_CROSS} Scan failed -- our engine is temporarily unavailable.\n"
        "Please try again in a moment."
    )
