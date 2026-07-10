# ======================================================
# SafeMail X — Deterministic Intent Classifier
# Mirrors the LLM's "detected_intent" field using fast
# pattern matching so the fallback engine can apply
# calibrated score ceilings/floors without the LLM.
# ======================================================

import re

# -------------------------------------------------------
# CONVERSATIONAL: short social messages — zero threat
# -------------------------------------------------------
_CONVERSATIONAL_PATTERNS = [
    r"\bhe+y+\b",            # hey, heyy, heyyy
    r"\bhi+\b",              # hi, hii
    r"\bhiya\b",
    r"\bhello+\b",           # hello, helloo
    r"\bhowdy\b",
    r"\bwhat'?s\s*up\b",
    r"\bwassup\b",
    r"\bsup\b",
    r"\bgood\s+(?:morning|afternoon|evening|night|day)\b",
    r"\bthank\s*(?:you|s)\b",
    r"\bthx\b",
    r"\bcheers\b",
    r"\bsee\s+you\b",
    r"\bbye\b",
    r"\btake\s+care\b",
    r"\bfollowing\s+up\b",
    r"\bjust\s+checking\s+in\b",
    r"\bquick\s+question\b",
    r"\bhope\s+(?:you\s+are|you're|this\s+finds\s+you)\b",
    r"\b(?:how\s+are\s+you|how\s+r\s+u)\b",
    r"\blol\b",
    r"\bomg\b",
    r"\bokay\b",
    r"\bok\b",
    r"\bwow\b",
    r"\bnice\b",
    r"\bcool\b",
    r"\bnvm\b",
    r"\bbrb\b",
    r"\btalk\s+(?:soon|later)\b",
    r"\bcatch\s+(?:you\s+)?later\b",
    r"\bkk\b",
    r"\byep\b",
    r"\byup\b",
    r"\bnope\b",
]
_CONVERSATIONAL_RE = re.compile("|".join(_CONVERSATIONAL_PATTERNS), re.IGNORECASE)

# -------------------------------------------------------
# BENIGN NOTIFICATION: service alerts from real companies
# -------------------------------------------------------
_BENIGN_NOTIFICATION_PATTERNS = [
    r"\byour order\b.{0,40}\bhas shipped\b",
    r"\btracking number\b",
    r"\border #[A-Z0-9\-]{4,}\b",
    r"\bdelivery confirmation\b",
    r"\byour payment of\b",
    r"\breceipt for your\b",
    r"\bsubscription renewal\b",
    r"\bnew sign.?in detected\b",
    r"\bwe noticed a new sign.?in\b",
    r"\bif this was you\b",
    r"\bno action needed\b",
    r"\bnew device\b.{0,40}\bsign.?in\b",
    r"\bpassword was changed\b",
    r"\byour invoice\b",
    r"\bmonthly statement\b",
    r"\byour account statement\b",
]
_BENIGN_NOTIFICATION_RE = re.compile("|".join(_BENIGN_NOTIFICATION_PATTERNS), re.IGNORECASE)

# -------------------------------------------------------
# MARKETING: promotional emails — not phishing
# -------------------------------------------------------
_MARKETING_PATTERNS = [
    r"\b\d{1,3}%\s*off\b",
    r"\bexclusive\s+(?:offer|deal|discount)\b",
    r"\bspecial\s+offer\b",
    r"\blimited\s+time\s+offer\b",
    r"\bflash\s+sale\b",
    r"\bsummer\s+sale\b",
    r"\bfestive\s+offer\b",
    r"\bcoupon\s+code\b",
    r"\bpromo\s+code\b",
    r"\buse\s+code\b",
    r"\bunsubscribe\b",
    r"\bview\s+in\s+browser\b",
    r"\bemail\s+preferences\b",
    r"\bopt.?out\b",
    r"\bnewsletter\b",
    r"\bshop\s+now\b",
    r"\bsale\s+ends\b",
    r"\bdiscount\s+code\b",
    r"\bbirthday\s+offer\b",
    r"\banniversary\s+(?:offer|deal|sale)\b",
]
_MARKETING_RE = re.compile("|".join(_MARKETING_PATTERNS), re.IGNORECASE)

# -------------------------------------------------------
# CREDENTIAL THEFT: direct password/account harvesting
# -------------------------------------------------------
_CREDENTIAL_THEFT_PATTERNS = [
    r"\benter\s+your\s+(?:password|credentials|username)\b",
    r"\bconfirm\s+your\s+(?:password|credentials|account\s+details)\b",
    r"\bverify\s+your\s+(?:account|identity|details|credentials)\b",
    r"\bsign\s+in\s+to\s+verify\b",
    r"\byour\s+account\s+has\s+been\s+(?:compromised|hacked|breached)\b",
    r"\bunauthorized\s+(?:access|login|activity)\b.{0,60}\b(?:verify|confirm|click)\b",
    r"\bclick\s+(?:here|below)\s+to\s+(?:verify|confirm|secure|restore|reactivate)\b",
    r"\breactivate\s+your\s+account\b",
    r"\brestore\s+access\b",
    r"\bupdate\s+your\s+(?:billing|payment)\s+(?:info|information|details)\b",
    r"\byour\s+account\s+will\s+be\s+(?:suspended|closed|deleted|deactivated|terminated)\b",
    r"\bconfirm\s+ownership\b",
    r"\bvalidate\s+your\s+(?:account|email|identity)\b",
]
_CREDENTIAL_THEFT_RE = re.compile("|".join(_CREDENTIAL_THEFT_PATTERNS), re.IGNORECASE)

# -------------------------------------------------------
# FINANCIAL FRAUD / BEC: wire transfer, gift card scams
# -------------------------------------------------------
_FINANCIAL_FRAUD_PATTERNS = [
    r"\bwire\s+transfer\b",
    r"\bbank\s+transfer\b",
    r"\btransfer\s+funds\b",
    r"\bgift\s+card\s*(?:s)?\b",
    r"\biTunes\s+card\b",
    r"\bgoogle\s+play\s+card\b",
    r"\bbitcoin\b",
    r"\bcrypto(?:currency)?\b",
    r"\busdt\b",
    r"\bsend\s+(?:money|funds|payment)\b",
    r"\bpayment\s+overdue\b",
    r"\boverdue\s+invoice\b",
    r"\bargent\s+payment\b",
    r"\bunpaid\s+invoice\b",
    r"\bare\s+you\s+available\b",
    r"\bare\s+you\s+at\s+your\s+desk\b",
    r"\bconfidential\s+(?:task|request|matter)\b",
    r"\bprocess\s+(?:this\s+)?payment\b",
    r"\bpurchase\s+(?:gift\s+card|voucher)\b",
    r"\bkeep\s+this\s+(?:private|confidential|between\s+us)\b",
    r"\bdo\s+not\s+(?:tell|inform|mention)\b.{0,30}\banyone\b",
]
_FINANCIAL_FRAUD_RE = re.compile("|".join(_FINANCIAL_FRAUD_PATTERNS), re.IGNORECASE)

# -------------------------------------------------------
# MALWARE DELIVERY: dropper/macro lures
# -------------------------------------------------------
_MALWARE_DELIVERY_PATTERNS = [
    r"\benable\s+(?:editing|content|macros)\b",
    r"\ballow\s+macros\b",
    r"\bopen\s+the\s+attached\b",
    r"\bdownload\s+and\s+run\b",
    r"\binstall\s+the\s+update\b",
    r"\bprotected\s+document\b",
    r"\bencrypted\s+(?:file|document|attachment)\b",
    r"\bpassword.?protected\b.{0,40}\battachment\b",
    r"\bcall\s+us\b.{0,60}\bcancel\b",           # BazarCall
    r"\bdo\s+not\s+recognize.{0,60}\bcall\b",    # BazarCall
    r"\bsubscription\b.{0,60}\bcall\b.{0,60}\bcancel\b",
]
_MALWARE_DELIVERY_RE = re.compile("|".join(_MALWARE_DELIVERY_PATTERNS), re.IGNORECASE)

# -------------------------------------------------------
# AUTHORITY IMPERSONATION: gov/bank/IT
# -------------------------------------------------------
_AUTHORITY_PATTERNS = [
    r"\bit\s+(?:department|support|helpdesk|team)\b",
    r"\bsystem\s+administrator\b",
    r"\btech(?:nical)?\s+support\b",
    r"\birs\b", r"\bfbi\b", r"\bcbi\b", r"\bed\s+(?:department)?\b",
    r"\bincome\s+tax\b", r"\buidai\b", r"\baadhar\b",
    r"\bgovernment\s+(?:of|notice)\b",
    r"\breserve\s+bank\b",
    r"\bsebi\b", r"\bnse\b", r"\bbse\b",
]
_AUTHORITY_RE = re.compile("|".join(_AUTHORITY_PATTERNS), re.IGNORECASE)

# -------------------------------------------------------
# SPECIFICITY SIGNALS: real email markers (REDUCE score)
# -------------------------------------------------------
_ORDER_ID_RE      = re.compile(r"(?:order|transaction|ref(?:erence)?|tracking)\s*[#:]\s*[A-Z0-9\-]{5,}", re.IGNORECASE)
_CARD_LAST4_RE    = re.compile(r"(?:ending|last)\s+(?:in\s+)?(?:\*+)?(\d{4})\b", re.IGNORECASE)
_DOLLAR_AMT_RE    = re.compile(r"(?:\$|₹|€|£|USD|INR)\s*\d[\d,]*(?:\.\d{1,2})?", re.IGNORECASE)
_PERSONAL_NAME_RE = re.compile(r"(?:hi|hello|dear)\s+[A-Z][a-z]{1,20}[,!]", re.IGNORECASE)

# -------------------------------------------------------
# MANIPULATION SIGNALS: vague attacker patterns
# -------------------------------------------------------
_GENERIC_GREETING_RE = re.compile(
    r"\bdear\s+(?:customer|user|account\s+holder|valued\s+(?:member|customer)|sir|madam|member)\b",
    re.IGNORECASE
)
_VAGUE_ACCOUNT_RE = re.compile(
    r"\byour\s+account\b(?!\s+(?:number|ending|id\s*:|\s*#))",
    re.IGNORECASE
)
_EXTREME_CONSEQUENCE_RE = re.compile(
    r"\bpermanently\s+(?:deleted|suspended|terminated|blocked)\b"
    r"|\bfinal\s+(?:warning|notice|reminder)\b"
    r"|\blast\s+chance\b"
    r"|\bimmediate(?:ly)?\s+(?:or|else)\b"
    r"|\bwithout\s+(?:further\s+)?(?:notice|warning)\b",
    re.IGNORECASE
)

# -------------------------------------------------------
# GRAMMAR / QUALITY SIGNALS (structural red flags)
# -------------------------------------------------------
_EXCESSIVE_CAPS_RE    = re.compile(r"\b[A-Z]{4,}\b")
_EXCESSIVE_PUNCT_RE   = re.compile(r"[!?]{2,}")
_NON_ASCII_MIXED_RE   = re.compile(r"[A-Za-z][^\x00-\x7F][A-Za-z]")   # e.g. pay𝓅al
_BROKEN_ENGLISH_RE    = re.compile(
    r"\bkindly\s+do\s+the\s+needful\b"
    r"|\brevert\s+back\b"
    r"|\bdo\s+the\s+needful\b"
    r"|\bplease\s+do\s+needful\b"
    r"|\bdear\s+sir\s+or\s+madam\b",
    re.IGNORECASE
)


# ======================================================
# PUBLIC API
# ======================================================

def classify_intent(text: str, url_records: list[dict] | None = None) -> str:
    """
    Deterministically classify the intent of a message using regex patterns.
    Mirrors the LLM's 'detected_intent' field.

    Returns one of:
        'conversational', 'benign_notification', 'marketing',
        'credential_theft', 'financial_fraud', 'malware_delivery',
        'authority_impersonation', 'unknown'
    """
    has_urls = bool(url_records) or bool(re.search(r"https?://\S+", text, re.IGNORECASE))

    # 1a. Strict conversational: no links + social language pattern match
    if not has_urls and len(text.strip()) < 400 and _CONVERSATIONAL_RE.search(text):
        return "conversational"

    # 1b. Ultra-short text fallback: if body is ≤ 80 chars and has no links,
    #     no URLs, and matches none of the threat patterns below, it is almost
    #     certainly conversational/innocuous (covers 'heyy', 'hi', '😊', etc.)
    body_only = text.split("\n\n", 1)[-1].strip()  # strip subject line added by hybrid engine
    if not has_urls and len(body_only) <= 80:
        return "conversational"

    # 2. Malware delivery (highest priority — always dangerous)
    if _MALWARE_DELIVERY_RE.search(text):
        return "malware_delivery"

    # 3. Credential theft
    if _CREDENTIAL_THEFT_RE.search(text):
        return "credential_theft"

    # 4. Financial fraud / BEC (no links typically)
    if _FINANCIAL_FRAUD_RE.search(text):
        return "financial_fraud"

    # 5. Authority impersonation
    if _AUTHORITY_RE.search(text):
        return "authority_impersonation"

    # 6. Marketing (only when NOT combined with credential theft signals)
    if _MARKETING_RE.search(text) and not _CREDENTIAL_THEFT_RE.search(text):
        return "marketing"

    # 7. Benign notification
    if _BENIGN_NOTIFICATION_RE.search(text):
        return "benign_notification"

    return "unknown"


def score_specificity(text: str) -> tuple[float, list[str]]:
    """
    Mirrors the LLM's Q2 specificity check.
    Returns (adjustment, reasons) where adjustment is NEGATIVE (reduces score).
    Real services provide order IDs, card digits, names. Phishing is vague.
    """
    adjustment = 0.0
    reasons: list[str] = []

    if _ORDER_ID_RE.search(text):
        adjustment -= 0.12
        reasons.append("specificity:order_id_present")
    if _CARD_LAST4_RE.search(text):
        adjustment -= 0.10
        reasons.append("specificity:card_last4_present")
    if _DOLLAR_AMT_RE.search(text):
        adjustment -= 0.06
        reasons.append("specificity:specific_amount_present")
    if _PERSONAL_NAME_RE.search(text):
        adjustment -= 0.08
        reasons.append("specificity:personalized_greeting")

    return adjustment, reasons


def score_manipulation(text: str) -> tuple[float, list[str]]:
    """
    Mirrors the LLM's Q3/Q4/Q5 manipulation check.
    Returns (adjustment, reasons) where adjustment is POSITIVE (increases score).
    """
    adjustment = 0.0
    reasons: list[str] = []

    if _GENERIC_GREETING_RE.search(text):
        adjustment += 0.10
        reasons.append("manipulation:generic_greeting")

    vague_hits = len(_VAGUE_ACCOUNT_RE.findall(text))
    if vague_hits >= 2:
        adjustment += 0.10
        reasons.append("manipulation:vague_account_references")

    if _EXTREME_CONSEQUENCE_RE.search(text):
        adjustment += 0.15
        reasons.append("manipulation:extreme_consequence_language")

    return adjustment, reasons


def score_grammar(text: str) -> tuple[float, list[str]]:
    """
    Mirrors the LLM's grammar_score and coherence_score fields.
    Returns (adjustment, reasons) where adjustment is POSITIVE (increases score).
    """
    adjustment = 0.0
    reasons: list[str] = []

    words = text.split()
    if words:
        caps_ratio = len(_EXCESSIVE_CAPS_RE.findall(text)) / len(words)
        if caps_ratio > 0.15:
            adjustment += 0.08
            reasons.append("grammar:excessive_caps")

    if len(_EXCESSIVE_PUNCT_RE.findall(text)) >= 2:
        adjustment += 0.06
        reasons.append("grammar:excessive_punctuation")

    if _NON_ASCII_MIXED_RE.search(text):
        adjustment += 0.10
        reasons.append("grammar:non_ascii_mixed_chars")

    if _BROKEN_ENGLISH_RE.search(text):
        adjustment += 0.08
        reasons.append("grammar:broken_english_pattern")

    return adjustment, reasons


def score_social_engineering_tactics(text: str) -> tuple[float, list[str]]:
    """
    Detects all 8 social engineering tactics mirroring the LLM's
    social_engineering_tactics field. Returns (score_addition, tactic_list).
    Each unique tactic adds a calibrated weight.
    """
    tactics_found: list[str] = []
    total_adjustment = 0.0

    TACTIC_RULES = [
        # (pattern, tactic_name, weight)
        (r"\bwe\s+noticed\b|\bwe\s+detected\b|\byour\s+(?:package|delivery)\b.{0,30}\b(?:failed|held|delayed)\b",
         "pretexting", 0.10),
        (r"\b(?:it\s+department|system\s+administrator|irs|fbi|bank\s+of|reserve\s+bank|uidai|sebi)\b",
         "authority_impersonation", 0.15),
        (r"\byour\s+account\s+will\s+be\s+(?:suspended|deleted|terminated|closed|blocked)\b"
         r"|\bpermanently\s+(?:banned|removed|deleted)\b",
         "fear_appeal", 0.18),
        (r"\bwon\b.{0,40}\b(?:prize|reward|lottery|gift)\b"
         r"|\bclaim\s+your\s+(?:prize|reward|gift|voucher)\b"
         r"|\byou\s+(?:have\s+been\s+selected|are\s+a\s+winner)\b",
         "reward_lure", 0.18),
        (r"\bonly\s+\d+\s+(?:spots?|seats?|left)\b"
         r"|\boffer\s+expires\b|\btoday\s+only\b|\bends\s+(?:tonight|soon|in\s+\d+\s+hours?)\b",
         "artificial_scarcity", 0.10),
        (r"\benter\s+your\s+(?:password|credentials)\b"
         r"|\bverify\s+your\s+(?:identity|account|credentials)\b"
         r"|\bconfirm\s+your\s+(?:password|login|details)\b",
         "credential_harvesting", 0.22),
        (r"\bwithin\s+(?:24|48|72)\s+hours?\b"
         r"|\brespond\s+immediately\b|\bexpires\s+(?:in\s+)?\d+\s+hours?\b"
         r"|\bby\s+(?:end\s+of\s+)?(?:today|tomorrow|midnight)\b",
         "false_deadline", 0.12),
        (r"\bgift\s+cards?\b|\bwire\s+transfer\b|\bbitcoin\b|\bcrypto\b"
         r"|\bare\s+you\s+available\b|\bconfidential\s+task\b",
         "bec_trust_exploitation", 0.20),
    ]

    for pattern, tactic, weight in TACTIC_RULES:
        if re.search(pattern, text, re.IGNORECASE):
            if tactic not in tactics_found:
                tactics_found.append(tactic)
                total_adjustment += weight

    # Multi-tactic correlation boost: if 3+ tactics detected, escalate
    if len(tactics_found) >= 3:
        total_adjustment += 0.10
        tactics_found.append("multi_tactic_correlation")

    return total_adjustment, tactics_found
