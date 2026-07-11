# ================================
# SafeMail X Rule-Based Engine
# Phase 3.0 — LLM-Parity Heuristics
# Upgraded to mirror the LLM 3-phase forensic protocol
# using deterministic sub-scorers.
# ================================

import re
from urllib.parse import urlparse

from utils.url_extractor import extract_urls
from engines.intent_classifier import (
    score_specificity,
    score_manipulation,
    score_grammar,
    score_social_engineering_tactics,
)


# -------- REAL-WORLD URGENCY PHRASES --------

HIGH_URGENCY_PHRASES = [
    "immediate action required",
    "action required",
    "verification required",
    "your account will be suspended",
    "your account will be deactivated",
    "account has been blocked",
    "account blocked",
    "your access will expire",
    "account suspension notice",
    "unauthorized activity detected",
    "security alert regarding your account",
    "password reset required",
    "billing issue payment failed",
    "final reminder before suspension",
    "last chance to avoid deactivation",
    "will be removed",
    "storage full",
    "limit reached"
]

MEDIUM_URGENCY_PHRASES = [
    "please verify your account",
    "please verify your email",
    "confirm your identity",
    "suspicious activity on your account",
    "important notice regarding your account",
    "limited time to respond",
    "service interruption notice",
    "syncing paused",
    "service interruption notice",
    "syncing paused",
    "services are paused"
]

# -------- SMS/TEXT SPECIFIC PHRASES --------

SMS_SCAM_PHRASES = [
    "reply stop",
    "package held at customs",
    "delivery attempt failed",
    "schedule your delivery",
    "unpaid toll fee",
    "lottery winner",
    "bank otp",
    "unusual activity on your card",
    "netflix subscription expired",
    "claim your prize",
    "click here to track",
]

LOW_URGENCY_WORDS = [
    "urgent",
    "immediately",
    "attention required",
    "act now"
]


# -------- ABUSED SHORT URL SERVICES --------

SHORT_URL_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "tiny.cc",
    "t.co",
    "ow.ly",
    "is.gd",
    "rebrand.ly",
    "t.ly",
    "qrco.de",
    "goo.su",
    "bit.do",
    "migre.me",
    "6url.ru",
    "shorturl.at",
    "soo.gd",
    "shorte.st",
    "lnkd.in"
]


# -------- REGEX PATTERNS --------

URL_PATTERN = re.compile(r"https?://\S+")
IP_PATTERN = re.compile(r"https?://\d+\.\d+\.\d+\.\d+")


# -------- RULE WEIGHTS (0–1 scale) --------

WEIGHTS = {
    "high_urgency": 0.25,        # Reduced slightly — tactics scorer now adds more precisely
    "medium_urgency": 0.15,
    "short_url": 0.35,
    "ip_url": 0.40,
    "urgency_plus_link": 0.18,
    "sms_scam_phrase": 0.45,
    "promo_cta": 0.10,           # Reduced — marketing intent cap handles this better
    "promo_deadline": 0.10,
    "cta_domain_mismatch": 0.38,
    "screenshot_cta_no_visible_url": 0.45,
    # Feature 1: QR quishing — QR code is the ONLY URL delivery mechanism
    "qr_hidden_url": 0.30,
}


# ======================================================
# CORE RULE ENGINE
# ======================================================

def analyze_rules(
    email_text: str,
    sender: str = "unknown_origin",
    url_records: list[dict] | None = None,
    source_type: str = "email",
):
    """
    Input  : email text (subject + body combined)
    Output : rule_score (0–100),
             rule_reasons (list),
             rule_features (dict)
    """

    text = email_text.lower()

    score = 0.0
    reasons = []

    # features used by hybrid engine
    features = {
        "structural_risk": False
    }

    # -------------------------
    # High urgency phrases
    # -------------------------

    for phrase in HIGH_URGENCY_PHRASES:
        if phrase in text:
            score += WEIGHTS["high_urgency"]
            reasons.append(f"high_urgency:{phrase}")

    # -------------------------
    # Medium urgency phrases
    # -------------------------

    for phrase in MEDIUM_URGENCY_PHRASES:
        if phrase in text:
            score += WEIGHTS["medium_urgency"]
            reasons.append(f"medium_urgency:{phrase}")

    # -------------------------
    # SMS Scam phrases
    # -------------------------

    for phrase in SMS_SCAM_PHRASES:
        if phrase in text:
            score += WEIGHTS.get("sms_scam_phrase", 0.45)
            reasons.append(f"sms_scam_phrase:{phrase}")

    # -------------------------
    # URL detection
    # -------------------------

    url_records = url_records or extract_urls(text)
    urls = [record["normalized_url"] for record in url_records]

    for url in urls:

        host = urlparse(url).hostname or ""

        # shortened URL detection
        for short in SHORT_URL_DOMAINS:
            if host == short or host.endswith("." + short):
                score += WEIGHTS["short_url"]
                reasons.append(f"shortened_url:{short}")
                features["structural_risk"] = True

        # IP based URL
        if IP_PATTERN.match(url):
            score += WEIGHTS["ip_url"]
            reasons.append("ip_based_url")
            features["structural_risk"] = True

    promo_phrases = ["50% off", "limited time", "birthday", "anniversary", "special offer", "exclusive offer"]
    cta_present = any(
        record.get("is_cta") or any(token in ((record.get("anchor_text") or "").lower()) for token in ("claim", "redeem", "unlock", "upgrade", "offer"))
        for record in url_records
    )
    promo_present = any(phrase in text for phrase in promo_phrases)
    has_deadline = any(token in text for token in ("today only", "expires", "until may", "last chance", "ends tonight"))

    if promo_present and cta_present:
        score += WEIGHTS["promo_cta"]
        reasons.append("promo_cta_lure")

    if promo_present and has_deadline and cta_present:
        score += WEIGHTS["promo_deadline"]
        reasons.append("promo_cta_deadline")

    for record in url_records:
        flags = record.get("flags", [])
        if any("domain_mismatch" in flag for flag in flags):
            score += WEIGHTS["cta_domain_mismatch"]
            reasons.append("cta_destination_domain_mismatch")
            features["structural_risk"] = True

    if source_type == "screenshot" and not urls:
        screenshot_cta = any(token in text for token in ("claim offer now", "redeem now", "unlock offer", "claim now", "50% off", "limited time"))
        if screenshot_cta:
            score += WEIGHTS["screenshot_cta_no_visible_url"]
            reasons.append("screenshot_cta_without_visible_destination")

    # -------------------------
    # Urgency + link combo
    # -------------------------

    if urls and reasons:
        score += WEIGHTS["urgency_plus_link"]
        reasons.append("urgency_and_link_combined")

    # -------------------------
    # Brand Spoofing Analysis
    # -------------------------
    
    KNOWN_BRANDS = {
        "apple": ["apple.com"],
        "google": ["google.com", "gmail.com"],
        "paypal": ["paypal.com"],
        "microsoft": ["microsoft.com", "outlook.com", "live.com"],
        "netflix": ["netflix.com"],
        "amazon": ["amazon.com"],
        "aaa": ["aaa.com"]
    }
    
    sender_domain = sender.split("@")[-1] if "@" in sender else ""
    
    # Only trigger brand spoofing if:
    # 1. The email contains URLs (attack payload required)
    # 2. Urgency language was already detected (manipulation signal)
    # 3. Sender domain is known and doesn't match the brand
    has_urgency = any(r.startswith("high_urgency:") or
                      r.startswith("medium_urgency:") for r in reasons)

    if urls and has_urgency and sender_domain and sender_domain != "unknown_origin":
        search_text = text + " " + sender.lower()
        for brand, auth_domains in KNOWN_BRANDS.items():
            # Use regex boundaries to prevent substring matches (e.g., "pineapple")
            if re.search(rf"\b{brand}\b", search_text) and sender_domain not in auth_domains:
                score += 0.45
                reasons.append(f"brand_spoof_mismatch:{brand}")
                features["structural_risk"] = True

    # ================================================================
    # PHASE 2 — Social Engineering Tactics (LLM parity)
    # Detects all 8 manipulation tactics with calibrated weights.
    # ================================================================
    tactic_adjustment, tactic_list = score_social_engineering_tactics(text)
    score += tactic_adjustment
    for t in tactic_list:
        reasons.append(f"tactic:{t}")
    if tactic_adjustment > 0:
        features["structural_risk"] = True

    # ================================================================
    # PHASE 3 — Specificity Scorer (False Positive Reducer)
    # Real emails are specific (order ID, card digits, name).
    # Phishing is always vague. Adjust score accordingly.
    # ================================================================
    spec_adjustment, spec_reasons = score_specificity(email_text)
    score += spec_adjustment          # spec_adjustment is negative = reduces score
    reasons.extend(spec_reasons)

    # ================================================================
    # PHASE 4 — Manipulation Language Scorer
    # Generic greetings, vague references, extreme consequence language.
    # ================================================================
    manip_adjustment, manip_reasons = score_manipulation(text)
    score += manip_adjustment
    reasons.extend(manip_reasons)

    # ================================================================
    # PHASE 5 — Grammar & Coherence Scorer
    # ALL CAPS ratio, excessive punctuation, non-ASCII mixed chars.
    # ================================================================
    gram_adjustment, gram_reasons = score_grammar(text)
    score += gram_adjustment
    reasons.extend(gram_reasons)

    # -------------------------
    # Cap score (0 to 1)
    # -------------------------
    score = max(0.0, min(score, 1.0))

    return float(score), list(set(reasons)), features


# ======================================================
# QUICK TEST
# ======================================================

if __name__ == "__main__":

    subject = "Immediate Action Required – Account Suspension"

    body = """
    Your account will be deactivated in 24 hours.
    Please verify now using http://t.ly/secure-login
    """

    text = subject + " " + body

    score, reasons, features = analyze_rules(text)

    print("Rule Score:", score)
    print("Reasons:", reasons)
    print("Features:", features)
