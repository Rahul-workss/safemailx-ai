# ================================
# SafeMail-X Rule-Based Engine
# Phase 2.5 (Real-world rules)
# Final Refined Version
# ================================

import re
from urllib.parse import urlparse


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
    "confirm your identity",
    "suspicious activity on your account",
    "important notice regarding your account",
    "limited time to respond",
    "service interruption notice",
    "syncing paused",
    "services are paused"
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
    "high_urgency": 0.30,
    "medium_urgency": 0.18,
    "short_url": 0.35,
    "ip_url": 0.40,
    "urgency_plus_link": 0.20
}


# ======================================================
# CORE RULE ENGINE
# ======================================================

def analyze_rules(email_text: str, sender: str = "unknown_origin"):
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
    # URL detection
    # -------------------------

    urls = URL_PATTERN.findall(text)

    for url in urls:

        host = urlparse(url).hostname or ""

        # shortened URL detection
        for short in SHORT_URL_DOMAINS:
            if short in host:
                score += WEIGHTS["short_url"]
                reasons.append(f"shortened_url:{short}")
                features["structural_risk"] = True

        # IP based URL
        if IP_PATTERN.match(url):
            score += WEIGHTS["ip_url"]
            reasons.append("ip_based_url")
            features["structural_risk"] = True

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
        "amazon": ["amazon.com"]
    }
    
    sender_domain = sender.split("@")[-1] if "@" in sender else ""
    
    # Only trigger brand spoofing if:
    # 1. The email contains URLs (attack payload required)
    # 2. Urgency language was already detected (manipulation signal)
    # 3. Sender domain is known and doesn't match the brand
    has_urgency = any(r.startswith("high_urgency:") or
                      r.startswith("medium_urgency:") for r in reasons)

    if urls and has_urgency and sender_domain and sender_domain != "unknown_origin":
        for brand, auth_domains in KNOWN_BRANDS.items():
            # Use regex boundaries to prevent substring matches (e.g., "pineapple")
            if re.search(rf"\b{brand}\b", text) and sender_domain not in auth_domains:
                score += 0.35
                reasons.append(f"brand_spoof_mismatch:{brand}")
                features["structural_risk"] = True

    # -------------------------
    # Cap score
    # -------------------------

    score = min(score, 1.0)
    
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