import re
from engines.url_analyzer import analyze_urls

def extract_sms_artifacts(text: str) -> dict:
    url_pattern = re.compile(r'(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?«»""'']))')
    urls = [match[0] for match in url_pattern.findall(text)]
    
    phone_pattern = re.compile(r'\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}')
    phones = phone_pattern.findall(text)
    
    return {
        "urls": urls,
        "phone_numbers": phones
    }

def analyze_sms(text: str, sender: str = None) -> tuple[float, list[str]]:
    artifacts = extract_sms_artifacts(text)
    signals = []
    base_risk = 0.0
    
    text_lower = text.lower()
    
    # 1. Structural Lures
    has_urgency = any(w in text_lower for w in ["urgent", "action required", "act now", "immediate", "suspended", "locked"])
    has_otp = any(w in text_lower for w in ["otp", "code", "verification", "auth"])
    has_package = any(w in text_lower for w in ["package", "delivery", "usps", "fedex", "ups", "dhl", "tracking"])
    has_reward = any(w in text_lower for w in ["won", "prize", "claim", "reward", "selected", "gift"])
    
    # 2. Extract URLs and check them
    urls_checked = analyze_urls(artifacts["urls"])
    if any("SafeBrowsing_Match" in u for u in urls_checked):
        signals.append("malicious_url_safe_browsing")
        base_risk += 1.0
    if "shortened_url" in urls_checked:
        signals.append("shortened_url")
        base_risk += 0.3
    
    # 3. Combine heuristics
    if has_package and artifacts["urls"]:
        signals.append("package_delivery_lure_with_link")
        base_risk += 0.4
    if has_reward and artifacts["urls"]:
        signals.append("reward_lure_with_link")
        base_risk += 0.5
    if has_urgency and has_otp:
        signals.append("urgent_otp_lure")
        base_risk += 0.3
    
    if has_otp and not artifacts["urls"] and not has_urgency:
        signals.append("benign_otp_structure")
        base_risk -= 0.5 # False positive suppression
        
    # Cap risk
    risk = max(0.0, min(1.0, base_risk))
    
    # Return formatted signals for QuickScanSignal later
    return risk, signals, artifacts
