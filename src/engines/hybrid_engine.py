import joblib
import numpy as np

from engines.rule_engine import analyze_rules
from engines.llm_analyzer import run_llm_analysis

# Load trained AI model
MODEL_PATH = "../models/phishing_ai_model.joblib"
model = joblib.load(MODEL_PATH)


# -- VIP Domain Safe-List (Zero-Trust: ONLY corporate domains) ----------------
# Free providers (gmail.com, outlook.com, yahoo.com) are EXCLUDED.
VIP_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "instagram.com", "meta.com",
    "microsoft.com", "apple.com", "icloud.com",
    "amazon.com", "amazon.in", "paypal.com", "netflix.com",
    "linkedin.com", "twitter.com", "x.com", "github.com",
    "dropbox.com", "spotify.com", "uber.com",
    "swiggy.in", "zomato.com", "flipkart.com", "myntra.com",
    "paytm.com", "phonepe.com",
}


def classify_risk_band(score):
    if score <= 35:
        return "SAFE"
    elif score <= 80:
        return "SUSPICIOUS"
    else:
        return "CRITICAL"


def run_ai_model(email_text):
    # Guard against empty/very short text
    if len(email_text.strip()) < 5:
        return 0.3, ["Insufficient text for semantic analysis "
                      "-- image-based payload suspected"]

    probability = model.predict_proba([email_text])[0][1]
    ai_score = float(probability)
    ai_reasons = []
    if probability > 0.8:
        ai_reasons.append("AI detected strong phishing language patterns")
    if "verify" in email_text.lower():
        ai_reasons.append("AI detected verification language")
    if "login" in email_text.lower():
        ai_reasons.append("AI detected login related wording")
    return ai_score, ai_reasons


def _build_security_summary(security_headers: dict) -> str:
    """Build a one-line summary of SPF/DKIM/DMARC for the LLM prompt."""
    if not security_headers:
        return ""
    spf   = security_headers.get("spf", "unknown")
    dkim  = security_headers.get("dkim", "unknown")
    dmarc = security_headers.get("dmarc", "unknown")
    return f"SPF={spf}, DKIM={dkim}, DMARC={dmarc}"


def hybrid_detect(subject, email_text, sender="unknown_origin",
                  attachment_score=None, url_flags=None,
                  security_headers=None):

    analysis_steps = []
    sec_hdrs = security_headers or {}

    # [BUGFIX] Combine Subject with Body so the engines aren't blind
    combined_text = f"Subject: {subject}\n\n{email_text}"

    # ================================================================
    # LAYER 1 -- Rule Engine (structural heuristics)
    # ================================================================
    rule_score, rule_reasons, rule_features = analyze_rules(
        combined_text, sender)

    # Merge URL analyzer flags into rule score
    if url_flags:
        for flag in url_flags:
            if flag not in rule_reasons:
                rule_reasons.append(flag)
                rule_score = min(rule_score + 0.15, 1.0)
        analysis_steps.append(
            f"URL analyzer added {len(url_flags)} threat signal(s)")

    analysis_steps.append(f"Rule engine produced score {rule_score}")

    # ================================================================
    # LAYER 2 -- TF-IDF + Logistic Regression (statistical NLP)
    # ================================================================
    ai_score, ai_reasons = run_ai_model(combined_text)
    analysis_steps.append(f"AI model semantic probability {ai_score}")

    # ================================================================
    # LAYER 3 -- LLM Feature Extraction (Qwen 3.5 via LM Studio)
    # ================================================================
    security_summary = _build_security_summary(sec_hdrs)
    llm_result    = run_llm_analysis(combined_text,
                                     subject=subject, sender=sender,
                                     security_summary=security_summary)
    llm_score     = None
    llm_reasons   = []
    llm_tactics   = []
    llm_available = False

    if llm_result is not None:
        llm_available = True
        llm_score     = llm_result["llm_score"]
        llm_tactics   = llm_result.get("tactics", [])
        llm_reasons   = [llm_result.get("reasoning", "")]
        analysis_steps.append(
            f"LLM deep analysis: threat={llm_score:.3f}, "
            f"urgency={llm_result.get('urgency_score')}/10, "
            f"tactics={llm_tactics or 'none'}")
    else:
        analysis_steps.append(
            "LLM unavailable -- using Rule + TF-IDF fallback")

    # ================================================================
    # ENSEMBLE SCORING - SIEM CORRELATION & SMART VETO
    # ================================================================
    conflict_detected = False

    if llm_available and llm_score is not None:
        llm_confidence = llm_result.get("confidence", 0.5)

        # 1. Base SIEM Correlation (Multi-signal fusion)
        # If multiple distinct engines trigger at moderate levels, escalate the threat dynamically
        if rule_score > 0.3 and ai_score > 0.4 and llm_score > 0.4:
            base_score = max(rule_score, ai_score, llm_score) + 0.15
            analysis_steps.append("Correlation Engine: Multiple weak signals escalated threat.")
        else:
            base_score = (0.2 * rule_score) + (0.3 * ai_score) + (0.5 * llm_score)
        
        final_score = base_score

        # 2. Smart Veto System (Graded Authority)
        if llm_score > 0.75:
            if llm_confidence > 0.8:
                final_score = max(final_score, llm_score)
                analysis_steps.append(f"Smart Veto: HARD VETO triggered by high LLM confidence ({llm_confidence}).")
                conflict_detected = True
            elif llm_confidence > 0.6:
                final_score = max(final_score, llm_score * 0.85)
                analysis_steps.append(f"Smart Veto: SOFT VETO triggered (confidence {llm_confidence}).")
        elif llm_score < 0.25 and llm_confidence > 0.8:
             final_score = min(final_score, llm_score + 0.1)
             analysis_steps.append(f"Smart Veto: SAFE override triggered by high LLM confidence ({llm_confidence}).")
             
    else:
        # ---------- TWO-BRAIN FALLBACK (LLM offline) ----------
        if rule_score > 0.7 and ai_score > 0.7:
            final_score = max(rule_score, ai_score)
            analysis_steps.append("Rule engine and AI strongly agree on phishing")
        elif rule_score < 0.3 and ai_score > 0.8:
            final_score = 0.6
            conflict_detected = True
            analysis_steps.append("Conflict detected: AI high but rules low")
        else:
            if rule_features.get("structural_risk", False):
                final_score = (0.7 * rule_score) + (0.3 * ai_score)
                analysis_steps.append("Structural indicators -- rule weighted higher")
            else:
                final_score = (0.4 * rule_score) + (0.6 * ai_score)
                analysis_steps.append("Language indicators -- AI weighted higher")

    # -- Confidence override (Extreme rules/ML) --------------------------------
    active_scores = [s for s in [rule_score, ai_score, llm_score] if s is not None]
    if any(s > 0.95 for s in active_scores) or rule_score > 0.9:
        final_score = max(final_score, 0.9)
        analysis_steps.append("Safety Limit: Confidence override triggered")

    # -- Conditional Trust Authentication --------------------------------------
    sender_domain = sender.split("@")[-1].lower() if "@" in sender else ""
    spf_pass  = sec_hdrs.get("spf", "").lower() == "pass"
    dkim_pass = sec_hdrs.get("dkim", "").lower() == "pass"

    if sender_domain in VIP_DOMAINS and spf_pass and dkim_pass:
        # Check if the LLM already vetoed this as a high threat
        if final_score >= 0.7:
            analysis_steps.append(f"ALERT: VIP Domain '{sender_domain}' authenticated, but ignored due to high threat Veto (Compromised sender/Invoice scam).")
        else:
            # Safe authentication -- apply a subtle 25% trust boost instead of a blind 50% slash
            old_score = final_score
            final_score = round(final_score * 0.75, 3)
            analysis_steps.append(f"VIP Domain '{sender_domain}' authenticated -- trust boost applied (score reduced from {old_score:.3f} to {final_score:.3f})")
            rule_reasons.append(f"vip_authenticated:{sender_domain}")
    elif sender_domain in VIP_DOMAINS and (not spf_pass or not dkim_pass):
        # Claims to be VIP but authentication FAILED -- potential spoof
        boost = 0.15
        final_score = round(min(final_score + boost, 1.0), 3)
        analysis_steps.append(f"ALERT: Claims VIP domain '{sender_domain}' but SPF/DKIM failed -- possible spoofing (+{boost})")
        rule_reasons.append(f"vip_spoof_attempt:{sender_domain}")

    # -- Attachment score merge ------------------------------------------------
    if attachment_score is not None:
        if attachment_score > 0.4:
            boost = round(attachment_score * 0.30, 3)
            final_score = round(min(final_score + boost, 1.0), 3)
            analysis_steps.append(
                f"Attachment boost +{boost} "
                f"(attachment_score={attachment_score})")
        else:
            analysis_steps.append(
                f"Attachment clean (score={attachment_score})")

    # -- Final classification --------------------------------------------------
    risk_band = classify_risk_band(int(final_score * 100))
    if final_score >= 0.80:
        final_label = "phishing"
    elif final_score > 0.35:
        final_label = "suspicious"
    else:
        final_label = "legitimate"
    analysis_steps.append(f"Final risk band: {risk_band}")

    return {
        "final_label":      final_label,
        "final_score":      round(final_score, 3),
        "ai_score":         round(ai_score, 3),
        "rule_score":       round(rule_score, 3),
        "llm_score":        round(llm_score, 3) if llm_score is not None
                            else None,
        "rule_reasons":     rule_reasons,
        "ai_reasons":       ai_reasons,
        "llm_reasons":      llm_reasons,
        "llm_tactics":      llm_tactics,
        "llm_analysis":     llm_result,
        "llm_available":    llm_available,
        "analysis_steps":   analysis_steps,
        "conflict_detected": conflict_detected,
    }
