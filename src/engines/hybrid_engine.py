import joblib

from engines.rule_engine import analyze_rules
from engines.llm_analyzer import run_llm_analysis
from engines.intent_classifier import classify_intent
from utils.config import MODEL_PATH

# Load the trained text classification model
model = joblib.load(MODEL_PATH)


# Corporate domain safelist used for conditional trust checks.
# Free mail providers are intentionally excluded.
# Expanded to 60+ to cover global banks, payment apps, gov services.
VIP_DOMAINS = {
    # Global Tech
    "google.com", "youtube.com", "facebook.com", "instagram.com", "meta.com",
    "microsoft.com", "apple.com", "icloud.com", "github.com",
    "amazon.com", "amazon.in", "paypal.com", "netflix.com",
    "linkedin.com", "twitter.com", "x.com",
    "dropbox.com", "spotify.com", "uber.com", "airbnb.com",
    "notion.so", "slack.com", "zoom.us", "atlassian.com", "adobe.com",
    # E-Commerce / Travel (India)
    "swiggy.in", "zomato.com", "flipkart.com", "myntra.com",
    "bigbasket.com", "nykaa.com", "meesho.com",
    "makemytrip.com", "goibibo.com", "irctc.co.in", "booking.com",
    # Payments / Fintech
    "paytm.com", "phonepe.com", "razorpay.com", "cashfree.com",
    "payu.in", "juspay.com", "gpay.app", "stripe.com",
    # Indian Banks
    "hdfcbank.com", "icicibank.com", "sbi.co.in", "axisbank.com",
    "kotak.com", "yesbank.in", "indusind.com", "pnb.co.in",
    "unionbankofindia.co.in", "canarabank.com",
    # Global Banks
    "chase.com", "wellsfargo.com", "bankofamerica.com", "citibank.com",
    "barclays.co.uk", "hsbc.com", "standardchartered.com",
    # Government
    "uidai.gov.in", "incometax.gov.in", "irs.gov", "gov.uk",
    "mca.gov.in", "nsdl.co.in", "sebi.gov.in",
    # OTT / Media
    "hotstar.com", "disneyplus.com", "primevideo.com",
    "jiocinema.com", "sonyliv.com",
}


def classify_risk_band(score):
    if score <= 40:
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
        ai_reasons.append("Model detected strong phishing language patterns")
    if "verify" in email_text.lower():
        ai_reasons.append("Model detected verification language")
    if "login" in email_text.lower():
        ai_reasons.append("Model detected login-related wording")
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
                  security_headers=None, auth_context="unknown",
                  url_details=None, source_type="email",
                  link_evidence_mode="none_visible"):

    analysis_steps = []
    sec_hdrs = security_headers or {}
    trust_original_auth = auth_context == "original_headers"

    # -- Pre-extract authentication signals for trust arbitration --
    sender_domain = sender.split("@")[-1].replace(">", "").strip().lower() if "@" in sender else ""
    spf_pass  = sec_hdrs.get("spf", "").lower() == "pass"
    dkim_pass = sec_hdrs.get("dkim", "").lower() == "pass"

    if not trust_original_auth:
        analysis_steps.append(
            f"Authentication trust disabled ({auth_context}); headers belong to forwarder or are unavailable")


    # Combine subject and body so all detectors see the same text context.
    combined_text = f"Subject: {subject}\n\n{email_text}"

    # ================================================================
    # LAYER 1 -- Rule Engine (structural heuristics)
    # ================================================================
    rule_score, rule_reasons, rule_features = analyze_rules(
        combined_text, sender, url_records=url_details, source_type=source_type)

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
    # LAYER 3 -- LLM Analysis (Qwen 2.5 via LM Studio)
    # ================================================================
    security_summary = _build_security_summary(sec_hdrs) if trust_original_auth else ""
    llm_channel = "email"
    if source_type == "sms":
        llm_channel = "sms"
    elif source_type == "text":
        llm_channel = "text"
    elif source_type == "url":
        llm_channel = "url"
    elif source_type in {"file", "screenshot"}:
        llm_channel = "file"

    llm_result    = run_llm_analysis(
        channel=llm_channel,
        email_text=combined_text,
        subject=subject,
        sender=sender,
        security_summary=security_summary,
    )
    llm_score     = None
    llm_reasons   = []
    llm_tactics   = []
    llm_available = False

    if llm_result is not None:
        llm_available = True
        llm_score     = llm_result["llm_score"]
        llm_intent    = llm_result.get("intent", "")
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
    # ENSEMBLE SCORING - multi-signal correlation and veto logic
    # ================================================================
    conflict_detected = False

    if llm_available and llm_score is not None:
        llm_confidence = llm_result.get("confidence", 0.5)

        # 1. Base correlation across the active detectors
        # If multiple engines trigger at moderate levels, escalate the result.
        if rule_score > 0.3 and ai_score > 0.4 and llm_score > 0.4:
            base_score = max(rule_score, ai_score, llm_score) + 0.15
            analysis_steps.append("Correlation Engine: Multiple weak signals escalated threat.")
        else:
            base_score = (0.2 * rule_score) + (0.3 * ai_score) + (0.5 * llm_score)
        
        final_score = base_score

        # 2. Smart veto logic
        if llm_score > 0.75:
            if llm_confidence > 0.8:
                final_score = max(final_score, llm_score)
                analysis_steps.append(f"Smart Veto: HARD VETO triggered by high LLM confidence ({llm_confidence}).")
                conflict_detected = True
            elif llm_confidence > 0.6:
                final_score = max(final_score, llm_score * 0.85)
                analysis_steps.append(f"Smart Veto: SOFT VETO triggered (confidence {llm_confidence}).")
        elif (llm_score < 0.25 and llm_confidence >= 0.8) or (llm_score == 0.0 and llm_intent == "conversational"):
            if llm_score == 0.0 and rule_score == 0.0:
                final_score = 0.0
                analysis_steps.append("Smart Veto: ABSOLUTE SAFE override triggered (score forced to 0).")
            else:
                final_score = min(final_score, llm_score + 0.1)
                analysis_steps.append(f"Smart Veto: SAFE override triggered by high LLM confidence ({llm_confidence}).")
             
    else:
        # ==========================================================
        # FALLBACK SCORING — Intent-Gated Calibrated Blending
        # Mirrors the LLM's calibrated score ranges per scenario.
        # ==========================================================

        # -- Step A: Determine intent for ceiling/floor logic --
        detected_intent = classify_intent(combined_text, url_details)
        analysis_steps.append(f"Intent classifier: {detected_intent}")

        # -- Step B: Calculate Base Blend --
        # Rule engine is now heavily enhanced so give it up to 70% weight.
        if rule_features.get("structural_risk", False):
            base_blend = (0.70 * rule_score) + (0.30 * ai_score)
            analysis_steps.append("Structural risk present — rule engine weighted 70%.")
        else:
            base_blend = (0.55 * rule_score) + (0.45 * ai_score)
            analysis_steps.append("No structural risk — balanced blend (55/45).")

        # -- Step C: Attack Vector Gate (False Positive Killer) --
        # If there are no URLs and no attachments, it is PHYSICALLY IMPOSSIBLE
        # for this to be a credential-harvesting attack.
        # Exception: BEC/financial fraud is conversational by design.
        has_attack_vector = bool(url_details) or attachment_score is not None
        bec_intent = detected_intent in {"financial_fraud", "malware_delivery"}

        if not has_attack_vector and not bec_intent:
            final_score = min(base_blend, 0.35)
            analysis_steps.append(
                "Attack Vector Gate: No links or attachments detected. "
                f"Credential theft impossible. Score capped at 0.35 (was {base_blend:.3f}).")
        else:
            final_score = base_blend

        # -- Step D: Apply Intent-Based Ceiling/Floor (LLM calibrated ranges) --
        if detected_intent == "conversational":
            if rule_score == 0.0:
                final_score = 0.0
                analysis_steps.append("Intent ceiling: conversational with 0 rule score → forced to 0.0")
            else:
                final_score = min(final_score, 0.10)
                analysis_steps.append("Intent ceiling: conversational → max 0.10")
        elif detected_intent == "benign_notification":
            final_score = min(final_score, 0.30)
            analysis_steps.append("Intent ceiling: benign_notification → max 0.30")
        elif detected_intent == "marketing":
            final_score = min(final_score, 0.35)
            analysis_steps.append("Intent ceiling: marketing → max 0.35")
        elif detected_intent == "authority_impersonation":
            final_score = max(final_score, 0.50)
            analysis_steps.append("Intent floor: authority_impersonation → min 0.50")
        elif detected_intent == "financial_fraud":
            final_score = max(final_score, 0.55)
            analysis_steps.append("Intent floor: financial_fraud/BEC → min 0.55")
        elif detected_intent == "credential_theft":
            final_score = max(final_score, 0.65)
            analysis_steps.append("Intent floor: credential_theft → min 0.65")
        elif detected_intent == "malware_delivery":
            final_score = max(final_score, 0.70)
            analysis_steps.append("Intent floor: malware_delivery → min 0.70")
        else:
            # Unknown intent: use plain blend, let conflict detection decide
            if rule_score > 0.7 and ai_score > 0.7:
                final_score = max(rule_score, ai_score)
                analysis_steps.append("Strong agreement: both engines high — using max.")
            elif rule_score < 0.3 and ai_score > 0.8:
                final_score = 0.60
                conflict_detected = True
                analysis_steps.append("Conflict: TF-IDF high but rules low — capped at 0.60.")
            elif rule_score == 0.0 and not has_attack_vector:
                # Rule engine found NOTHING and there are no links/attachments.
                # TF-IDF alone cannot justify a score above 0.20.
                # This is the final safety net for: short text, no URLs, no rule hits,
                # intent unknown (e.g. typos like "heyy" the classifier missed).
                final_score = min(base_blend, 0.20)
                analysis_steps.append(
                    f"Safety Net: rule=0, no attack vector, unknown intent — "
                    f"TF-IDF alone capped at 0.20 (was {base_blend:.3f}).")
            else:
                analysis_steps.append("Unknown intent: standard blend applied.")

    # -- Confidence override for extreme rule/model scores ----------------------
    active_scores = [s for s in [rule_score, ai_score, llm_score] if s is not None]
    
    # Do NOT apply the extreme safety override if the LLM explicitly vetoed as SAFE
    is_safe_veto = llm_available and (llm_score is not None) and (
        (llm_score < 0.25 and llm_confidence >= 0.8) or (llm_score == 0.0 and llm_intent == "conversational")
    )
    
    if not is_safe_veto:
        if any(s > 0.95 for s in active_scores) or rule_score > 0.9:
            final_score = max(final_score, 0.9)
            analysis_steps.append("Safety Limit: Confidence override triggered")

    # -- Conditional trust based on authentication signals ----------------------
    sender_domain = sender.split("@")[-1].lower() if "@" in sender else ""
    spf_pass  = sec_hdrs.get("spf", "").lower() == "pass"
    dkim_pass = sec_hdrs.get("dkim", "").lower() == "pass"

    trust_arbitration = {"tier": None, "applied": False, "reason": None}

    has_cta_mismatch = any(
        reason.startswith("cta_sender_domain_mismatch:") or
        reason.startswith("cta_resolved_domain_mismatch:")
        for reason in rule_reasons
    )

    if not trust_original_auth:
        analysis_steps.append(
            f"Authentication trust disabled ({auth_context}); headers belong to forwarder or are unavailable")
    elif sender_domain in VIP_DOMAINS and spf_pass and dkim_pass and not has_cta_mismatch:
        # Do not suppress a result that the LLM already pushed high.
        if final_score >= 0.7:
            analysis_steps.append(f"ALERT: VIP Domain '{sender_domain}' authenticated, but ignored due to high threat Veto (Compromised sender/Invoice scam).")
        else:
            # Apply a modest trust reduction when authentication is strong.
            old_score = final_score
            final_score = round(final_score * 0.75, 3)
            analysis_steps.append(f"VIP Domain '{sender_domain}' authenticated -- trust boost applied (score reduced from {old_score:.3f} to {final_score:.3f})")
            rule_reasons.append(f"vip_authenticated:{sender_domain}")
            trust_arbitration = {"tier": "vip_authenticated", "applied": True, "reason": sender_domain}
    elif sender_domain in VIP_DOMAINS and (not spf_pass or not dkim_pass):
        # Claims to be a safelisted domain but authentication failed.
        boost = 0.15
        final_score = round(min(final_score + boost, 1.0), 3)
        analysis_steps.append(f"ALERT: Claims VIP domain '{sender_domain}' but SPF/DKIM failed -- possible spoofing (+{boost})")
        rule_reasons.append(f"vip_spoof_attempt:{sender_domain}")

    if has_cta_mismatch:
        analysis_steps.append("Trust arbitration disabled due to CTA destination mismatch.")

    screenshot_cta_words = ("claim offer now", "claim now", "redeem", "verify", "unlock", "50% off", "limited time")
    if (
        source_type == "screenshot"
        and link_evidence_mode == "none_visible"
        and not url_details
        and any(token in combined_text.lower() for token in screenshot_cta_words)
    ):
        final_score = max(final_score, 0.55)
        analysis_steps.append("Screenshot CTA present without visible destination; capped at suspicious.")

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
    final_score = min(max(final_score, 0.0), 1.0)
    risk_band = classify_risk_band(int(final_score * 100))
    if final_score >= 0.80:
        final_label = "phishing"
    elif final_score > 0.40:
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
        "auth_context":     auth_context,
        "trust_arbitration": trust_arbitration,
    }
