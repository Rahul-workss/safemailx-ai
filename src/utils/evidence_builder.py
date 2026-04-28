# ==================================
# Evidence Builder
# Creates forensic investigation data
# ==================================

import re
import uuid
from datetime import datetime


def _extract_sender_forensics(sender_raw: str, security_headers: dict) -> dict:
    """Extract structured sender identity data for forensic reporting."""
    display_name = ""
    raw_address  = sender_raw
    # Parse "Display Name <email@domain.com>" format
    m = re.match(r'^"?([^"<]*)"?\s*<([^>]+)>', sender_raw)
    if m:
        display_name = m.group(1).strip()
        raw_address  = m.group(2).strip()

    domain = security_headers.get("from_domain", "")

    return {
        "display_name":       display_name,
        "raw_address":        raw_address,
        "sender_domain":      domain,
        "reply_to":           security_headers.get("reply_to"),
        "reply_to_mismatch":  security_headers.get("reply_to_mismatch", False),
        "x_mailer":           security_headers.get("x_mailer"),
        "msg_id_domain":      security_headers.get("message_id_domain"),
        "msg_id_mismatch":    security_headers.get("message_id_mismatch", False),
    }


def _extract_top_keywords(email_body: str) -> list:
    """Heuristically extract phishing-related trigger keywords from body text."""
    PHISHING_KEYWORDS = [
        "urgent", "immediately", "verify", "suspended", "deactivated",
        "click here", "login", "confirm", "password", "account blocked",
        "billing", "payment failed", "limited time", "act now",
        "unauthorized", "security alert", "reset", "expire"
    ]
    body_lower = email_body.lower()
    found = []
    for kw in PHISHING_KEYWORDS:
        if kw in body_lower and kw not in found:
            found.append(kw)
    return found[:10]  # Cap at 10 keyword pills for PDF layout


def build_forensic_evidence(email_subject, email_body, hybrid_result,
                             attachment_result=None, security_headers=None,
                             sender_raw="", url_details=None):

    sec_hdrs = security_headers or {}
    sender_forensics = _extract_sender_forensics(sender_raw, sec_hdrs)
    top_keywords     = _extract_top_keywords(email_body)
    case_id          = f"SMX-{str(uuid.uuid4())[:8].upper()}"

    evidence = {

        "case_id":   case_id,
        "timestamp": str(datetime.utcnow()),

        "email_metadata": {
            "subject":     email_subject,
            "body_length": len(email_body)
        },

        "rule_analysis": {
            "rule_score":   hybrid_result["rule_score"],
            "rule_reasons": hybrid_result["rule_reasons"]
        },

        "ai_analysis": {
            "ai_score":    hybrid_result["ai_score"],
            "ai_reasons":  hybrid_result.get("ai_reasons", []),
            "top_keywords": top_keywords,
        },

        "llm_analysis": {
            "llm_available":    hybrid_result.get("llm_available", False),
            "llm_score":        hybrid_result.get("llm_score"),
            "llm_reasoning":    (hybrid_result.get("llm_reasons", [""])[0]
                                 if hybrid_result.get("llm_reasons")
                                 else ""),
            "llm_tactics":      hybrid_result.get("llm_tactics", []),
            "urgency_score":    (hybrid_result.get("llm_analysis") or {})
                                .get("urgency_score"),
            "legitimacy_score": (hybrid_result.get("llm_analysis") or {})
                                .get("legitimacy_score"),
            "grammar_score":    (hybrid_result.get("llm_analysis") or {})
                                .get("grammar_score"),
            "coherence_score":  (hybrid_result.get("llm_analysis") or {})
                                .get("coherence_score"),
        },

        "hybrid_decision": {
            "final_label":      hybrid_result["final_label"],
            "final_score":      hybrid_result["final_score"],
            "conflict_detected": hybrid_result.get("conflict_detected", False)
        },

        "analysis_steps": hybrid_result.get("analysis_steps", []),

        # Transmission & sender security
        "security_headers":  sec_hdrs,
        "sender_forensics":  sender_forensics,

        # Structured URL details (list of dicts, one per URL found)
        "url_details": url_details or [],

        # Attachment analysis results
        "attachment_analysis": {
            "attachment_score": attachment_result.get("attachment_score") if attachment_result else None,
            "findings":         attachment_result.get("attachment_findings", []) if attachment_result else []
        }
    }

    return evidence