from typing import Any

from engines.data_leak_engine import detect_data_leak
from engines.fraud_scam_engine import detect_fraud_scams
from engines.identity_risk_engine import detect_identity_risk
from engines.payment_risk_engine import detect_payment_risk
from engines.ransomware_malware_engine import detect_malware_ransomware
from engines.threat_taxonomy import (
    THREAT_PRIORITY,
    normalize_source_type,
    recommendation_for,
    reporting_targets_for,
)


def _unique(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _primary_from_findings(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "unknown"
    by_category = {finding["category"]: finding.get("score", 0.0) for finding in findings}
    for category in THREAT_PRIORITY:
        if category in by_category and by_category[category] >= 0.55:
            return category
    return max(findings, key=lambda item: item.get("score", 0.0)).get("category", "unknown")


def _profile_from_findings(findings: list[dict[str, Any]], source_type: str) -> dict[str, Any]:
    primary = _primary_from_findings(findings)
    categories = _unique([finding.get("category", "") for finding in sorted(findings, key=lambda item: item.get("score", 0.0), reverse=True)])
    requested_actions = _unique([
        action
        for finding in findings
        for action in finding.get("requested_actions", [])
    ]) or ["none"]
    reporting_targets = _unique([
        target
        for finding in findings
        for target in finding.get("reporting_targets", [])
    ]) or reporting_targets_for(primary)
    signals = _unique([
        signal
        for finding in findings
        for signal in finding.get("signals", [])
    ])
    risk_score = max([float(finding.get("score", 0.0)) for finding in findings], default=0.0)

    return {
        "primary_threat": primary,
        "threat_categories": categories,
        "requested_action": requested_actions[0],
        "requested_actions": requested_actions,
        "recommended_action": recommendation_for(primary),
        "reporting_targets": reporting_targets,
        "risk_score": round(risk_score, 3),
        "source_type": source_type,
        "signals": signals,
    }


def build_risk_profile(
    *,
    subject: str,
    body: str,
    sender: str = "",
    source_type: str = "email",
    hybrid_result: dict[str, Any] | None = None,
    attachment_result: dict[str, Any] | None = None,
    url_details: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    normalized_source = normalize_source_type(source_type)
    full_text = f"Subject: {subject}\nSender: {sender}\n\n{body}"
    findings: list[dict[str, Any]] = []
    findings.extend(detect_fraud_scams(subject, body, sender))
    findings.extend(detect_payment_risk(full_text))
    findings.extend(detect_identity_risk(full_text))
    findings.extend(detect_data_leak(full_text))
    findings.extend(detect_malware_ransomware(full_text, attachment_result))

    hybrid = hybrid_result or {}
    if hybrid.get("final_label") == "phishing" or hybrid.get("llm_score", 0) and hybrid.get("llm_score", 0) >= 0.75:
        findings.append({
            "category": "phishing",
            "score": max(0.72, float(hybrid.get("final_score", 0.0))),
            "signals": ["existing_phishing_pipeline_high_risk"],
            "requested_actions": ["login"] if "login" in full_text.lower() else ["none"],
            "reporting_targets": ["IC3", "employer IT"],
        })

    if url_details and any(detail.get("flags") for detail in url_details):
        findings.append({
            "category": "phishing",
            "score": 0.66,
            "signals": ["suspicious_url_context"],
            "requested_actions": ["login"] if normalized_source == "url" else ["none"],
            "reporting_targets": ["IC3", "employer IT"],
        })

    return _profile_from_findings(findings, normalized_source)


def build_domain_risk_profile(domain_analysis: dict[str, Any]) -> dict[str, Any]:
    signals = list(domain_analysis.get("signals", []) or [])
    risk_score = float(domain_analysis.get("risk_score", 0.0) or 0.0)
    findings = []
    if signals:
        findings.append({
            "category": "domain_exposure",
            "score": risk_score,
            "signals": signals,
            "requested_actions": ["none"],
            "reporting_targets": ["employer IT"],
        })
    return _profile_from_findings(findings, "domain")


def apply_risk_profile_to_hybrid_result(result: dict[str, Any], risk_profile: dict[str, Any]) -> dict[str, Any]:
    risk_score = float(risk_profile.get("risk_score", 0.0) or 0.0)
    primary = risk_profile.get("primary_threat", "unknown")
    if risk_score <= 0:
        return result

    original_score = float(result.get("final_score", 0.0) or 0.0)
    adjusted = max(original_score, risk_score)
    high_social_or_malware = primary in {
        "phishing",
        "bec_payment_fraud",
        "investment_crypto_scam",
        "tech_support_scam",
        "romance_social_scam",
        "malware_delivery",
        "ransomware_risk",
        "credential_theft",
        "identity_takeover",
    }

    if adjusted >= 0.80 and high_social_or_malware:
        result["final_label"] = "phishing"
    elif adjusted > 0.40:
        result["final_label"] = "suspicious"

    if adjusted > original_score:
        result["final_score"] = round(min(adjusted, 1.0), 3)
        result.setdefault("analysis_steps", []).append(
            f"Cyber-risk profile raised score from {original_score:.3f} to {result['final_score']:.3f} ({primary})."
        )
    return result
