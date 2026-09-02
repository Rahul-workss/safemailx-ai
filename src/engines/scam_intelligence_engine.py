"""
SafeMailX — Scam Intelligence Engine
Coordinates the 7-layer call scam detection pipeline.
Used by the Hold + Describe feature.
"""
import logging
from typing import Optional

from engines.layers import (
    isolation_detector,
    information_asymmetry,
    policy_verification,
    manipulation_sequence,
    script_library,
    knowledge_profiler,
    conversation_dynamics,
)

logger = logging.getLogger("SCAM_INTELLIGENCE")

# Layer weights (must sum to 1.0)
LAYER_WEIGHTS = {
    "policy_verification":    0.22,
    "information_asymmetry":  0.20,
    "isolation_signal":       0.18,
    "manipulation_sequence":  0.15,
    "script_library":         0.12,
    "knowledge_profiler":     0.08,
    "conversation_dynamics":  0.05,
}


def _build_transcript(claims: dict) -> str:
    """For Path B (structured), build a synthetic transcript from checkbox data."""
    parts = []
    org = claims.get("org_claimed", "")
    if org:
        parts.append(f"Caller claimed to be from {org}.")
    actions = claims.get("actions_requested", [])
    if actions:
        parts.append(f"They asked for: {', '.join(actions)}.")
    warnings = claims.get("warning_phrases", [])
    if warnings:
        parts.append(f"They said: {'. '.join(warnings)}.")
    return " ".join(parts)


def _get_recommended_action(risk_band: str, org_callback: str = "") -> str:
    if risk_band == "CRITICAL":
        return "Hang up immediately. Do not share any information. Report at cybercrime.gov.in or call 1930."
    elif risk_band == "SUSPICIOUS":
        callback_str = f" Call {org_callback} to verify." if org_callback else ""
        return f"Be very cautious. Do not share OTP, passwords, or card details. Hang up and call the organization's official number directly.{callback_str}"
    else:
        return "Call appears relatively safe. Stay alert — never share OTPs or passwords regardless of who is calling."


def analyze(input_data: dict) -> dict:
    """
    Main entry point for call scam analysis.
    
    input_data keys:
        transcript      : str  — voice description or synthetic
        org_claimed     : str
        actions_requested: list[str]
        warning_phrases : list[str]
        input_mode      : str  — 'voice' | 'structured'
    """
    input_mode = input_data.get("input_mode", "structured")
    transcript = input_data.get("transcript", "")
    org_claimed = input_data.get("org_claimed", "")
    actions_requested = input_data.get("actions_requested", [])
    warning_phrases = input_data.get("warning_phrases", [])

    # Build synthetic transcript for structured input
    claims = {
        "org_claimed": org_claimed,
        "actions_requested": actions_requested,
        "warning_phrases": warning_phrases,
    }

    if input_mode == "structured" or not transcript.strip():
        transcript = _build_transcript(claims)
        # Also append warning phrases to transcript for keyword detection
        transcript += " " + " ".join(warning_phrases)

    logger.info("[SCAM_INTEL] Analyzing call. mode=%s org='%s' transcript_len=%d",
                input_mode, org_claimed, len(transcript))

    # Run all 7 layers
    layer_results = {
        "policy_verification":   policy_verification.analyze(transcript, claims),
        "information_asymmetry": information_asymmetry.analyze(transcript, claims),
        "isolation_signal":      isolation_detector.analyze(transcript, claims),
        "manipulation_sequence": manipulation_sequence.analyze(transcript, claims),
        "script_library":        script_library.analyze(transcript, claims),
        "knowledge_profiler":    knowledge_profiler.analyze(transcript, claims),
        "conversation_dynamics": conversation_dynamics.analyze(transcript, claims),
    }

    # Find hard floors
    hard_floors_triggered = []
    floor_score = 0.0
    official_callback = ""

    for layer_name, result in layer_results.items():
        hf = result.get("hard_floor")
        if hf and hf > floor_score:
            floor_score = hf
            hard_floors_triggered.append(f"{layer_name}: {hf}")
        # Collect official callback number
        if result.get("official_callback"):
            official_callback = result["official_callback"]

    # Also from policy result
    if layer_results["policy_verification"].get("official_callback"):
        official_callback = layer_results["policy_verification"]["official_callback"]

    # Calculate weighted composite score
    composite_score = sum(
        layer_results[layer_name]["score"] * weight
        for layer_name, weight in LAYER_WEIGHTS.items()
        if layer_name in layer_results
    )

    # Final score = max of composite and floor
    final_score = max(composite_score, floor_score)
    final_score = round(min(1.0, final_score), 3)

    # Risk band
    if final_score > 0.70:
        risk_band = "CRITICAL"
    elif final_score >= 0.40:
        risk_band = "SUSPICIOUS"
    else:
        risk_band = "SAFE"

    # Signals fired
    signals_fired = [
        name for name, result in layer_results.items()
        if result.get("score", 0) > 0.30
    ]

    # Build top 3 why_flagged bullets
    sorted_layers = sorted(
        [(name, res) for name, res in layer_results.items() if res.get("score", 0) > 0.30],
        key=lambda x: x[1]["score"],
        reverse=True
    )
    why_flagged = [res["plain_english"] for _, res in sorted_layers[:3]]

    # Full explanation
    org_display = org_claimed or "Unknown Organization"
    explanation_parts = [f"Caller claimed to be from: {org_display}."]
    if why_flagged:
        explanation_parts.append("Why SafeMail X flagged this call:")
        for bullet in why_flagged:
            explanation_parts.append(f"• {bullet}")
    full_explanation = "\n".join(explanation_parts)

    recommended_action = _get_recommended_action(risk_band, official_callback)

    result = {
        "final_score": final_score,
        "risk_band": risk_band,
        "score_display": round(final_score * 100),
        "org_claimed": org_claimed,
        "purpose_detected": ", ".join(actions_requested) if actions_requested else "Unknown",
        "layer_results": {
            name: {
                "score": round(res["score"], 3),
                "finding": res["finding"],
                "plain_english": res["plain_english"]
            }
            for name, res in layer_results.items()
        },
        "signals_fired": signals_fired,
        "hard_floors_triggered": hard_floors_triggered,
        "composite_score": round(composite_score, 3),
        "floor_score": round(floor_score, 3),
        "full_explanation": full_explanation,
        "why_flagged": why_flagged,
        "recommended_action": recommended_action,
        "official_callback_number": official_callback,
        "report_url": "cybercrime.gov.in | Helpline: 1930",
    }

    logger.info("[SCAM_INTEL] Result: score=%.3f band=%s floors=%s",
                final_score, risk_band, hard_floors_triggered)
    return result
