"""
SafeMailX — Scam Intelligence Engine
Coordinates the 7-layer rule pipeline + Qwen3 arbiter + Live Policy Agent.
Used by the Hold + Describe feature.
"""
import logging
import concurrent.futures
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

# Stage 3: Qwen3 thinking-mode arbiter (grey-zone only)
try:
    from engines.layers.qwen_call_layer import analyze_with_qwen
    _QWEN_AVAILABLE = True
except ImportError:
    _QWEN_AVAILABLE = False
    def analyze_with_qwen(*a, **kw): return None  # type: ignore

# Stage 4: Live policy fact-checker (web search + scrape + Qwen3)
try:
    from engines.layers import live_policy_agent
    _LIVE_POLICY_AVAILABLE = True
except ImportError:
    _LIVE_POLICY_AVAILABLE = False
    live_policy_agent = None  # type: ignore

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

    # Risk band from rules
    if final_score > 0.70:
        rule_band = "CRITICAL"
    elif final_score >= 0.30:
        rule_band = "SUSPICIOUS"
    else:
        rule_band = "SAFE"

    # ── Stage 3 + 4 run in parallel (only if score is in grey zone) ──────────
    GREY_ZONE = 0.20 <= final_score <= 0.85
    qwen_result = None
    live_policy_result = None

    def _run_qwen():
        if not GREY_ZONE:
            return None
        return analyze_with_qwen(
            transcript=transcript,
            org_claimed=org_claimed,
            actions_requested=actions_requested,
            warning_phrases=warning_phrases,
            rule_results=layer_results,
            composite_score=composite_score,
            floor_score=floor_score,
            hard_floors_triggered=hard_floors_triggered,
            timeout=55,
        )

    def _run_live_policy():
        if not _LIVE_POLICY_AVAILABLE or not org_claimed:
            return None
        return live_policy_agent.check(
            org_claimed=org_claimed,
            actions_requested=actions_requested,
            timeout=50,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        f_qwen   = ex.submit(_run_qwen)
        f_policy = ex.submit(_run_live_policy)
        try:
            qwen_result        = f_qwen.result(timeout=60)
        except Exception as e:
            logger.warning("[SCAM_INTEL] Qwen3 stage error: %s", e)
        try:
            live_policy_result = f_policy.result(timeout=60)
        except Exception as e:
            logger.warning("[SCAM_INTEL] Live policy stage error: %s", e)

    # ── Merge Qwen3 verdict ───────────────────────────────────────────────────
    if qwen_result:
        final_score  = qwen_result["threat_probability"]
        risk_band    = qwen_result["final_verdict"]
        qwen_plain   = qwen_result["plain_english"]
        tactics      = qwen_result["tactics_detected"]
        qwen_conf    = qwen_result["confidence"]
        qwen_avail   = True
        logger.info("[SCAM_INTEL] Qwen3 override: %s (prob=%.3f)", risk_band, final_score)
    else:
        risk_band    = rule_band
        qwen_plain   = ""
        tactics      = []
        qwen_conf    = None
        qwen_avail   = False

    score_display = round(final_score * 100)

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

    # Full explanation — prefer Qwen3's human explanation if available
    org_display = org_claimed or "Unknown Organization"
    explanation_parts = [f"Caller claimed to be from: {org_display}."]
    if qwen_plain:
        explanation_parts.append(qwen_plain)
    elif why_flagged:
        explanation_parts.append("Why SafeMail X flagged this call:")
        for bullet in why_flagged:
            explanation_parts.append(f"• {bullet}")
    full_explanation = "\n".join(explanation_parts)

    recommended_action = _get_recommended_action(risk_band, official_callback)

    result = {
        "final_score":             final_score,
        "risk_band":               risk_band,
        "score_display":           score_display,
        "org_claimed":             org_claimed,
        "purpose_detected":        ", ".join(actions_requested) if actions_requested else "Unknown",
        "layer_results": {
            name: {
                "score":       round(res["score"], 3),
                "finding":     res["finding"],
                "plain_english": res["plain_english"]
            }
            for name, res in layer_results.items()
        },
        "signals_fired":           signals_fired,
        "hard_floors_triggered":   hard_floors_triggered,
        "composite_score":         round(composite_score, 3),
        "floor_score":             round(floor_score, 3),
        "full_explanation":        full_explanation,
        "why_flagged":             why_flagged,
        "recommended_action":      recommended_action,
        "official_callback_number": official_callback,
        "report_url":              "cybercrime.gov.in | Helpline: 1930",
        # Qwen3 fields
        "qwen_available":          qwen_avail,
        "qwen_confidence":         qwen_conf,
        "tactics_detected":        tactics,
        "plain_english":           qwen_plain,
        # Live policy fact-check
        "live_policy_check":       live_policy_result,
    }

    logger.info(
        "[SCAM_INTEL] Final: score=%.3f band=%s qwen=%s policy_checked=%s floors=%s",
        final_score, risk_band, qwen_avail,
        bool(live_policy_result and live_policy_result.get("checked")),
        hard_floors_triggered
    )
    return result

