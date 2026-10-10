"""
SafeMailX — Scam Intelligence Engine
Coordinates the 7-layer rule pipeline + Qwen3 arbiter + Live Policy Agent.
Used by the Hold + Describe feature. ISOLATED from the email/SMS scan pipeline.
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

# Stage 3: Qwen3 thinking-mode arbiter
try:
    from engines.layers.qwen_call_layer import analyze_with_qwen
    _QWEN_AVAILABLE = True
except ImportError:
    _QWEN_AVAILABLE = False
    def analyze_with_qwen(*a, **kw): return None  # type: ignore

# Stage 4: Live policy fact-checker
try:
    from engines.layers import live_policy_agent
    _LIVE_POLICY_AVAILABLE = True
except ImportError:
    _LIVE_POLICY_AVAILABLE = False
    live_policy_agent = None  # type: ignore

logger = logging.getLogger("SCAM_INTELLIGENCE")

# ── Dynamic layer weights ─────────────────────────────────────────────────────
# Structured (chip-only) input: knowledge_profiler and conversation_dynamics
# cannot operate without a real transcript — skip them, redistribute weight.
STRUCTURED_WEIGHTS = {
    "policy_verification":    0.35,
    "information_asymmetry":  0.30,
    "isolation_signal":       0.18,
    "manipulation_sequence":  0.12,
    "script_library":         0.05,
    "knowledge_profiler":     0.00,
    "conversation_dynamics":  0.00,
}

# Voice/transcript input: all 7 layers contribute meaningfully.
VOICE_WEIGHTS = {
    "policy_verification":    0.22,
    "information_asymmetry":  0.20,
    "isolation_signal":       0.18,
    "manipulation_sequence":  0.15,
    "script_library":         0.12,
    "knowledge_profiler":     0.08,
    "conversation_dynamics":  0.05,
}


def _build_transcript(claims: dict) -> str:
    """For structured input, build a synthetic transcript from checkbox data."""
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


def _compute_engine_confidence(layer_results, input_mode, layers_above_threshold,
                                final_score, hard_floors_triggered) -> float:
    """Compute engine confidence when Qwen3 is unavailable."""
    base = 0.50
    # More independent signals = more confidence
    base += min(0.25, layers_above_threshold * 0.07)
    # Hard floor = certainty signal
    if hard_floors_triggered:
        base += 0.18
    # Voice transcript gives richer signal than chip-only
    if input_mode in ("voice", "transcript"):
        base += 0.08
    # Very low or very high scores = engine is more certain
    if final_score < 0.15 or final_score > 0.85:
        base += 0.06
    return round(min(0.99, base), 2)


def _get_recommended_action(risk_band: str, org_callback: str = "") -> str:
    if risk_band == "CRITICAL":
        return "Hang up immediately. Do not share any information. Report at cybercrime.gov.in or call 1930."
    elif risk_band == "HIGH RISK":
        callback_str = f" Call {org_callback} to verify." if org_callback else ""
        return f"Do not share any OTP, card details, or personal credentials. Hang up and call the organisation's official number directly.{callback_str}"
    elif risk_band == "SUSPICIOUS":
        callback_str = f" Call {org_callback} to verify." if org_callback else ""
        return f"Be very cautious. Do not share sensitive information on this call. Hang up and call the organisation's official number yourself.{callback_str}"
    else:
        return "Call appears relatively safe. Stay alert — never share OTPs or passwords regardless of who is calling."


def _build_deterministic_explanation(org, actions, warnings, top_layer_result, band) -> str:
    """Always-present explanation. Works without any LLM."""
    org_display = org or "an unknown caller"
    action_str  = " and ".join(actions[:2]) if actions else "sensitive information"

    personal = f"You received a call from someone claiming to be {org_display}."
    if actions:
        personal += f" They asked you to provide your {action_str}."
    if warnings:
        personal += f" They also said: \"{warnings[0]}\"."

    consequence = {
        "CRITICAL":   (
            "This is almost certainly a scam. Sharing what they asked for could result in "
            "immediate financial loss or identity theft. Hang up now."
        ),
        "HIGH RISK":  (
            "This call has strong scam indicators. Do not share any financial details, "
            "OTPs, or personal credentials. Verify directly by calling the official number."
        ),
        "SUSPICIOUS": (
            "This call has some warning signs. Proceed with caution — legitimate organisations "
            "never pressure you on a call or ask you to act urgently."
        ),
        "SAFE":       (
            "This call appears relatively low-risk based on what you described. "
            "Stay alert — never share OTPs or passwords regardless of who is calling."
        ),
    }.get(band, "")

    finding_text = (top_layer_result or {}).get("plain_english", "").strip()
    return "\n\n".join(filter(None, [personal, consequence, finding_text]))


def _build_contextual_advice(org, actions, warnings) -> dict:
    """Deterministic fallback for means_for_you, next_tactics, how_to_verify."""
    org_lower   = (org or "").lower()
    is_bank     = any(k in org_lower for k in ["bank", "hdfc", "sbi", "icici", "axis", "kotak", "rbi", "yes bank", "pnb", "canara", "idfc"])
    is_govt     = any(k in org_lower for k in ["uidai", "aadhaar", "police", "cbi", "income tax", "customs", "trai", "enforcement", "cyber crime"])
    asked_otp   = any("otp" in a.lower() or "pin" in a.lower() or "password" in a.lower() for a in actions)
    asked_money = any("transfer" in a.lower() or "money" in a.lower() for a in actions)
    asked_app   = any("install" in a.lower() or "app" in a.lower() or "screen" in a.lower() for a in actions)
    asked_card  = any("cvv" in a.lower() or "card" in a.lower() for a in actions)

    if is_bank and asked_otp:
        means = (
            f"Your bank already knows your secret OTP code because they are the ones who sent it to you. "
            f"If someone calls and asks you to tell them the OTP, they are a thief trying to steal your money. "
            f"Never tell anyone your OTP."
        )
        tactics = [
            "They have already initiated a transaction on your account and are waiting for your OTP to authorise it.",
            "If you hang up, they may call back as the 'fraud department' offering to reverse the transaction.",
            "They may ask you to install a 'security app' to 'protect' your account — giving them remote access.",
        ]
    elif is_govt:
        means = (
            f"Real police or government offices like {org or 'this one'} will never call you on the phone to scare you or ask for money. "
            f"If someone calls and says you are in trouble or need to pay a fine, they are lying. They just want to scare you into giving them money."
        )
        tactics = [
            "They will escalate to threats of arrest, account freeze, or legal cases to create panic.",
            "They may loop in a fake 'senior officer' or play audio of court proceedings to increase pressure.",
            "They will demand you transfer money to a 'safe account' they control to avoid the fabricated consequence.",
        ]
    elif asked_money:
        means = (
            f"A real company will never ask you to send money to a 'safe account' over a phone call. "
            f"If you send the money, it goes straight to the thief and you cannot get it back."
        )
        tactics = [
            "They will give you a bank account number to transfer to, claiming it is a 'safe' or 'secure' RBI account.",
            "They may stay on the line the entire time to prevent you from calling anyone for advice.",
            "After you transfer, they will become unreachable and the account will be emptied immediately.",
        ]
    elif asked_app:
        means = (
            f"If you install the app they are asking you to, the caller will be able to see everything on your phone screen. "
            f"They will watch you open your bank app and steal your passwords."
        )
        tactics = [
            "They will guide you to open your banking app while watching your screen in real time.",
            "They may silently initiate a transfer while keeping you distracted with conversation.",
            "They may lock your device remotely and demand payment to unlock it.",
        ]
    elif asked_card:
        means = (
            f"Your bank already has your card details. If a caller asks for your card number or CVV, "
            f"they are trying to use your card to buy things online. Do not tell them."
        )
        tactics = [
            "They will use your card details immediately to make online purchases or transfer funds.",
            "They may call back as a 'fraud alert' to extract the OTP sent to verify the transaction.",
        ]
    else:
        means = (
            f"Real companies will not force you to stay on the phone. "
            f"It is always safer to hang up. You can call the real company back using the number on their official website."
        )
        tactics = [
            "They may call repeatedly to wear down your resistance if you do not comply immediately.",
            "They may use personal information from social media to sound legitimate and build trust.",
        ]

    how_to_verify = [
        "Hang up immediately. Do NOT call back the number they gave you.",
        f"Find the official number for {org or 'the organisation'} from their official website or the back of your card.",
        "Call that number yourself and ask if they actually called you today.",
        "If they claimed to be a government agency, visit the physical office in person — never respond over phone.",
    ]

    return {
        "means_for_you": means,
        "next_tactics":  tactics,
        "how_to_verify": how_to_verify,
    }


def analyze(input_data: dict) -> dict:
    """
    Main entry point for call scam analysis.

    input_data keys:
        transcript       : str  — voice description or synthetic
        org_claimed      : str
        actions_requested: list[str]
        warning_phrases  : list[str]
        input_mode       : str  — 'voice' | 'transcript' | 'structured'
    """
    input_mode        = input_data.get("input_mode", "structured")
    transcript        = input_data.get("transcript", "")
    org_claimed       = input_data.get("org_claimed", "")
    actions_requested = input_data.get("actions_requested", [])
    warning_phrases   = input_data.get("warning_phrases", [])

    claims = {
        "org_claimed":       org_claimed,
        "actions_requested": actions_requested,
        "warning_phrases":   warning_phrases,
    }

    # Build synthetic transcript for structured input
    if input_mode == "structured" or not transcript.strip():
        transcript = _build_transcript(claims)
        transcript += " " + " ".join(warning_phrases)

    logger.info("[SCAM_INTEL] Analyzing. mode=%s org='%s' transcript_len=%d",
                input_mode, org_claimed, len(transcript))

    # ── Select dynamic weights based on input mode ────────────────────────────
    weights = VOICE_WEIGHTS if input_mode in ("voice", "transcript") else STRUCTURED_WEIGHTS

    # ── Run all 7 layers ──────────────────────────────────────────────────────
    layer_results = {
        "policy_verification":   policy_verification.analyze(transcript, claims),
        "information_asymmetry": information_asymmetry.analyze(transcript, claims),
        "isolation_signal":      isolation_detector.analyze(transcript, claims),
        "manipulation_sequence": manipulation_sequence.analyze(transcript, claims),
        "script_library":        script_library.analyze(transcript, claims),
        "knowledge_profiler":    knowledge_profiler.analyze(transcript, claims),
        "conversation_dynamics": conversation_dynamics.analyze(transcript, claims),
    }

    # ── Hard floors ───────────────────────────────────────────────────────────
    hard_floors_triggered = []
    floor_score           = 0.0
    official_callback     = ""

    for layer_name, result in layer_results.items():
        hf = result.get("hard_floor")
        if hf and hf > floor_score:
            floor_score = hf
            hard_floors_triggered.append(f"{layer_name}: {hf}")
        if result.get("official_callback"):
            official_callback = result["official_callback"]

    if layer_results["policy_verification"].get("official_callback"):
        official_callback = layer_results["policy_verification"]["official_callback"]

    # ── Weighted composite score (dynamic weights) ────────────────────────────
    composite_score = sum(
        layer_results[layer_name]["score"] * weight
        for layer_name, weight in weights.items()
        if layer_name in layer_results and weight > 0
    )

    max_layer_score = max(
        (res.get("score", 0.0) for res in layer_results.values()), default=0.0
    )

    # ── 2-layer override rule ─────────────────────────────────────────────────
    # max_layer_score can override composite only if ≥2 layers fired above 0.50.
    # Prevents a single outlier rule from dominating on sparse input.
    layers_above_threshold = sum(
        1 for res in layer_results.values() if res.get("score", 0) >= 0.50
    )
    if layers_above_threshold >= 2:
        final_score = max(composite_score, floor_score, max_layer_score)
    else:
        final_score = max(composite_score, floor_score)

    final_score = round(min(1.0, final_score), 3)

    # ── 4-band risk classification ────────────────────────────────────────────
    if final_score > 0.85:    rule_band = "CRITICAL"
    elif final_score > 0.65:  rule_band = "HIGH RISK"
    elif final_score >= 0.25: rule_band = "SUSPICIOUS"
    else:                     rule_band = "SAFE"

    # ── Decide whether to run Qwen3 ───────────────────────────────────────────
    is_rich_input  = input_mode in ("voice", "transcript")
    in_grey_zone   = 0.25 <= final_score <= 0.85
    should_run_qwen = is_rich_input or in_grey_zone

    qwen_result        = None
    live_policy_result = None

    def _run_qwen():
        if not should_run_qwen:
            return None
        return analyze_with_qwen(
            transcript=transcript,
            org_claimed=org_claimed,
            actions_requested=actions_requested,
            warning_phrases=warning_phrases,
            rule_results=layer_results,
            rule_final_score=final_score,
            hard_floors_triggered=hard_floors_triggered,
            timeout=120,
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
            qwen_result        = f_qwen.result(timeout=130)
        except Exception as e:
            logger.warning("[SCAM_INTEL] Qwen3 stage error: %s", e)
        try:
            live_policy_result = f_policy.result(timeout=55)
        except Exception as e:
            logger.warning("[SCAM_INTEL] Live policy stage error: %s", e)

    # ── Merge Qwen3 verdict ───────────────────────────────────────────────────
    if qwen_result:
        final_score   = qwen_result["threat_probability"]  # already ±0.20 guarded
        risk_band     = qwen_result["final_verdict"]
        qwen_plain    = qwen_result["plain_english"]
        tactics       = qwen_result["tactics_detected"]
        qwen_conf     = qwen_result["confidence"]           # shown directly to user
        qwen_means    = qwen_result.get("means_for_you", "")
        qwen_next     = qwen_result.get("next_tactics", [])
        qwen_avail    = True
        logger.info("[SCAM_INTEL] Qwen3 override: %s (prob=%.3f conf=%.2f)", risk_band, final_score, qwen_conf)
    else:
        risk_band  = rule_band
        qwen_plain = ""
        tactics    = []
        qwen_conf  = None
        qwen_means = ""
        qwen_next  = []
        qwen_avail = False

    score_display = round(final_score * 100)

    # ── Confidence score ──────────────────────────────────────────────────────
    if qwen_avail and qwen_conf is not None:
        confidence_score = qwen_conf   # Qwen3 has seen everything — trust it directly
    else:
        confidence_score = _compute_engine_confidence(
            layer_results, input_mode, layers_above_threshold, final_score, hard_floors_triggered
        )

    # ── Build signals + why_flagged ───────────────────────────────────────────
    signals_fired = [
        name for name, result in layer_results.items()
        if result.get("score", 0) > 0.30
    ]
    sorted_layers = sorted(
        [(name, res) for name, res in layer_results.items() if res.get("score", 0) > 0.30],
        key=lambda x: x[1]["score"],
        reverse=True,
    )
    why_flagged = [res["plain_english"] for _, res in sorted_layers[:3]]

    # ── Deterministic explanation (always present) ────────────────────────────
    top_layer_result = sorted_layers[0][1] if sorted_layers else None
    deterministic_explanation = _build_deterministic_explanation(
        org_claimed, actions_requested, warning_phrases, top_layer_result, risk_band
    )

    # ── Contextual advice sections ────────────────────────────────────────────
    # If Qwen3 is live and returned personalised content, use it.
    # Otherwise fall back to deterministic templates.
    advice = _build_contextual_advice(org_claimed, actions_requested, warning_phrases)
    means_for_you = qwen_means  if qwen_means  else advice["means_for_you"]
    next_tactics  = qwen_next   if qwen_next   else advice["next_tactics"]
    how_to_verify = advice["how_to_verify"]   # always templated

    # ── Full explanation ──────────────────────────────────────────────────────
    org_display = org_claimed or "Unknown Organization"
    explanation_parts = [f"Caller claimed to be from: {org_display}."]
    if qwen_plain:
        explanation_parts.append(qwen_plain)
    elif why_flagged:
        explanation_parts.append("Why SafeMailX flagged this call:")
        for bullet in why_flagged:
            explanation_parts.append(f"• {bullet}")
    full_explanation = "\n".join(explanation_parts)

    recommended_action = _get_recommended_action(risk_band, official_callback)

    result = {
        "final_score":              final_score,
        "risk_band":                risk_band,
        "score_display":            score_display,
        "org_claimed":              org_claimed,
        "purpose_detected":         ", ".join(actions_requested) if actions_requested else "Unknown",
        "layer_results": {
            name: {
                "score":         round(res["score"], 3),
                "finding":       res["finding"],
                "plain_english": res["plain_english"],
            }
            for name, res in layer_results.items()
        },
        "signals_fired":            signals_fired,
        "hard_floors_triggered":    hard_floors_triggered,
        "composite_score":          round(composite_score, 3),
        "floor_score":              round(floor_score, 3),
        "full_explanation":         full_explanation,
        "why_flagged":              why_flagged,
        "recommended_action":       recommended_action,
        "official_callback_number": official_callback,
        "report_url":               "cybercrime.gov.in | Helpline: 1930",
        # Qwen3 fields
        "qwen_available":           qwen_avail,
        "qwen_confidence":          qwen_conf,
        "tactics_detected":         tactics,
        "plain_english":            qwen_plain,
        # New personalisation fields
        "confidence_score":         confidence_score,
        "deterministic_explanation": deterministic_explanation,
        "means_for_you":            means_for_you,
        "next_tactics":             next_tactics,
        "how_to_verify":            how_to_verify,
        # Live policy fact-check
        "live_policy_check":        live_policy_result,
    }

    logger.info(
        "[SCAM_INTEL] Final: score=%.3f band=%s conf=%.2f qwen=%s layers_fired=%d floors=%s",
        final_score, risk_band, confidence_score, qwen_avail, layers_above_threshold,
        hard_floors_triggered,
    )
    return result
