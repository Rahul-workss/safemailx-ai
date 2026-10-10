"""
SafeMail X - Qwen3 Call Analysis Layer (Stage 3)
Runs for:
  - voice/transcript input: ALWAYS (rich context = max personalisation)
  - structured chip input: only in grey zone (0.25-0.85)
Returns None if LM Studio is offline (deterministic fallback takes over).
"""

import json
import logging
import re
import requests
from typing import Optional

logger = logging.getLogger("QWEN_CALL_LAYER")

SYSTEM_PROMPT = '''You are SafeMail X Vishing Intelligence — a specialist in detecting voice phishing (vishing) scams targeting Indian citizens. You have the deepest context: you receive the user's own words describing exactly what happened on the call.

== YOUR JOB ==
1. Make the FINAL verdict on whether this call is a scam
2. Write a PERSONALISED explanation that references specific things the caller said or did (from the transcript)
3. Write a personalised "what this means for you" paragraph explaining the specific danger using the actual org claimed + action requested
4. Predict what the scammer will likely do NEXT, specific to the tactic detected

== HARD RULES (non-negotiable) ==
- No bank EVER asks for OTP, CVV, PIN, or password over a phone call
- UIDAI and RBI NEVER call citizens for any reason — every such call is fraud
- Law enforcement NEVER conducts arrests via phone ("digital arrest" is not a legal concept in India)
- No government agency collects fines or taxes via UPI/PhonePe/Google Pay
- Legitimate organisations NEVER say "do not tell anyone" or "stay on the line"
- A bank already KNOWS your OTP or CVV — asking for them back PROVES fraud

== ANTI-FALSE-POSITIVE RULES ==
Do NOT flag as CRITICAL:
- Bank calling to CONFIRM (not extract) a large transaction the user already made
- Credit card / loan EMI due date reminder (informational only)
- Appointment reminders from hospitals, banks, businesses
- Delivery confirmation calls with no money demand

SUSPICIOUS != CRITICAL. Escalate to CRITICAL only when caller explicitly requests OTP/PIN/CVV/money, makes a threat, uses isolation commands, or claims to be UIDAI/RBI/law enforcement.

== RISK BANDS ==
Use exactly one of: "SAFE" | "SUSPICIOUS" | "HIGH RISK" | "CRITICAL"
- SAFE: No red flags detected. Call appears legitimate.
- SUSPICIOUS: Some warning signs, but not confirmed scam. User should verify independently.
- HIGH RISK: Strong scam signals present. Very likely fraud.
- CRITICAL: Confirmed scam pattern. User is in immediate danger.

== PERSONALISATION RULES ==
- In plain_english: Quote or reference SPECIFIC things from the transcript (e.g. "You mentioned the caller said 'your account will be frozen' — this is the classic fear-induction tactic used in bank impersonation scams to create panic.")
- In means_for_you: Write this in extremely simple, non-technical language. Explain the danger as if you are speaking to a child or an elderly person with no tech knowledge. Crucially, focus on the SPECIFIC information the caller asked for (e.g. if they asked for CVV, talk about CVV, DO NOT talk about OTP). No jargon. Use the ACTUAL org name claimed.
- In next_tactics: Be specific to the detected tactic. If it is CVV/OTP harvesting: "They have already initiated a transaction and are waiting for your CVV/OTP to authorise the transfer." If digital arrest: "They will escalate to a fake senior officer or 'court video call' to increase panic."

== OUTPUT FORMAT ==
Return ONLY a valid JSON object — no markdown, no preamble, no <think> tags:
{
  "threat_probability": <float 0.0-1.0>,
  "final_verdict": <"SAFE" | "SUSPICIOUS" | "HIGH RISK" | "CRITICAL">,
  "confidence": <float 0.0-1.0>,
  "plain_english": <2-3 sentences referencing specific details from the transcript>,
  "means_for_you": <1 personalised paragraph: what does this specific call mean for this specific user's safety>,
  "next_tactics": <list of 2-3 specific strings: what THIS scammer will do next based on the tactic detected>,
  "tactics_detected": <list from: ["otp_harvesting","digital_arrest","aadhaar_fraud","customs_parcel","income_tax","kyc_expiry","courier_payment","safe_account_transfer","remote_access","isolation_command","authority_impersonation","fear_induction","urgency_pressure","none_detected"]>,
  "override_reason": <string explaining why you changed the rule score, or null>
}'''


def _get_llm_cfg():
    try:
        from engines.llm_analyzer import _get_live_config
        cfg = _get_live_config()
        return {
            "base_url": cfg.get("base_url", "http://127.0.0.1:1234/v1/chat/completions"),
            "model":    cfg.get("model", "qwen3-8b"),
            "thinking": cfg.get("thinking", True),
            "max_tokens": min(cfg.get("max_tokens", 4000), 3000),  # enough for thinking + expanded JSON
        }
    except Exception:
        pass
    try:
        from utils.config import LLM_BASE_URL, LLM_MODEL, LLM_ENABLE_THINKING
        return {"base_url": LLM_BASE_URL, "model": LLM_MODEL,
                "thinking": LLM_ENABLE_THINKING, "max_tokens": 2500}
    except Exception:
        return {"base_url": "http://127.0.0.1:1234/v1/chat/completions",
                "model": "qwen3-8b", "thinking": True, "max_tokens": 2500}


def _call_qwen3(user_message, timeout=120):
    cfg = _get_llm_cfg()
    payload = {
        "model":       cfg["model"],
        "messages":    [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_message},
        ],
        "temperature": 0.6 if cfg["thinking"] else 0.1,
        "top_p":       0.95 if cfg["thinking"] else 0.80,
        "max_tokens":  cfg["max_tokens"],
        "stream":      False,
    }
    if cfg["thinking"]:
        payload["chat_template_kwargs"] = {"enable_thinking": True}
    try:
        resp = requests.post(cfg["base_url"], json=payload, timeout=timeout)
        resp.raise_for_status()
        msg     = resp.json()["choices"][0]["message"]
        content = (msg.get("content", "") or "").strip()
        think_w = len((msg.get("reasoning_content", "") or "").split())
        logger.info("[QWEN_CALL] OK. content_len=%d think_words=%d", len(content), think_w)
        return content
    except requests.exceptions.ConnectionError:
        logger.info("[QWEN_CALL] LM Studio offline — rule-only mode.")
        return None
    except requests.exceptions.Timeout:
        logger.warning("[QWEN_CALL] Timeout (%ds) — rule-only mode.", timeout)
        return None
    except Exception as e:
        logger.warning("[QWEN_CALL] Error: %s", e)
        return None


def _parse_json(content):
    if not content:
        return None
    # Strip <think>...</think> blocks from Qwen3 thinking output
    content = re.sub(r"<think>[\s\S]*?</think>", "", content).strip()
    try:
        return json.loads(content)
    except Exception:
        pass
    clean = re.sub(r"`(?:json)?\s*([\s\S]*?)\s*`", r"\1", content).strip()
    try:
        return json.loads(clean)
    except Exception:
        pass
    matches = list(re.finditer(r"\{[\s\S]*\}", content))
    if matches:
        try:
            return json.loads(matches[-1].group(0))
        except Exception:
            pass
    return None


def analyze_with_qwen(transcript, org_claimed, actions_requested, warning_phrases,
                      rule_results, rule_final_score, hard_floors_triggered,
                      timeout=120):
    layers_lines = []
    for name, res in rule_results.items():
        score = res.get("score", 0.0)
        if score > 0.0:
            layers_lines.append(
                f"  [{name}] score={score:.2f} | {res.get('finding', '')}\n"
                f"    -> {res.get('plain_english', '')}"
            )
    floors_block = ""
    if hard_floors_triggered:
        floors_block = "\n  HARD FLOORS:\n  " + "\n  ".join(hard_floors_triggered)

    user_msg = (
        f"=== CALL DESCRIPTION ===\n"
        f"{transcript.strip() or '(no transcript — structured chip input)'}\n\n"
        f"=== SIGNALS ===\n"
        f"Org claimed       : {org_claimed or '(not specified)'}\n"
        f"Actions requested : {', '.join(actions_requested) if actions_requested else '(none)'}\n"
        f"Warning phrases   : {', '.join(warning_phrases) if warning_phrases else '(none)'}\n\n"
        f"=== RULE ENGINE ===\n"
        f"Rule Final Score: {rule_final_score:.3f}\n"
        f"{floors_block}\n\n"
        f"Layer breakdown:\n"
        f"{chr(10).join(layers_lines) or '  All layers low/zero.'}\n\n"
        f"Remember: reference specific details from the call description above in your personalised fields.\n"
        f"Output ONLY the JSON object."
    )

    raw = _call_qwen3(user_msg, timeout=timeout)
    if raw is None:
        return None

    parsed = _parse_json(raw)
    if parsed is None:
        return None

    try:
        raw_qwen_prob = max(0.0, min(1.0, float(parsed.get("threat_probability", rule_final_score))))

        # ── ±0.20 score guard: Qwen3 refines but cannot completely flip the rule engine ──
        DRIFT_LIMIT  = 0.20
        guarded_prob = max(
            rule_final_score - DRIFT_LIMIT,
            min(rule_final_score + DRIFT_LIMIT, raw_qwen_prob)
        )
        threat_prob = round(guarded_prob, 3)

        verdict = str(parsed.get("final_verdict", "")).upper().strip()
        verdict = verdict.replace("HIGH_RISK", "HIGH RISK")   # normalise either format
        if verdict not in ("SAFE", "SUSPICIOUS", "HIGH RISK", "CRITICAL"):
            if threat_prob > 0.85:    verdict = "CRITICAL"
            elif threat_prob > 0.65:  verdict = "HIGH RISK"
            elif threat_prob >= 0.25: verdict = "SUSPICIOUS"
            else:                     verdict = "SAFE"

        confidence    = round(max(0.0, min(1.0, float(parsed.get("confidence", 0.75)))), 2)
        plain_english = str(parsed.get("plain_english", "")).strip()[:700]
        means_for_you = str(parsed.get("means_for_you", "")).strip()[:900]
        next_tactics  = [
            str(t).strip() for t in parsed.get("next_tactics", [])
            if isinstance(t, str) and str(t).strip()
        ][:4]
        tactics       = [str(t) for t in parsed.get("tactics_detected", []) if isinstance(t, str)]
        override_reason = parsed.get("override_reason")
        override_reason = str(override_reason).strip() if override_reason else None

        # Safety guard: hard floors >= 0.92 block SAFE verdict
        if hard_floors_triggered and rule_final_score >= 0.92 and verdict == "SAFE":
            logger.warning("[QWEN_CALL] Hard floor blocks SAFE — upgrading to SUSPICIOUS.")
            verdict     = "SUSPICIOUS"
            threat_prob = max(threat_prob, 0.50)
            override_reason = "Hard floor >=0.92; SAFE overridden to SUSPICIOUS."

        logger.info(
            "[QWEN_CALL] %s prob=%.3f (raw=%.3f rule=%.3f drift=%+.3f) conf=%.2f tactics=%s",
            verdict, threat_prob, raw_qwen_prob, rule_final_score,
            raw_qwen_prob - rule_final_score, confidence, tactics,
        )
        return {
            "threat_probability": threat_prob,
            "final_verdict":      verdict,
            "confidence":         confidence,
            "plain_english":      plain_english,
            "means_for_you":      means_for_you,
            "next_tactics":       next_tactics,
            "tactics_detected":   tactics,
            "override_reason":    override_reason,
            "qwen_available":     True,
        }
    except Exception as e:
        logger.warning("[QWEN_CALL] Validation error: %s", e)
        return None
