"""
SafeMail X - Qwen3 Call Analysis Layer (Stage 3)
Only called for grey-zone scores (0.20-0.85).
Returns None if LM Studio is offline.
"""

import json
import logging
import re
import requests
from typing import Optional

logger = logging.getLogger("QWEN_CALL_LAYER")

SYSTEM_PROMPT = '''You are SafeMail X Vishing Intelligence - a specialist detecting voice phishing (vishing) scams targeting Indian citizens.

You receive a description of a phone call AND findings from 7 automated detection layers.
Your job: make the FINAL verdict on whether this call is a scam.

== HARD RULES - NEVER negotiate these ==
- No bank EVER asks for OTP, CVV, PIN, or password over a phone call
- UIDAI and RBI NEVER call citizens for any reason
- Law enforcement NEVER conducts arrests via phone ("digital arrest" is illegal)
- No government agency collects fines/tax via UPI/PhonePe/Google Pay
- Legitimate organizations NEVER say "do not tell anyone" or "stay on the line"
- A bank that sent you an OTP already KNOWS it - asking for it back PROVES fraud

== ANTI-FALSE-POSITIVE RULES ==
These are NOT scams - do NOT flag as CRITICAL:
- Bank calling to CONFIRM (not extract) a large transaction you made
- Credit card / loan EMI due date reminder (informational only)
- Appointment reminders from hospitals, banks, businesses
- Delivery confirmation calls with no money demand

SUSPICIOUS != CRITICAL. Escalate to CRITICAL only when:
- Caller explicitly requests OTP, PIN, CVV, or money transfer
- Caller makes a threat (arrest, account freeze, legal case)
- Caller uses isolation command ("do not tell anyone", "stay on the line")
- Caller claims to be UIDAI, RBI, or law enforcement

== OUTPUT FORMAT ==
Return ONLY a valid JSON object - no markdown, no preamble:
{
  "threat_probability": <float 0.0-1.0>,
  "final_verdict": <"SAFE" | "SUSPICIOUS" | "CRITICAL">,
  "confidence": <float 0.0-1.0>,
  "plain_english": <2-3 sentences for a non-technical person in danger>,
  "tactics_detected": <list from: ["otp_harvesting","digital_arrest","aadhaar_fraud","customs_parcel","income_tax","kyc_expiry","courier_payment","safe_account_transfer","remote_access","isolation_command","authority_impersonation","fear_induction","urgency_pressure","none_detected"]>,
  "override_reason": <string or null>
}'''


def _get_llm_cfg():
    try:
        from engines.llm_analyzer import _get_live_config
        cfg = _get_live_config()
        return {"base_url": cfg.get("base_url","http://127.0.0.1:1234/v1/chat/completions"),
                "model": cfg.get("model","qwen3-8b"),
                "thinking": cfg.get("thinking",True),
                "max_tokens": min(cfg.get("max_tokens",3200),1500)}
    except Exception:
        pass
    try:
        from utils.config import LLM_BASE_URL,LLM_MODEL,LLM_ENABLE_THINKING
        return {"base_url":LLM_BASE_URL,"model":LLM_MODEL,"thinking":LLM_ENABLE_THINKING,"max_tokens":1200}
    except Exception:
        return {"base_url":"http://127.0.0.1:1234/v1/chat/completions","model":"qwen3-8b","thinking":True,"max_tokens":1200}


def _call_qwen3(user_message, timeout=55):
    cfg = _get_llm_cfg()
    payload = {"model":cfg["model"],
               "messages":[{"role":"system","content":SYSTEM_PROMPT},{"role":"user","content":user_message}],
               "temperature":0.6 if cfg["thinking"] else 0.1,
               "top_p":0.95 if cfg["thinking"] else 0.80,
               "max_tokens":cfg["max_tokens"],"stream":False}
    if cfg["thinking"]:
        payload["chat_template_kwargs"] = {"enable_thinking":True}
    try:
        resp = requests.post(cfg["base_url"],json=payload,timeout=timeout)
        resp.raise_for_status()
        msg = resp.json()["choices"][0]["message"]
        content = (msg.get("content","") or "").strip()
        think_w = len((msg.get("reasoning_content","") or "").split())
        logger.info("[QWEN_CALL] OK. content_len=%d think_words=%d",len(content),think_w)
        return content
    except requests.exceptions.ConnectionError:
        logger.info("[QWEN_CALL] LM Studio offline - rule-only mode.")
        return None
    except requests.exceptions.Timeout:
        logger.warning("[QWEN_CALL] Timeout (%ds) - rule-only mode.",timeout)
        return None
    except Exception as e:
        logger.warning("[QWEN_CALL] Error: %s",e)
        return None


def _parse_json(content):
    if not content: return None
    try: return json.loads(content)
    except: pass
    clean = re.sub(r"`(?:json)?\s*([\s\S]*?)\s*`",r"\1",content).strip()
    try: return json.loads(clean)
    except: pass
    matches = list(re.finditer(r"\{[\s\S]*\}",content))
    if matches:
        try: return json.loads(matches[-1].group(0))
        except: pass
    return None


def analyze_with_qwen(transcript, org_claimed, actions_requested, warning_phrases,
                      rule_results, composite_score, floor_score, hard_floors_triggered,
                      timeout=55):
    layers_lines = []
    for name,res in rule_results.items():
        score = res.get("score",0.0)
        if score > 0.0:
            layers_lines.append(f"  [{name}] score={score:.2f} | {res.get('finding','')}\n    -> {res.get('plain_english','')}")
    floors_block = ""
    if hard_floors_triggered:
        floors_block = "\n  HARD FLOORS:\n  " + "\n  ".join(hard_floors_triggered)

    user_msg = f"""=== CALL DESCRIPTION ===
{transcript.strip() or '(no transcript)'}

=== SIGNALS ===
Org claimed       : {org_claimed or '(not specified)'}
Actions requested : {', '.join(actions_requested) if actions_requested else '(none)'}
Warning phrases   : {', '.join(warning_phrases) if warning_phrases else '(none)'}

=== RULE ENGINE ===
Composite: {composite_score:.3f}  Floor: {floor_score:.3f}  Combined: {max(composite_score,floor_score):.3f}
{floors_block}

Layer breakdown:
{chr(10).join(layers_lines) or '  All layers low/zero.'}

Output ONLY the JSON object."""

    raw = _call_qwen3(user_msg,timeout=timeout)
    if raw is None: return None

    parsed = _parse_json(raw)
    if parsed is None: return None

    try:
        threat_prob = round(max(0.0,min(1.0,float(parsed.get("threat_probability",composite_score)))),3)
        verdict = str(parsed.get("final_verdict","")).upper()
        if verdict not in ("SAFE","SUSPICIOUS","CRITICAL"):
            verdict = "CRITICAL" if threat_prob>0.70 else ("SUSPICIOUS" if threat_prob>=0.30 else "SAFE")
        confidence = round(max(0.0,min(1.0,float(parsed.get("confidence",0.75)))),2)
        plain_english = str(parsed.get("plain_english","")).strip()[:600]
        tactics = [str(t) for t in parsed.get("tactics_detected",[]) if isinstance(t,str)]
        override_reason = parsed.get("override_reason")
        override_reason = str(override_reason).strip() if override_reason else None

        # Safety guard: hard floors >= 0.92 block SAFE verdict
        if hard_floors_triggered and floor_score>=0.92 and verdict=="SAFE":
            logger.warning("[QWEN_CALL] Hard floor blocks SAFE - upgrading to SUSPICIOUS.")
            verdict = "SUSPICIOUS"
            threat_prob = max(threat_prob,0.50)
            override_reason = "Hard floor >=0.92; SAFE overridden to SUSPICIOUS."

        logger.info("[QWEN_CALL] %s prob=%.3f conf=%.2f tactics=%s",verdict,threat_prob,confidence,tactics)
        return {"threat_probability":threat_prob,"final_verdict":verdict,"confidence":confidence,
                "plain_english":plain_english,"tactics_detected":tactics,
                "override_reason":override_reason,"qwen_available":True}
    except Exception as e:
        logger.warning("[QWEN_CALL] Validation error: %s",e)
        return None
