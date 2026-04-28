# =============================================
# SafeMail-X  —  Deep Threat Intelligence Engine
# Powered by Qwen 3.5 9B via LM Studio
# 100% Local  •  Zero Data Leaves the Machine
# =============================================

import json
import re
import requests

# -- LM Studio Configuration --------------------------------------------------
LM_STUDIO_URL     = "http://localhost:1234/v1/chat/completions"
LM_STUDIO_TIMEOUT = 300  # Increased to 5 minutes for Qwen 3.5 9B inference

# -- System Prompt — Forensic Decision Protocol --------------------------------
SYSTEM_PROMPT = """You are SafeMail-X Threat Intelligence Engine, a forensic email analyst.

Your job is to determine whether an email is PHISHING or LEGITIMATE.

CRITICAL: You must MINIMIZE FALSE POSITIVES. Many legitimate emails look like phishing:
- Google sends "Your storage is full" — this is REAL, not phishing
- Amazon sends "Your order has shipped — track here" — this is REAL
- Banks send "New login detected from Windows PC" — this is REAL
- Netflix sends "Payment failed, update billing" — this is REAL
- LinkedIn sends "Someone viewed your profile" — this is REAL
- Companies send "50% off limited time!" — this is marketing, NOT phishing

BEFORE scoring, you MUST reason through this 3-phase protocol:

== PHASE 1: LEGITIMACY CHECK ==
Ask yourself these 5 questions:
Q1. Is this a standard service notification? (shipping, billing, security alert, marketing promo)
    If YES — lean toward LEGITIMATE unless there are CLEAR deceptive signals.
Q2. Does the email provide SPECIFIC details? (order ID, last 4 digits of card, device name, username)
    Real services provide specifics. Phishing uses vague "your account", "your transaction".
Q3. Is the greeting personalized? ("Hi Rahul" vs "Dear Customer" vs no greeting)
    Real services usually address you by name. Phishing uses generic greetings.
Q4. Does the call-to-action make sense? ("View your order" vs "CLICK NOW OR LOSE EVERYTHING")
    Real services use calm actions. Phishing creates irrational panic.
Q5. Does the tone INFORM or MANIPULATE?
    Real: "We noticed a new sign-in. If this was you, no action needed."
    Phishing: "UNAUTHORIZED ACCESS! VERIFY IMMEDIATELY OR ACCOUNT WILL BE DELETED!"

== PHASE 2: THREAT ASSESSMENT (only if Phase 1 raises concerns) ==
- Does the email directly ask for passwords or credentials in the body?
- Does it demand immediate action with extreme consequences?
- Is the sender domain suspicious or mismatched with the brand?
- Are there shortened/suspicious URLs that don't match the claimed service?
- Is the grammar broken, inconsistent, or machine-translated?

== PHASE 3: CALIBRATED SCORING ==
Use this calibration guide — your scores MUST align with these:
- Real Google/Amazon/Bank notification with verified sender: threat_probability 0.00 - 0.15
- Marketing/promotional email with urgency language: threat_probability 0.10 - 0.30
- Ambiguous email with some suspicious signals: threat_probability 0.30 - 0.55
- Email with clear deceptive intent but no credential harvesting: threat_probability 0.55 - 0.75
- Email actively requesting credentials with fake urgency: threat_probability 0.75 - 0.90
- Confirmed phishing with spoofed sender and malicious links: threat_probability 0.90 - 1.00

Return a JSON object with EXACTLY these keys:
{
  "urgency_score": <integer 0-10, 0=no urgency, 10=extreme artificial panic>,
  "legitimacy_score": <integer 0-10, 0=clearly genuine, 10=clearly impersonating>,
  "grammar_score": <integer 0-10, 0=professional, 10=very poor/suspicious>,
  "coherence_score": <integer 0-10, 0=fully logical, 10=nonsensical template>,
  "social_engineering_tactics": <list from: ["pretexting","authority_impersonation","fear_appeal","reward_lure","artificial_scarcity","credential_harvesting","false_deadline","trust_exploitation","none_detected"]>,
  "detected_intent": <string from: ["credential_theft", "financial_fraud", "malware_delivery", "coercion", "benign_notification", "marketing", "unknown"]>,
  "threat_probability": <float 0.0-1.0>,
  "reasoning": <string: 2-3 sentence professional assessment explaining your verdict>
}

RULES:
- Return ONLY valid JSON. No markdown fences, no extra text, no thinking tags.
- If the email is clearly a real service notification, give it LOW scores.
- NEVER flag a legitimate marketing email as high-threat just because it uses urgency words.
- Focus on INTENT and DECEPTION, not just keywords."""


def run_llm_analysis(email_text: str, subject: str = "",
                     sender: str = "",
                     security_summary: str = "") -> dict | None:
    """
    Send email content to Qwen 3.5 9B and return structured features.

    Returns a dict with keys:
        llm_score, urgency_score, legitimacy_score, grammar_score,
        coherence_score, tactics, intent, reasoning, confidence, llm_available

    Returns None if LM Studio is offline/fails — the caller
    (hybrid_engine) will seamlessly fall back to TF-IDF only.
    """

    # Build rich user message with full forensic context
    user_msg = (
        "Analyze this email using the 3-phase forensic protocol.\n\n"
        f"SENDER: {sender}\n"
        f"SUBJECT: {subject}\n"
    )

    # Add security header context if available
    if security_summary:
        user_msg += f"AUTHENTICATION: {security_summary}\n"

    user_msg += (
        "\n--- EMAIL BODY ---\n"
        f"{email_text[:25000]}\n"
        "--- END ---\n\n"
        "Apply the 3-phase protocol internally to evaluate the email. "
        "DO NOT output your internal reasoning steps. You must output ONLY the final JSON object."
    )

    payload = {
        "model": "qwen/qwen3.5-9b",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_msg},
        ],
        "temperature": 0.3,
        "top_p": 0.8,
        "max_tokens": 4000,
        "stream": False,
    }

    import threading
    import sys
    import time

    # -- Call LM Studio --------------------------------------------------------
    try:
        done = False
        def progress_bar():
            start = time.time()
            bar_len = 30
            pos = 0
            direction = 1
            while not done:
                elapsed = time.time() - start
                
                # Create a bouncing scanner effect (Cylon style)
                bar = ['-'] * bar_len
                bar[pos] = '#'
                if pos > 0: bar[pos-1] = '='
                if pos < bar_len - 1: bar[pos+1] = '='
                
                bar_str = "".join(bar)
                sys.stdout.write(
                    f"\r[SafeMail-X Deep Engine] [{bar_str}] Analyzing threat vectors... "
                    f"({int(elapsed)}s elapsed)  "
                )
                sys.stdout.flush()
                
                pos += direction
                if pos == bar_len - 1:
                    direction = -1
                elif pos == 0:
                    direction = 1
                    
                time.sleep(0.1)

        t = threading.Thread(target=progress_bar)
        t.start()

        try:
            resp = requests.post(LM_STUDIO_URL, json=payload,
                                 timeout=LM_STUDIO_TIMEOUT)
            resp.raise_for_status()
        finally:
            done = True
            t.join()
            sys.stdout.write(
                f"\r[SafeMail-X Deep Engine] [{'#' * 30}] 100% (Complete)"
                f"                \n")
            sys.stdout.flush()

        msg = resp.json()["choices"][0]["message"]
        content = msg.get("content", "") or ""
        reasoning = msg.get("reasoning_content", "") or ""
        
        # Combine them because sometimes Qwen places the JSON inside the reasoning block
        raw = (reasoning + "\n" + content).strip()
        print(f"[SafeMail-X Deep Engine] Analysis complete. "
              f"({len(raw)} chars received)")

    except requests.exceptions.ConnectionError:
        print("[SafeMail-X Deep Engine] LM Studio not running "
              "-- fallback to TF-IDF.")
        return None
    except requests.exceptions.Timeout:
        print("[SafeMail-X Deep Engine] LM Studio timed out (>90s) "
              "-- fallback to TF-IDF.")
        return None
    except Exception as e:
        print(f"[SafeMail-X Deep Engine] API error: {e} "
              "-- fallback to TF-IDF.")
        return None

    # -- Parse JSON ------------------------------------------------------------
    try:
        # Try direct parse first (Qwen 3.5 with json mode should be clean)
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            # Fallback: extract first {...} block
            m = re.search(r"\{[\s\S]*\}", raw)
            if not m:
                raise ValueError("No JSON object found in LLM output")
            parsed = json.loads(m.group(0))
    except (json.JSONDecodeError, ValueError) as e:
        print(f"[SafeMail-X Deep Engine] JSON parse failed: {e} "
              "-- fallback to TF-IDF.")
        return None

    # -- Validate & clamp every field ------------------------------------------
    def _clamp_int(val, lo, hi, default):
        try:
            return min(max(int(val), lo), hi)
        except (TypeError, ValueError):
            return default

    def _clamp_float(val, lo, hi, default):
        try:
            return min(max(float(val), lo), hi)
        except (TypeError, ValueError):
            return default

    threat  = _clamp_float(parsed.get("threat_probability"), 0.0, 1.0, 0.5)
    urgency = _clamp_int(parsed.get("urgency_score"),    0, 10, 5)
    legit   = _clamp_int(parsed.get("legitimacy_score"), 0, 10, 5)
    grammar = _clamp_int(parsed.get("grammar_score"),    0, 10, 5)
    cohere  = _clamp_int(parsed.get("coherence_score"),  0, 10, 5)

    tactics = parsed.get("social_engineering_tactics", [])
    if not isinstance(tactics, list):
        tactics = []
    tactics = [t for t in tactics
               if isinstance(t, str) and t.lower() != "none_detected"]
               
    intent = str(parsed.get("detected_intent", "unknown")).lower()

    reasoning = str(parsed.get("reasoning",
                               "No detailed reasoning provided."))

    # -- Calculate LLM Confidence Score (0.0 to 1.0) ---------------------------
    confidence = 0.5  # Base confidence
    
    if len(tactics) > 0:
        confidence += 0.2
    if urgency >= 8:
        confidence += 0.1
    if legit >= 8:
        confidence += 0.1
    if cohere >= 7:
        confidence += 0.1
    if intent in ["credential_theft", "financial_fraud", "malware_delivery", "coercion"]:
        confidence += 0.2
    elif intent in ["benign_notification", "marketing"]:
        confidence += 0.2  # Confident that it's safe
        
    confidence = min(1.0, confidence)

    result = {
        "llm_score":        threat,
        "urgency_score":    urgency,
        "legitimacy_score": legit,
        "grammar_score":    grammar,
        "coherence_score":  cohere,
        "tactics":          tactics,
        "intent":           intent,
        "reasoning":        reasoning,
        "confidence":       round(confidence, 2),
        "llm_available":    True,
    }

    print(f"[SafeMail-X Deep Engine] Threat: {threat:.2f} | Confidence: {confidence:.2f} | "
          f"Intent: {intent} | Tactics: {tactics}")
    return result
