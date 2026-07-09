# =============================================
# TrustMail LLM Analysis Module
# Uses Qwen 2.5 through LM Studio
# =============================================

import json
import re
from urllib.parse import urlparse

import requests

from utils.config import (
    LLM_BASE_URL,
    LLM_EMAIL_CHAR_LIMIT,
    LLM_HEALTH_URL,
    LLM_MAX_CONTEXT_TOKENS,
    LLM_MAX_OUTPUT_TOKENS,
    LLM_MODEL,
    LLM_PROVIDER,
    LLM_TIMEOUT,
    LM_STUDIO_AUTO_CONTEXT,
)

# -- System prompts -------------------------------------------------------------
PROMPTS = {
    "email": """You are TrustMail Threat Intelligence Engine, a forensic email analyst.

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
  "detected_intent": <string from: ["credential_theft", "financial_fraud", "malware_delivery", "coercion", "benign_notification", "marketing", "conversational", "unknown"]>,
  "threat_probability": <float 0.0-1.0>,
  "reasoning": <string: 2-3 sentence professional assessment. Include the apparent intent, the strongest benign or suspicious evidence, and what factor most influenced the score. Do not expose hidden chain-of-thought.>
}

EXAMPLE OUTPUT:
{
  "urgency_score": 2,
  "legitimacy_score": 0,
  "grammar_score": 0,
  "coherence_score": 0,
  "social_engineering_tactics": [],
  "detected_intent": "benign_notification",
  "threat_probability": 0.05,
  "reasoning": "This is a standard automated notification from a verified service with no suspicious links."
}

RULES:
- Return ONLY valid JSON. No markdown fences, no extra text, no thinking tags.
- If the email is clearly a real service notification, give it LOW scores.
- NEVER flag a legitimate marketing email as high-threat just because it uses urgency words.
- Focus on INTENT and DECEPTION, not just keywords.
- If the message is extremely short and conversational (e.g., 'hey there', 'how are you') with NO links and NO suspicious requests, score it EXACTLY threat_probability: 0.0 and set detected_intent: 'conversational'.""",

    "sms": """You are a Cybersecurity SMS Analyst specializing in SMISHING (SMS Phishing) detection.

Your job is to determine whether an SMS text message is a PHISHING attempt or LEGITIMATE.

CRITICAL FOCUS FOR SMS:
- Smishing often relies on extremely short links (bit.ly, tinyurl) or deceptive typosquatting.
- Attackers frequently impersonate delivery services (USPS, FedEx, UPS), banks, or government agencies (IRS).
- Look for severe urgency: "Your package is held", "Your account is locked", "Final notice".

You will be provided with the SMS text and hard forensic facts extracted by our engines.

Return a JSON object with EXACTLY these keys:
{
  "urgency_score": <integer 0-10, 0=no urgency, 10=extreme artificial panic>,
  "legitimacy_score": <integer 0-10, 0=clearly genuine, 10=clearly impersonating>,
  "grammar_score": <integer 0-10, 0=professional, 10=very poor/suspicious>,
  "coherence_score": <integer 0-10, 0=fully logical, 10=nonsensical template>,
  "social_engineering_tactics": <list from: ["pretexting","authority_impersonation","fear_appeal","reward_lure","artificial_scarcity","credential_harvesting","false_deadline","trust_exploitation","none_detected"]>,
  "detected_intent": <string from: ["credential_theft", "financial_fraud", "malware_delivery", "coercion", "benign_notification", "marketing", "conversational", "unknown"]>,
  "threat_probability": <float 0.0-1.0>,
  "reasoning": <string: 2-3 sentence professional assessment based on the text AND the provided metadata facts.>
}

RULES:
- Return ONLY valid JSON. No markdown fences, no extra text.
- Rely heavily on the provided metadata/features to inform your probability score.
- If the message is extremely short and conversational (e.g., 'hey there', 'how are you') with NO links and NO suspicious requests, score it EXACTLY threat_probability: 0.0 and set detected_intent: 'conversational'.""",

    "text": """You are a Cybersecurity Text Analyst specializing in raw message detection.

Your job is to determine whether a raw text message or email excerpt is a PHISHING attempt or LEGITIMATE.

CRITICAL FOCUS FOR RAW TEXT:
- Attackers frequently impersonate delivery services, banks, or corporate IT.
- Look for severe urgency or demands to verify accounts.
- If the text is just a standard system test or completely benign (e.g., 'test', 'hello'), score it very low.

Return a JSON object with EXACTLY these keys:
{
  "urgency_score": <integer 0-10, 0=no urgency, 10=extreme artificial panic>,
  "legitimacy_score": <integer 0-10, 0=clearly genuine, 10=clearly impersonating>,
  "grammar_score": <integer 0-10, 0=professional, 10=very poor/suspicious>,
  "coherence_score": <integer 0-10, 0=fully logical, 10=nonsensical template>,
  "social_engineering_tactics": <list from: ["pretexting","authority_impersonation","fear_appeal","reward_lure","artificial_scarcity","credential_harvesting","false_deadline","trust_exploitation","none_detected"]>,
  "detected_intent": <string from: ["credential_theft", "financial_fraud", "malware_delivery", "coercion", "benign_notification", "marketing", "conversational", "unknown"]>,
  "threat_probability": <float 0.0-1.0>,
  "reasoning": <string: 2-3 sentence professional assessment based on the text AND the provided metadata facts.>
}

RULES:
- Return ONLY valid JSON. No markdown fences, no extra text.
- If the message is extremely short and conversational (e.g., 'hey there', 'how are you') with NO links and NO suspicious requests, score it EXACTLY threat_probability: 0.0 and set detected_intent: 'conversational'.""",

    "url": """You are a Cybersecurity Web Analyst specializing in malicious URL detection and credential harvesting lures.

Your job is to determine whether a given URL and its context represent a PHISHING threat or are LEGITIMATE.

CRITICAL FOCUS FOR URLs:
- Look closely at the provided heuristic metadata (domain age, typosquatting hits, entropy).
- If the metadata shows typosquatting (e.g. "paypal.com" vs "paypa1.com"), score the threat VERY HIGH.
- If the metadata shows a newly registered domain (age < 14 days), treat it with high suspicion.
- Evaluate any contextual text provided along with the URL for deceptive lures.

Return a JSON object with EXACTLY these keys:
{
  "urgency_score": <integer 0-10, 0=no urgency, 10=extreme artificial panic>,
  "legitimacy_score": <integer 0-10, 0=clearly genuine, 10=clearly impersonating>,
  "grammar_score": <integer 0-10, 0=professional, 10=very poor/suspicious>,
  "coherence_score": <integer 0-10, 0=fully logical, 10=nonsensical template>,
  "social_engineering_tactics": <list from: ["pretexting","authority_impersonation","fear_appeal","reward_lure","artificial_scarcity","credential_harvesting","false_deadline","trust_exploitation","none_detected"]>,
  "detected_intent": <string from: ["credential_theft", "financial_fraud", "malware_delivery", "coercion", "benign_notification", "marketing", "conversational", "unknown"]>,
  "threat_probability": <float 0.0-1.0>,
  "reasoning": <string: 2-3 sentence professional assessment based heavily on the heuristic URL features.>
}

RULES:
- Return ONLY valid JSON. No markdown fences, no extra text.""",

    "file": """You are a Cybersecurity Malware Analyst specializing in document lures.

Your job is to determine whether a file's extracted text and metadata represent a THREAT (e.g., dropper, macro-enabled lure) or are LEGITIMATE.

CRITICAL FOCUS FOR FILES:
- Threat actors use fake invoices, receipts, and encrypted document notifications to trick users into enabling macros or calling a fake phone number (Callback Phishing/BazarCall).
- If the metadata indicates suspicious macros or YARA hits, score the threat probability extremely high.
- If the text tells the user to "Enable Editing" or "Enable Content" to view the file, it is highly likely a malicious dropper.

Return a JSON object with EXACTLY these keys:
{
  "urgency_score": <integer 0-10, 0=no urgency, 10=extreme artificial panic>,
  "legitimacy_score": <integer 0-10, 0=clearly genuine, 10=clearly impersonating>,
  "grammar_score": <integer 0-10, 0=professional, 10=very poor/suspicious>,
  "coherence_score": <integer 0-10, 0=fully logical, 10=nonsensical template>,
  "social_engineering_tactics": <list from: ["pretexting","authority_impersonation","fear_appeal","reward_lure","artificial_scarcity","credential_harvesting","false_deadline","trust_exploitation","none_detected"]>,
  "detected_intent": <string from: ["credential_theft", "financial_fraud", "malware_delivery", "coercion", "benign_notification", "marketing", "conversational", "unknown"]>,
  "threat_probability": <float 0.0-1.0>,
  "reasoning": <string: 2-3 sentence professional assessment. Highlight if the text contains lure language like "Enable Macros".>
}

RULES:
- Return ONLY valid JSON. No markdown fences, no extra text."""
}

def get_system_prompt(channel: str) -> str:
    return PROMPTS.get(channel, PROMPTS["email"])


def _estimate_tokens(text: str) -> int:
    """Rough token estimate good enough for local context budgeting."""
    return max(1, len(text) // 4)


def _detect_loaded_context_tokens() -> int:
    """Read the active LM Studio context length when the local API exposes it."""
    if not LM_STUDIO_AUTO_CONTEXT:
        return LLM_MAX_CONTEXT_TOKENS

    if LLM_PROVIDER != "lmstudio":
        return LLM_MAX_CONTEXT_TOKENS

    try:
        parsed = urlparse(LLM_BASE_URL)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        resp = requests.get(f"{base_url}/api/v1/models", timeout=3)
        resp.raise_for_status()
        for model in resp.json().get("models", []):
            if model.get("key") != LLM_MODEL:
                continue
            for instance in model.get("loaded_instances", []):
                context_length = instance.get("config", {}).get("context_length")
                if context_length:
                    detected = int(context_length)
                    print(f"[LLM] LM Studio context detected: {detected} tokens")
                    return detected
    except Exception as e:
        print(f"[LLM] Context auto-detect unavailable: {e}")

    return LLM_MAX_CONTEXT_TOKENS


def _fit_email_to_context(prefix: str, suffix: str, email_text: str,
                          force_char_limit: int | None = None) -> str:
    """
    Fit the email excerpt inside the loaded LM Studio context window.
    Qwen2.5 1M can support long context, but LM Studio may load it with a
    smaller context_length (often 4096), so request size must respect that.
    """
    if force_char_limit is not None:
        char_limit = force_char_limit
    else:
        # Fallback to estimating based on the email prompt
        reserved_prompt_tokens = _estimate_tokens(PROMPTS["email"] + prefix + suffix)
        context_tokens = _detect_loaded_context_tokens()
        available_tokens = (
            context_tokens
            - LLM_MAX_OUTPUT_TOKENS
            - reserved_prompt_tokens
            - 256
        )
        available_chars = max(1200, available_tokens * 4)
        char_limit = min(LLM_EMAIL_CHAR_LIMIT, available_chars)

    if len(email_text) <= char_limit:
        return email_text

    head_chars = int(char_limit * 0.7)
    tail_chars = max(400, int(char_limit * 0.3))
    omitted = len(email_text) - head_chars - tail_chars
    return (
        email_text[:head_chars]
        + f"\n\n[... {omitted} characters omitted for local LLM context budget ...]\n\n"
        + email_text[-tail_chars:]
    )


def _build_user_message(prefix: str, suffix: str, email_text: str,
                        force_char_limit: int | None = None) -> str:
    email_excerpt = _fit_email_to_context(
        prefix,
        suffix,
        email_text,
        force_char_limit=force_char_limit,
    )
    return (
        prefix
        + "\n--- EMAIL BODY ---\n"
        + email_excerpt
        + suffix
    )


def _is_context_error(resp: requests.Response) -> bool:
    body = resp.text.lower()
    return resp.status_code == 400 and any(
        marker in body
        for marker in ["context", "n_ctx", "n_keep", "prompt"]
    )


def run_llm_analysis(
    channel: str = "email",
    email_text: str = "",
    subject: str = "",
    sender: str = "",
    security_summary: str = "",
    text: str | None = None,
) -> dict | None:
    """
    Send email content to Qwen 2.5 7B and return structured features.

    Returns a dict with keys:
        llm_score, urgency_score, legitimacy_score, grammar_score,
        coherence_score, tactics, intent, reasoning, confidence, llm_available

    Returns None if LM Studio is offline/fails — the caller
    (hybrid_engine) will seamlessly fall back to TF-IDF only.
    """

    # Backward compatibility:
    # - older callers passed text="..."
    # - some legacy callers passed the body as the first positional argument
    if text is not None and not email_text:
        email_text = text
    if channel not in PROMPTS and not email_text:
        email_text = channel
        channel = "email"

    system_prompt = get_system_prompt(channel)

    # Build the user message with the available forensic context.
    user_prefix = (
        f"Analyze this {channel} using the forensic protocol.\n\n"
        f"SENDER/SOURCE: {sender}\n"
        f"SUBJECT/TITLE: {subject}\n"
    )

    # Add authentication context when it is available.
    if security_summary:
        user_prefix += f"AUTHENTICATION/FEATURES: {security_summary}\n"

    user_suffix = (
        "\n--- END ---\n\n"
        "Apply the protocol internally to evaluate the content. "
        "DO NOT output your internal reasoning steps. You must output ONLY the final JSON object."
    )
    
    # We must patch _fit_email_to_context and _build_user_message calls locally
    # since they previously relied on the global SYSTEM_PROMPT. 
    # For now, we will compute char_limit locally or rely on their default logic.
    user_msg = _build_user_message(user_prefix, user_suffix, email_text)

    payload = {
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_msg},
        ],
        "temperature": 0.1,
        "top_p": 0.8,
        "max_tokens": LLM_MAX_OUTPUT_TOKENS,
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
                
                # Draw a simple progress indicator while the request is running.
                bar = ['-'] * bar_len
                bar[pos] = '#'
                if pos > 0: bar[pos-1] = '='
                if pos < bar_len - 1: bar[pos+1] = '='
                
                bar_str = "".join(bar)
                sys.stdout.write(
                    f"\r[LLM] [{bar_str}] Running analysis... "
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
            resp = requests.post(LLM_BASE_URL, json=payload,
                                 timeout=LLM_TIMEOUT)
            if _is_context_error(resp):
                print("[LLM] Context limit hit; retrying with shorter excerpts.")
                last_context_error = resp.text[:240].replace("\n", " ")
                for forced_limit in (12000, 6000, 2500):
                    shorter_payload = dict(payload)
                    shorter_messages = [dict(m) for m in payload["messages"]]
                    shorter_messages[1]["content"] = _build_user_message(
                        user_prefix,
                        user_suffix,
                        email_text,
                        force_char_limit=forced_limit,
                    )
                    shorter_payload["messages"] = shorter_messages
                    shorter_payload["max_tokens"] = min(400, LLM_MAX_OUTPUT_TOKENS)
                    resp = requests.post(
                        LLM_BASE_URL,
                        json=shorter_payload,
                        timeout=LLM_TIMEOUT,
                    )
                    if not _is_context_error(resp):
                        print(f"[LLM] Retry succeeded with {forced_limit} chars.")
                        break
                    last_context_error = resp.text[:240].replace("\n", " ")
                if _is_context_error(resp):
                    print(f"[LLM] Context retries exhausted: {last_context_error}")
            resp.raise_for_status()
        finally:
            done = True
            t.join()
            sys.stdout.write(
                f"\r[LLM] [{'#' * 30}] 100% (Complete)"
                f"                \n")
            sys.stdout.flush()

        msg = resp.json()["choices"][0]["message"]
        content = msg.get("content", "") or ""
        reasoning = msg.get("reasoning_content", "") or ""
        
        # Some responses place the JSON inside the reasoning block, so combine both.
        raw = (reasoning + "\n" + content).strip()
        print(f"[LLM] Analysis complete. "
              f"({len(raw)} chars received)")

    except requests.exceptions.ConnectionError:
        print("[LLM] LM Studio not running "
              "-- fallback to TF-IDF.")
        return None
    except requests.exceptions.Timeout:
        print("[LLM] LM Studio timed out (>90s) "
              "-- fallback to TF-IDF.")
        return None
    except requests.exceptions.HTTPError as e:
        body = e.response.text[:300].replace("\n", " ") if e.response is not None else ""
        print(f"[LLM] API error: {e}; response={body} "
              "-- fallback to TF-IDF.")
        return None
    except Exception as e:
        print(f"[LLM] API error: {e} "
              "-- fallback to TF-IDF.")
        return None

    # -- Parse JSON ------------------------------------------------------------
    try:
        # Try direct JSON parsing first.
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            # Fallback 1: remove markdown code blocks if present.
            clean_raw = re.sub(r"```(?:json)?\s*([\s\S]*?)\s*```", r"\1", raw).strip()
            try:
                parsed = json.loads(clean_raw)
            except json.JSONDecodeError:
                # Fallback 2: extract the last JSON-like block.
                matches = list(re.finditer(r"\{[\s\S]*\}", raw))
                if not matches:
                    # Fallback 3: no JSON-like block was returned.
                    raise ValueError("No JSON object found in LLM output")
                
                # Use the last match, which is usually the final JSON object.
                json_candidate = matches[-1].group(0)
                parsed = json.loads(json_candidate)
                
    except (json.JSONDecodeError, ValueError) as e:
        print(f"[LLM] JSON parse failed: {e}")
        # Print a short preview to help with local debugging.
        debug_snippet = raw[:500].replace("\n", " ")
        print(f"[LLM] RAW OUTPUT PREVIEW: {debug_snippet}...")
        print("[LLM] Falling back to TF-IDF.")
        return None

    # -- Validate and clamp every field ----------------------------------------
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

    # -- Calculate LLM confidence score ----------------------------------------
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
    elif intent in ["benign_notification", "marketing", "conversational"]:
        confidence += 0.2  # Strong confidence in a benign result
        
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

    print(f"[LLM] Threat: {threat:.2f} | Confidence: {confidence:.2f} | "
          f"Intent: {intent} | Tactics: {tactics}")
    return result
