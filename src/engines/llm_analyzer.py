# =============================================
# TrustMail LLM Analysis Module
# Qwen 3 8B (thinking mode) via LM Studio
# =============================================

import json
import re
from urllib.parse import urlparse

import requests

from utils.config import (
    LLM_BASE_URL,
    LLM_ENABLE_THINKING,
    LLM_EMAIL_CHAR_LIMIT,
    LLM_HEALTH_URL,
    LLM_MAX_CONTEXT_TOKENS,
    LLM_MAX_OUTPUT_TOKENS,
    LLM_MODEL,
    LLM_PROVIDER,
    LLM_TIMEOUT,
    LM_STUDIO_AUTO_CONTEXT,
)
import logging as _logging
_llc_logger = _logging.getLogger(__name__)


def _get_live_config() -> dict:
    """Read LLM config fresh from .env on every call — no restart needed for model changes.
    Self-contained: uses Path(__file__) so it works regardless of CWD or import context.
    Logs any failure so bugs are visible in uvicorn/worker logs.
    """
    try:
        from pathlib import Path as _Path
        # src/engines/llm_analyzer.py → parents[0]=engines, parents[1]=src, parents[2]=project root
        _env_path = _Path(__file__).resolve().parents[2] / ".env"
        _env: dict = {}
        if _env_path.exists():
            with open(_env_path, "r", encoding="utf-8", errors="replace") as _f:
                for _line in _f:
                    _line = _line.strip()
                    if _line and not _line.startswith("#") and "=" in _line:
                        _k, _, _v = _line.partition("=")
                        _env[_k.strip()] = _v.strip()
        _model = _env.get("LLM_MODEL", "").strip() or LLM_MODEL
        _thinking_raw = _env.get("LLM_ENABLE_THINKING", "").strip().lower()
        _thinking = _thinking_raw in {"1", "true", "yes", "on"} if _thinking_raw else LLM_ENABLE_THINKING
        try:
            _max_tokens = int(_env.get("LLM_MAX_OUTPUT_TOKENS", str(LLM_MAX_OUTPUT_TOKENS)))
        except (ValueError, TypeError):
            _max_tokens = LLM_MAX_OUTPUT_TOKENS
        return {"model": _model, "thinking": _thinking, "max_tokens": _max_tokens}
    except Exception as _exc:
        _llc_logger.warning(
            "_get_live_config() failed, using startup defaults. "
            "model=%s thinking=%s max_tokens=%s  error=%s",
            LLM_MODEL, LLM_ENABLE_THINKING, LLM_MAX_OUTPUT_TOKENS, _exc
        )
        return {"model": LLM_MODEL, "thinking": LLM_ENABLE_THINKING, "max_tokens": LLM_MAX_OUTPUT_TOKENS}



# -- Feature 2: Prompt Injection Guard -----------------------------------------
try:
    from engines.prompt_injection_guard import scan_for_prompt_injection, sanitize_for_prompt
    _INJECTION_GUARD_AVAILABLE = True
except ImportError:
    _INJECTION_GUARD_AVAILABLE = False
    def scan_for_prompt_injection(text):  # type: ignore[misc]
        return {"injection_detected": False, "matched_patterns": [], "encoding_hints": [], "confidence": 0.0}
    def sanitize_for_prompt(text, max_len=8000):  # type: ignore[misc]
        return text[:max_len] if text else ""


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
  "urgency_score": <integer 0-10. 0=completely calm/no urgency. 10=extreme artificial panic. A real bank alert scores 1-2. A "ACCOUNT DELETED IN 1 HOUR" phishing scores 9-10.>,
  "legitimacy_score": <integer 0-10. 0=clearly a genuine email from a real org. 10=clearly impersonating a real org. A real Moneyview loan email scores 1-2. A fake Amazon account alert scores 8-9.>,
  "grammar_score": <integer 0-10. 0=perfect professional grammar. 10=very poor, suspicious, machine-translated. A well-written corporate email scores 0-1.>,
  "coherence_score": <integer 0-10. 0=fully logical and coherent. 10=nonsensical, generic template with no specifics. A personalized notification with loan ID scores 0-2.>,
  "social_engineering_tactics": <list from: ["pretexting","authority_impersonation","fear_appeal","reward_lure","artificial_scarcity","credential_harvesting","false_deadline","trust_exploitation","none_detected"]. Only include tactics that are ACTUALLY PRESENT. An informational update with no manipulation gets []>,
  "detected_intent": <string from: ["credential_theft", "financial_fraud", "malware_delivery", "coercion", "benign_notification", "marketing", "conversational", "unknown"]>,
  "threat_probability": <float 0.0-1.0>,
  "confidence": <float 0.0-1.0, how certain you are about your threat_probability. 0.9+ = very sure, 0.5 = genuinely ambiguous>,
  "reasoning": <string: 2-3 sentence professional assessment. Include the apparent intent, the strongest benign or suspicious evidence, and what factor most influenced the score. Do not expose hidden chain-of-thought.>
}

EXAMPLE OUTPUT (legitimate loan notification):
{
  "urgency_score": 1,
  "legitimacy_score": 1,
  "grammar_score": 0,
  "coherence_score": 1,
  "social_engineering_tactics": [],
  "detected_intent": "benign_notification",
  "threat_probability": 0.05,
  "confidence": 0.92,
  "reasoning": "This is a standard automated notification from a verified service with no suspicious links."
}

RULES:
- Return ONLY the JSON object in your final response. No markdown fences, no extra text.
- If the email is clearly a real service notification, give it LOW scores (0-2 range).
- NEVER flag a legitimate marketing email as high-threat just because it uses urgency words.
- Focus on INTENT and DECEPTION, not just keywords.
- social_engineering_tactics must only list tactics ACTUALLY present — do NOT add "reward_lure" for a routine service update.
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
- Return ONLY the JSON object in your final response. No markdown fences, no extra text.
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
- Return ONLY the JSON object in your final response. No markdown fences, no extra text.
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
- Return ONLY the JSON object in your final response. No markdown fences, no extra text.""",

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
- Return ONLY the JSON object in your final response. No markdown fences, no extra text."""
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


def _clean_prompt_field(value: str | None, max_len: int) -> str:
    value = str(value or "")[:max_len]
    if _INJECTION_GUARD_AVAILABLE:
        return sanitize_for_prompt(value, max_len=max_len)
    return value


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
    Send content to the configured LLM (Qwen 3 8B via LM Studio) and return structured features.

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

    sender = _clean_prompt_field(sender, 320)
    subject = _clean_prompt_field(subject, 500)
    security_summary = _clean_prompt_field(security_summary, 6000)
    email_text = _clean_prompt_field(email_text, LLM_EMAIL_CHAR_LIMIT)
    combined_context = "\n".join((sender, subject, security_summary, email_text))
    injection_finding = scan_for_prompt_injection(combined_context)

    system_prompt = get_system_prompt(channel)

    # ── Live config read (always fresh from .env — no restart needed) ──────
    _live_cfg = _get_live_config()
    print(
        f"[LLM] Scan config: model={_live_cfg['model']!r}  "
        f"max_tokens={_live_cfg['max_tokens']}  "
        f"thinking={_live_cfg['thinking']}  "
        f"channel={channel!r}"
    )

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
        "Apply the protocol to evaluate the content. "
        "Output ONLY the final JSON object in your response — no preambles, no markdown, no extra text."
    )

    # -- Feature 2: Prompt Injection Guard ------------------------------------
    # sanitize_for_prompt runs UNCONDITIONALLY — zero scoring impact, pure defense.
    # scan_for_prompt_injection result is attached to the returned dict so
    # hybrid_engine can apply the score floor if injection is detected.
    user_msg = _build_user_message(user_prefix, user_suffix, email_text)

    payload = {
        "model": _live_cfg["model"],
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_msg},
        ],
        "temperature": 0.1,
        "top_p": 0.8,
        "max_tokens": _live_cfg["max_tokens"],
        "stream": False,
    }
    # Enable Qwen 3 chain-of-thought reasoning via LM Studio chat_template_kwargs.
    # LLM_ENABLE_THINKING=false in .env disables this for Qwen 2.5 rollback.
    # Both values are read live from .env so changes take effect without restart.
    if _live_cfg["thinking"]:
        payload["chat_template_kwargs"] = {"enable_thinking": True}


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

        t = threading.Thread(target=progress_bar, daemon=True)
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
        content     = (msg.get("content", "") or "").strip()
        think_block = (msg.get("reasoning_content", "") or "").strip()

        think_words = len(think_block.split()) if think_block else 0
        print(f"[LLM] Analysis complete. "
              f"({len(content)} chars in answer"
              f"{f', {think_words} think-words' if think_block else ''})")

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

    # -- Parse JSON — 2-stage parser for Qwen 3 thinking mode -----------------
    # Stage 1: Try the content field directly.
    #   Qwen 3 (thinking mode): LM Studio puts the JSON answer in `content`
    #   and the think block in `reasoning_content`. Parsing `content` alone
    #   is clean — no think-block text to confuse the parser.
    # Stage 2: Fallback — search combined text.
    #   Qwen 2.5 path (reasoning_content is always empty, JSON is in content).
    #   Also catches edge cases where content has a preamble before the JSON.
    raw = content  # used in error messages; may be overwritten in Stage 2
    try:
        _parsed_s1 = None
        if content:
            try:
                _parsed_s1 = json.loads(content)
            except json.JSONDecodeError:
                # Stage 1b: strip markdown fences from content and retry.
                _clean_content = re.sub(
                    r"```(?:json)?\s*([\s\S]*?)\s*```", r"\1", content
                ).strip()
                try:
                    _parsed_s1 = json.loads(_clean_content)
                    raw = _clean_content
                except json.JSONDecodeError:
                    pass  # fall through to Stage 2

        if _parsed_s1 is not None:
            parsed = _parsed_s1
        else:
            # Stage 2: combine think block + content and search for last JSON object.
            raw = (think_block + "\n" + content).strip()[:100000]
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                clean_raw = re.sub(
                    r"```(?:json)?\s*([\s\S]*?)\s*```", r"\1", raw
                ).strip()
                try:
                    parsed = json.loads(clean_raw)
                except json.JSONDecodeError:
                    matches = list(re.finditer(r"\{[\s\S]*\}", raw))
                    if not matches:
                        raise ValueError("No JSON object found in LLM output")
                    # Use the last match (final JSON object after any think-block examples)
                    json_candidate = matches[-1].group(0)
                    parsed = json.loads(json_candidate)

        if not isinstance(parsed, dict):
            raise ValueError("LLM output was not a JSON object")

    except (json.JSONDecodeError, ValueError) as e:
        print(f"[LLM] JSON parse failed: {e}")
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
    tactics = [t[:80] for t in tactics
               if isinstance(t, str) and t.lower() != "none_detected"][:12]

    allowed_intents = {"credential_theft", "financial_fraud", "malware_delivery", "coercion", "benign_notification", "marketing", "conversational", "unknown"}
    intent = str(parsed.get("detected_intent", "unknown")).lower()
    if intent not in allowed_intents:
        intent = "unknown"

    reasoning = str(parsed.get("reasoning",
                               "No detailed reasoning provided."))[:2000]

    # -- Calculate LLM confidence score ----------------------------------------
    # Model-agnostic: measures HOW CLEARLY the primary outputs point in one
    # direction — not how many suspicious signals exist.
    # This works correctly for both Qwen2.5 and Qwen3 (and future models).
    #
    # Old formula rewarded Qwen2.5's miscalibrated subscores (high legit/cohere
    # on legitimate emails → artificially high confidence). Qwen3 gives correct
    # subscores (low legit for genuine email) → old formula gave 0.7, breaking
    # the safe override threshold of 0.8.

    _BENIGN_INTENTS = {"benign_notification", "conversational", "marketing"}
    _THREAT_INTENTS = {"credential_theft", "financial_fraud", "malware_delivery", "coercion"}

    # Base: how far is threat from the uncertain midpoint (0.5)?
    # 0.0 → ambiguous; 0.5 → completely certain in one direction
    _distance = abs(threat - 0.5)                        # 0.0–0.5
    confidence = 0.40 + (_distance * 1.20)               # maps: 0→0.40, 0.35→0.82, 0.5→1.0

    # Corroboration: threat direction matches intent (both agree → more confident)
    if threat < 0.25 and intent in _BENIGN_INTENTS:
        confidence += 0.15    # LLM clearly says safe AND intent confirms it
    elif threat > 0.70 and intent in _THREAT_INTENTS:
        confidence += 0.15    # LLM clearly says danger AND intent confirms it

    # Corroboration: tactics list is consistent with threat direction
    if tactics and threat > 0.35:
        confidence += 0.10    # tactics found and score is elevated — consistent
    elif not tactics and threat < 0.35:
        confidence += 0.05    # no tactics and score is low — consistent

    # If the LLM itself reported a confidence value (new prompt field), blend it in.
    # The LLM's self-assessment is useful signal but we don't fully trust it to
    # avoid prompt injection attacks that claim high confidence for malicious emails.
    _llm_self_confidence = _clamp_float(parsed.get("confidence"), 0.0, 1.0, None)
    if _llm_self_confidence is not None:
        # Weight: 60% computed (robust), 40% LLM self-reported (informed but manipulable)
        confidence = round(0.60 * confidence + 0.40 * _llm_self_confidence, 2)

    confidence = min(1.0, round(confidence, 2))

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
        # Feature 2: prompt injection finding — new optional key, existing callers ignore it
        "prompt_injection": injection_finding,
    }

    print(f"[LLM] Threat: {threat:.2f} | Confidence: {confidence:.2f} | "
          f"Intent: {intent} | Tactics: {tactics}")
    if injection_finding.get("injection_detected"):
        print(f"[LLM] \u26a0\ufe0f  Prompt injection attempt detected in content "
              f"(confidence={injection_finding['confidence']})")
    return result
