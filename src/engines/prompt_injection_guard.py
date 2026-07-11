# ============================================================
# SafeMail X — Prompt Injection Guard
# Feature 2: Prompt-Injection Defense for the LLM Layer
# Controlled by: FEATURE_PROMPT_INJECTION_GUARD_ENABLED
# ============================================================
# Detects when attacker-controlled content tries to manipulate
# the LLM's verdict via embedded instructions. Two defenses:
#   1. scan_for_prompt_injection() — signals detection to the
#      scoring engine (score floor raised if detected).
#   2. sanitize_for_prompt() — strips fake role tags before
#      content is interpolated into the LLM prompt template.
#      Runs unconditionally — it's cheap and purely defensive.
# ============================================================

import re
import logging
from typing import Optional

logger = logging.getLogger("PROMPT_INJECTION_GUARD")

# ---------------------------------------------------------------------------
# Pattern groups — grouped by technique for easy extension/maintenance.
# When adding new patterns, keep them in the appropriate group and add a
# comment explaining what attack technique they catch.
# ---------------------------------------------------------------------------

# Group 1: Explicit instruction override attempts
_INSTRUCTION_OVERRIDE_PATTERNS = [
    r"ignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above|preceding)\s+instructions?",
    r"disregard\s+(all\s+|any\s+|the\s+)?(previous|prior|above)\s+(instructions?|rules?|prompt)",
    r"forget\s+(everything|all)\s+(you|that)\s+(were|was)\s+told",
    r"new\s+instructions?\s*:",
    r"overriding\s+instructions?\s*:",
    r"updated\s+system\s+prompt\s*:",
]

# Group 2: Role/persona manipulation
_ROLE_MANIPULATION_PATTERNS = [
    r"you\s+are\s+now\s+(in\s+)?(a\s+new|another)\s+(mode|role|persona)",
    r"act\s+as\s+(if|though)\s+you\s+(are|were)",
    r"switch\s+to\s+(developer|jailbreak|unrestricted)\s+mode",
    r"enter\s+(DAN|dev|unrestricted|free)\s+mode",
    r"pretend\s+(that\s+)?you\s+(have\s+no|are\s+not\s+bound\s+by)",
]

# Group 3: Explicit verdict manipulation (attacker telling the LLM what to output)
_VERDICT_MANIPULATION_PATTERNS = [
    r"do\s+not\s+(flag|mark|classify|score)\s+this\s+as\s+(phishing|suspicious|malicious)",
    r"(always\s+)?(classify|score|mark|label)\s+this\s+(email|message|content)\s+as\s+(safe|legitimate|not\s+phishing)",
    r"respond\s+only\s+with.{0,30}(legitimate|safe|score.{0,10}0)",
    r"this\s+(email|message)\s+is\s+(safe|legitimate|not\s+phishing).{0,60}(please|always)\s+(confirm|classify|score)\s+it\s+as\s+such",
    r"your\s+final\s+answer\s+(must|should)\s+be.{0,30}(legitimate|safe|0\s*%|score\s*:\s*0)",
]

# Group 4: Fake chat-role / prompt delimiter injection (structural attacks)
_FAKE_ROLE_TAG_PATTERNS = [
    r"</?(?:system|assistant|user|prompt|instruction)>",
    r"\[/?(?:system|assistant|instructions?|prompt|override)\]",
    r"###\s*(?:system|assistant|user|instruction)\s*:",
    r"\|\|\|\s*(?:system|assistant|override)",
]

# Group 5: Encoding hints — weak signal individually, meaningful in combination
_ENCODING_HINT_PATTERNS = [
    r"\bbase64\b",               # suggesting the model decode something hidden
    r"\\u00[0-9a-f]{2}",         # unicode-escape smuggling
    r"&(?:#x?[0-9a-fA-F]+);",    # HTML entity encoding to hide text from filters
    r"\\x[0-9a-fA-F]{2}",        # hex-escape smuggling
]

# Pre-compile all pattern groups at module load (O(1) per call)
_compiled_override = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in _INSTRUCTION_OVERRIDE_PATTERNS]
_compiled_role = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in _ROLE_MANIPULATION_PATTERNS]
_compiled_verdict = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in _VERDICT_MANIPULATION_PATTERNS]
_compiled_fake_tags = [re.compile(p, re.IGNORECASE) for p in _FAKE_ROLE_TAG_PATTERNS]
_compiled_encoding = [re.compile(p, re.IGNORECASE) for p in _ENCODING_HINT_PATTERNS]

# Structural tag patterns reused in sanitize_for_prompt()
_SANITIZE_PATTERNS = [
    re.compile(r"</?(?:system|assistant|user|prompt|instruction)>", re.IGNORECASE),
    re.compile(r"\[/?(?:system|assistant|instructions?|prompt|override)\]", re.IGNORECASE),
    re.compile(r"###\s*(?:system|assistant|user|instruction)\s*:", re.IGNORECASE),
]


def scan_for_prompt_injection(text: str) -> dict:
    """
    Scan arbitrary attacker-controlled text for LLM prompt-injection attempts.

    Returns a structured finding dict. Never raises.

    Return schema:
      injection_detected  bool   — True if a clear injection attempt was found
      matched_patterns    list   — regex patterns that fired (for explainability)
      encoding_hints      list   — encoding anomalies found (weaker signal)
      confidence          float  — 0.0–1.0 estimate of how certain the detection is
    """
    if not text:
        return {
            "injection_detected": False,
            "matched_patterns": [],
            "encoding_hints": [],
            "confidence": 0.0,
        }

    try:
        all_override_matches: list[str] = []

        for pattern in _compiled_override:
            if pattern.search(text):
                all_override_matches.append(pattern.pattern)

        for pattern in _compiled_role:
            if pattern.search(text):
                all_override_matches.append(pattern.pattern)

        for pattern in _compiled_verdict:
            if pattern.search(text):
                all_override_matches.append(pattern.pattern)

        for pattern in _compiled_fake_tags:
            if pattern.search(text):
                all_override_matches.append(pattern.pattern)

        encoding_hints: list[str] = []
        for pattern in _compiled_encoding:
            if pattern.search(text):
                encoding_hints.append(pattern.pattern)

        # Detection logic:
        # - Any override/role/verdict/tag match → detected (clear attack signal)
        # - Encoding hints alone need >= 2 to count (encoding is used legitimately too)
        detected = bool(all_override_matches) or len(encoding_hints) >= 2

        # Confidence: each distinct match group adds weight
        confidence = min(1.0, 0.4 * len(all_override_matches) + 0.15 * len(encoding_hints))

        return {
            "injection_detected": detected,
            "matched_patterns": all_override_matches,
            "encoding_hints": encoding_hints,
            "confidence": round(confidence, 2),
        }

    except Exception as exc:
        logger.warning("[PROMPT_INJECTION] scan_for_prompt_injection error: %s", exc)
        return {
            "injection_detected": False,
            "matched_patterns": [],
            "encoding_hints": [],
            "confidence": 0.0,
        }


def sanitize_for_prompt(text: str, max_len: int = 8000) -> str:
    """
    Defense-in-depth: sanitize untrusted content before interpolating it into
    an LLM prompt template. This does NOT replace scan_for_prompt_injection() —
    both are needed.

    Actions:
      1. Truncate to max_len (limits prompt-stuffing attacks)
      2. Strip fake chat-role / prompt delimiter tags so they render as inert
         text rather than being interpreted as prompt structure.

    This function runs unconditionally (no feature flag) — it has zero scoring
    impact and is pure safety hardening.
    """
    cleaned = text[:max_len] if text else ""
    for pattern in _SANITIZE_PATTERNS:
        cleaned = pattern.sub("[stripped-tag]", cleaned)
    return cleaned
