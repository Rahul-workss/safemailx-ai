"""
Layer 2 — Manipulation Sequence Detector
All scam calls follow a 6-stage psychological manipulation sequence.
Detecting the sequence is language-independent fraud detection.
"""
import logging
from typing import Optional

logger = logging.getLogger("MANIPULATION_SEQ")

# The 6 stages with keyword banks in EN + HI + Hinglish
STAGES = {
    "HOOK": [
        # English
        "urgent matter", "important notice", "calling from", "this is regarding",
        "official call", "calling on behalf", "important information",
        # Hindi
        "zaruri baat", "important kaam", "aapke baare mein",
        # Hinglish
        "urgent hai", "official call hai", "important matter hai"
    ],
    "FEAR": [
        # English
        "flagged", "illegal activity", "arrested", "warrant", "blocked",
        "suspended", "case registered", "FIR", "narcotics", "money laundering",
        "criminal charges", "cyber crime", "fraud detected", "account compromised",
        # Hindi
        "giraftari", "case darj", "illegal", "band ho jayega", "arrest hoga",
        "warrant nikla", "pakad liya jayega",
        # Hinglish
        "account block ho jayega", "case ho gaya hai", "arrest ho sakte hain",
        "FIR darj ho sakti hai"
    ],
    "AUTHORITY": [
        # English
        "CBI", "cyber crime cell", "RBI", "TRAI", "Supreme Court",
        "enforcement directorate", "ED", "income tax officer", "customs officer",
        "NARCOTICS", "department of", "government of india", "ministry of",
        # Hindi
        "pulis", "court", "sarkar", "adhikari", "vibhag", "sarkaari",
        # Hinglish
        "CBI officer", "government authority", "cyber cell wale"
    ],
    "URGENCY": [
        # English
        "2 hours", "immediately", "right now", "today only", "final warning",
        "last chance", "before midnight", "within 24 hours", "emergency",
        "time is running out", "act now",
        # Hindi
        "abhi", "turant", "2 ghante mein", "aaj hi", "warna", "jaldi karo",
        # Hinglish
        "immediate action lo", "abhi karo warna late ho jayega",
        "2 ghante mein action chahiye"
    ],
    "ISOLATION": [
        "don't tell anyone", "do not hang up", "stay on the line",
        "don't call anyone else", "keep confidential", "do not share",
        "kisi ko mat batana", "line mat katna", "family ko mat batao",
        "please hold the line", "kisi ko mat bolo", "dont disconnect"
    ],
    "ACTION": [
        # English
        "transfer money", "share OTP", "install app", "pay immediately",
        "safe account", "verify card", "Google Pay", "share screen",
        "TeamViewer", "AnyDesk", "remote access", "give OTP",
        "send money", "UPI transfer",
        # Hindi
        "paisa bhejo", "OTP batao", "app install karo", "transfer karo",
        # Hinglish
        "money transfer karo", "OTP share karo", "app download karo"
    ]
}

STAGE_ORDER = ["HOOK", "FEAR", "AUTHORITY", "URGENCY", "ISOLATION", "ACTION"]

SCORE_MAP = {1: 0.10, 2: 0.25, 3: 0.50, 4: 0.72, 5: 0.88, 6: 0.96}

# Benign urgency whitelist — these should NOT count as FEAR/URGENCY in legitimate contexts
BENIGN_URGENCY_WHITELIST = [
    "emi due", "payment due", "minimum due", "bill due", "recharge due"
]


def analyze(transcript: str, claims: Optional[dict] = None) -> dict:
    transcript_lower = transcript.lower()

    # Check for benign urgency (legitimate payment reminders)
    is_benign_urgency = any(phrase in transcript_lower for phrase in BENIGN_URGENCY_WHITELIST)

    stages_detected = []
    stage_evidence = {}

    for stage_name in STAGE_ORDER:
        keywords = STAGES[stage_name]
        found_kw = None
        for kw in keywords:
            if kw.lower() in transcript_lower:
                # Skip FEAR/URGENCY if it's a benign payment reminder
                if stage_name in ("FEAR", "URGENCY") and is_benign_urgency:
                    continue
                found_kw = kw
                break
        if found_kw:
            stages_detected.append(stage_name)
            stage_evidence[stage_name] = found_kw

    count = len(stages_detected)
    score = SCORE_MAP.get(count, 0.0)

    if count >= 3:
        stages_str = " → ".join(stages_detected)
        logger.info("[MANIPULATION] %d stages detected: %s", count, stages_str)
        return {
            "score": score,
            "finding": "manipulation_sequence_detected",
            "plain_english": f"Manipulation sequence detected: {stages_str}. Scam calls follow predictable psychological patterns — {count} of 6 stages identified. Legitimate organizations never follow this pattern.",
            "evidence": {"stages_detected": stages_detected, "stage_evidence": stage_evidence, "count": count},
            "hard_floor": 0.88 if count >= 5 else None
        }
    elif count > 0:
        return {
            "score": score,
            "finding": "partial_manipulation_sequence",
            "plain_english": f"{count} manipulation stage(s) detected ({', '.join(stages_detected)}). Not enough to confirm a full scam pattern alone.",
            "evidence": {"stages_detected": stages_detected, "count": count},
            "hard_floor": None
        }
    else:
        return {
            "score": 0.0,
            "finding": "no_manipulation_sequence",
            "plain_english": "No manipulation sequence detected.",
            "evidence": {"stages_detected": [], "count": 0},
            "hard_floor": None
        }
