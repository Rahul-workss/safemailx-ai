"""
Layer 6 — Caller Knowledge Profiler
Real orgs demonstrate specific account knowledge. Scammers only know name + phone.
Only useful when a voice transcript is available (Path A).
"""
import logging
from typing import Optional
import re

logger = logging.getLogger("KNOWLEDGE_PROFILER")

# High specificity patterns — real org employee would say these
HIGH_SPECIFICITY_PATTERNS = [
    r"account ending in \d+",
    r"last \d+ digits",
    r"transaction of (rs\.?|rupees?|₹)\s*[\d,]+",
    r"on (monday|tuesday|wednesday|thursday|friday|saturday|sunday|\d{1,2}(th|st|nd|rd)?)",
    r"your registered address",
    r"relationship manager",
    r"branch at",
    r"account number \d+",
]

# Low specificity phrases — scammer would say these
LOW_SPECIFICITY_PHRASES = [
    "as per our records", "according to our system", "we have your details",
    "our records show", "your account", "your recent transaction",
    "your registered mobile", "we can see your", "system shows",
    "hamara system dikha raha hai", "hamare record mein"
]


def analyze(transcript: str, claims: Optional[dict] = None) -> dict:
    # Skip if no meaningful transcript (Path B structured input)
    if not transcript or len(transcript.strip()) < 30:
        return {
            "score": 0.0,
            "finding": "skipped_no_transcript",
            "plain_english": "Knowledge profiling requires voice description.",
            "evidence": {},
            "hard_floor": None
        }

    transcript_lower = transcript.lower()
    specificity_score = 0

    # Check high specificity
    high_found = []
    for pattern in HIGH_SPECIFICITY_PATTERNS:
        if re.search(pattern, transcript_lower):
            specificity_score += 1
            high_found.append(pattern)

    # Check low specificity
    low_found = []
    for phrase in LOW_SPECIFICITY_PHRASES:
        if phrase.lower() in transcript_lower:
            specificity_score -= 1
            low_found.append(phrase)

    if specificity_score < -1:
        org = claims.get("org_claimed", "the organization") if claims else "the organization"
        return {
            "score": 0.55,
            "finding": "low_specificity",
            "plain_english": f"Caller claims to represent {org} but demonstrates no specific knowledge about your account. Real {org} employees can cite your account number, last transaction, or branch. This caller cannot.",
            "evidence": {"specificity_score": specificity_score, "vague_phrases_used": low_found},
            "hard_floor": None
        }
    elif specificity_score > 1:
        return {
            "score": 0.15,
            "finding": "high_specificity",
            "plain_english": "Caller demonstrated account-specific knowledge consistent with legitimate access.",
            "evidence": {"specificity_score": specificity_score, "specific_details": high_found},
            "hard_floor": None
        }
    else:
        return {
            "score": 0.25,
            "finding": "neutral_specificity",
            "plain_english": "Insufficient specificity data to assess caller's knowledge.",
            "evidence": {"specificity_score": specificity_score},
            "hard_floor": None
        }
