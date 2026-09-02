"""
Layer 4 — Isolation Signal Detector
Highest-confidence individual scam signal.
No legitimate organization instructs callers to not speak with others or not hang up.
"""
import logging
from typing import Optional

logger = logging.getLogger("ISOLATION_DETECTOR")

# Keyword banks — 3 languages
ISOLATION_KEYWORDS_EN = [
    "don't tell anyone", "do not tell anyone", "dont tell anyone",
    "do not hang up", "don't hang up", "dont hang up",
    "stay on the line", "stay on line", "remain on the line",
    "do not contact anyone", "don't contact anyone",
    "keep this confidential", "keep this between us", "strictly confidential",
    "do not discuss with family", "don't discuss with family",
    "do not put me on hold", "don't put me on hold",
    "do not share this information", "don't share this",
    "between us only", "you cannot speak to anyone",
    "do not call anyone else", "don't call anyone else",
    "legal confidentiality prevents", "legal obligation not to",
    "no need to call the bank", "no need to verify",
    "calling back will delay your case", "do not verify independently"
]

ISOLATION_KEYWORDS_HI = [
    "kisi ko mat batana", "kisi ko mat bolo", "kisi ko nahi batana",
    "line mat katna", "phone mat rakhna", "call mat karo",
    "family ko mat batana", "ghar walon ko mat batana",
    "confidential hai", "secret rakho",
    "abhi mat jaiye", "line pe raho", "hold mat karo",
    "kisi ko involve mat karo", "kisi se mat bolo",
    "bank ko mat call karo", "alag se verify mat karo"
]

ISOLATION_KEYWORDS_HINGLISH = [
    "please hold the line", "kisi ko mat bolo", "dont disconnect",
    "yeh confidential hai", "family se mat bolna", "line pe raho",
    "kisi ko share mat karo", "abhi call mat karo bank ko",
    "verify karne ki zaroorat nahi"
]

ALL_ISOLATION_KEYWORDS = (
    ISOLATION_KEYWORDS_EN + ISOLATION_KEYWORDS_HI + ISOLATION_KEYWORDS_HINGLISH
)


def analyze(transcript: str, claims: Optional[dict] = None) -> dict:
    """
    Scan transcript for isolation commands.
    Returns a LayerResult dict.
    """
    transcript_lower = transcript.lower()
    found_phrases = []

    for keyword in ALL_ISOLATION_KEYWORDS:
        if keyword.lower() in transcript_lower:
            found_phrases.append(keyword)

    if found_phrases:
        primary = found_phrases[0]
        logger.info("[ISOLATION] Found %d isolation phrase(s): %s", len(found_phrases), found_phrases[:3])
        return {
            "score": 0.92,
            "finding": "isolation_command_detected",
            "plain_english": (
                f'ISOLATION COMMAND: Caller used phrase "{primary}". '
                "No legitimate organization — bank, government, or otherwise — "
                "ever instructs a caller not to speak with family or not to hang up. "
                "This is a definitive scam indicator."
            ),
            "evidence": {
                "phrases_found": found_phrases,
                "count": len(found_phrases),
                "hard_floor_triggered": True
            },
            "hard_floor": 0.92
        }
    else:
        return {
            "score": 0.0,
            "finding": "no_isolation_commands",
            "plain_english": "No isolation commands detected.",
            "evidence": {"phrases_found": [], "count": 0},
            "hard_floor": None
        }
