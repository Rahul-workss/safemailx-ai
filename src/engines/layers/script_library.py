"""
Layer 5 — Scam Script Library Matcher
Matches the call description against documented Indian scam scripts using keyword overlap.
"""
import json
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("SCRIPT_LIBRARY")

_SCRIPT_LIBRARY: Optional[list] = None
_LIBRARY_PATH = Path(__file__).resolve().parents[2] / "data" / "scam_scripts" / "india_scam_library.json"


def _load_library() -> list:
    global _SCRIPT_LIBRARY
    if _SCRIPT_LIBRARY is not None:
        return _SCRIPT_LIBRARY
    try:
        with open(_LIBRARY_PATH, "r", encoding="utf-8") as f:
            _SCRIPT_LIBRARY = json.load(f)
        logger.info("[SCRIPT_LIB] Loaded %d scam script entries.", len(_SCRIPT_LIBRARY))
    except Exception as e:
        logger.warning("[SCRIPT_LIB] Failed to load library: %s", e)
        _SCRIPT_LIBRARY = []
    return _SCRIPT_LIBRARY


def _jaccard_similarity(text: str, phrases: list[str]) -> float:
    """Compute Jaccard similarity between text word-set and phrase word-set."""
    text_words = set(text.lower().split())
    phrase_words = set()
    for phrase in phrases:
        phrase_words.update(phrase.lower().split())

    # Remove very common words (stop words)
    stop_words = {"the", "a", "an", "is", "are", "you", "your", "they", "them",
                  "will", "has", "have", "been", "be", "to", "of", "in", "for",
                  "on", "at", "by", "from", "or", "and", "not", "hai", "ka",
                  "ki", "ke", "se", "ko", "mein", "karo", "aur", "mat"}
    text_words -= stop_words
    phrase_words -= stop_words

    if not phrase_words:
        return 0.0

    intersection = text_words & phrase_words
    union = text_words | phrase_words
    return len(intersection) / len(union) if union else 0.0


def analyze(transcript: str, claims: Optional[dict] = None) -> dict:
    library = _load_library()
    if not library:
        return {
            "score": 0.0,
            "finding": "library_unavailable",
            "plain_english": "Scam script library not available.",
            "evidence": {},
            "hard_floor": None
        }

    # Include org_claimed in the text to match against
    full_text = transcript
    if claims and claims.get("org_claimed"):
        full_text = claims["org_claimed"] + " " + transcript
    if claims and claims.get("actions_requested"):
        full_text += " " + " ".join(claims.get("actions_requested", []))
    if claims and claims.get("warning_phrases"):
        full_text += " " + " ".join(claims.get("warning_phrases", []))

    matches = []
    for entry in library:
        similarity = _jaccard_similarity(full_text, entry.get("key_phrases", []))
        if similarity > 0.15:  # Low threshold — show partial matches too
            matches.append({"entry": entry, "similarity": similarity})

    if not matches:
        return {
            "score": 0.0,
            "finding": "no_script_match",
            "plain_english": "No known Indian scam script pattern detected.",
            "evidence": {"top_matches": []},
            "hard_floor": None
        }

    matches.sort(key=lambda x: x["similarity"], reverse=True)
    top = matches[0]
    top_entry = top["entry"]
    top_sim = top["similarity"]
    cases = top_entry.get("reported_cases", "many")
    name = top_entry.get("display_name", "Unknown Scam")
    callback = top_entry.get("official_callback", "1930")

    if top_sim > 0.45:
        logger.info("[SCRIPT_LIB] Strong match: %s (%.2f)", name, top_sim)
        return {
            "score": min(0.93, 0.5 + top_sim),
            "finding": "scam_script_match",
            "plain_english": f"Matches the '{name}' pattern ({cases} reported). Report at cybercrime.gov.in or call {callback}.",
            "evidence": {"matched_script": name, "similarity": round(top_sim, 3), "reported_cases": cases},
            "hard_floor": 0.93 if top_sim > 0.65 else None
        }
    else:
        return {
            "score": top_sim * 1.5,  # Scale up partial match
            "finding": "partial_script_match",
            "plain_english": f"Partial match to '{name}' scam pattern. Exercise caution.",
            "evidence": {"matched_script": name, "similarity": round(top_sim, 3)},
            "hard_floor": None
        }
