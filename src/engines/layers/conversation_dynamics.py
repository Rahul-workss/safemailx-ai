"""
Layer 7 — Conversation Dynamics Analyser
Requires diarized transcript. Returns 0.0 (skipped) for MVP.
Will be enabled in Phase 2 when speaker diarization is available.
"""
import logging
from typing import Optional

logger = logging.getLogger("CONV_DYNAMICS")


def analyze(transcript: str, claims: Optional[dict] = None) -> dict:
    """
    MVP: This layer is skipped (returns 0.0).
    Requires Pyannote speaker diarization to separate SPEAKER_00 and SPEAKER_01.
    Will be implemented in Phase 2 with audio file upload analysis.
    """
    return {
        "score": 0.0,
        "finding": "skipped_no_diarization",
        "plain_english": "Conversation dynamics analysis requires audio file upload (coming soon).",
        "evidence": {"skipped": True, "reason": "diarization_not_available"},
        "hard_floor": None
    }
