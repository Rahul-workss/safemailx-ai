# ============================================================
# SafeMail X — Voice/Vishing Analyzer
# Feature 7: Transcribe audio attachments and route through
#             the standard phishing detection pipeline
# Controlled by: FEATURE_VISHING_DETECTION_ENABLED
# ============================================================
#
# HOW IT WORKS:
#   1. Worker receives an audio attachment (wav/mp3/ogg/m4a/flac).
#   2. The audio bytes are decoded by openai-whisper (model=tiny).
#   3. The transcribed text is passed through the normal
#      hybrid_detect() pipeline as if it were email body text.
#   4. The result is annotated with:
#        source_type = "audio_transcription"
#        vishing_analysis.model  = whisper model used
#        vishing_analysis.transcript = full transcript
#        vishing_analysis.audio_duration_s = duration in seconds
#
# SAFE FALLBACK:
#   If whisper is not installed, model load fails, or the file is
#   unreadable, the function returns:
#       {"success": False, "reason": "<error>", "transcript": ""}
#   The caller treats this as a no-op — no verdict is produced from
#   a failed transcription.
#
# MEMORY BUDGET:
#   Whisper "tiny" model = ~75MB parameters. This is the only model
#   size supported given the 512MB Koyeb/Render free-tier constraint.
#   Model size is configurable via WHISPER_MODEL_SIZE (default "tiny").
#   Any other value is accepted but may OOM on constrained environments.
#
# PRIVACY:
#   Audio bytes are processed in-process — never uploaded to a third
#   party. The transcript is stored with the scan evidence (same
#   retention policy as email body text).
# ============================================================

import io
import logging
import os
import tempfile
from typing import Optional

logger = logging.getLogger("VISHING_ANALYZER")

# Lazy module-level handle — loaded at first call, not at import time
_WHISPER_MODEL = None
_WHISPER_LOAD_FAILED = False


def _get_whisper_model(model_size: str = "tiny"):
    """
    Load the Whisper model lazily (once per process).
    Returns None if whisper is not installed.
    """
    global _WHISPER_MODEL, _WHISPER_LOAD_FAILED
    if _WHISPER_LOAD_FAILED:
        return None
    if _WHISPER_MODEL is not None:
        return _WHISPER_MODEL
    try:
        import whisper
        logger.info("[VISHING] Loading Whisper model '%s'…", model_size)
        _WHISPER_MODEL = whisper.load_model(model_size)
        logger.info("[VISHING] Whisper model '%s' loaded successfully.", model_size)
        return _WHISPER_MODEL
    except ImportError:
        logger.warning(
            "[VISHING] openai-whisper is not installed. "
            "Install it with: pip install openai-whisper"
        )
        _WHISPER_LOAD_FAILED = True
        return None
    except Exception as exc:
        logger.warning("[VISHING] Whisper model load failed: %s", exc)
        _WHISPER_LOAD_FAILED = True
        return None


def transcribe_audio(
    audio_bytes: bytes,
    filename: str = "audio.wav",
    model_size: str = "tiny",
    language: Optional[str] = None,
) -> dict:
    """
    Transcribe audio bytes using Whisper.

    Parameters:
      audio_bytes  — raw bytes of the audio file
      filename     — original filename (used to infer format extension)
      model_size   — Whisper model size; must be "tiny" on constrained envs
      language     — BCP-47 language code hint (None = auto-detect)

    Returns:
      {
        "success":          bool,
        "transcript":       str,   # empty on failure
        "language":         str,   # detected language code
        "audio_duration_s": float, # detected duration in seconds (0 on failure)
        "model":            str,   # model size used
        "reason":           str,   # error message on failure, "" on success
      }
    """
    empty = {
        "success": False,
        "transcript": "",
        "language": "",
        "audio_duration_s": 0.0,
        "model": model_size,
        "reason": "",
    }

    if not audio_bytes:
        empty["reason"] = "Empty audio bytes"
        return empty

    model = _get_whisper_model(model_size)
    if model is None:
        empty["reason"] = "Whisper model unavailable (not installed or load failed)"
        return empty

    # Write to a named temp file — whisper requires a file path
    ext = os.path.splitext(filename)[-1].lower() or ".wav"
    try:
        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp_file:
            tmp_path = tmp_file.name
            tmp_file.write(audio_bytes)

        try:
            import whisper
            decode_opts = {}
            if language:
                decode_opts["language"] = language

            result = model.transcribe(tmp_path, **decode_opts)
            transcript = (result.get("text") or "").strip()
            detected_lang = result.get("language", "")
            # Duration from segments if available
            segs = result.get("segments") or []
            duration = segs[-1]["end"] if segs else 0.0

            logger.info(
                "[VISHING] Transcription complete. Language=%s Duration=%.1fs Chars=%d",
                detected_lang, duration, len(transcript)
            )
            return {
                "success": True,
                "transcript": transcript,
                "language": detected_lang,
                "audio_duration_s": round(duration, 2),
                "model": model_size,
                "reason": "",
            }
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    except Exception as exc:
        logger.warning("[VISHING] Transcription failed: %s", exc)
        result = dict(empty)
        result["reason"] = str(exc)
        return result


def analyze_audio_for_vishing(
    audio_bytes: bytes,
    filename: str = "audio.wav",
    model_size: str = "tiny",
) -> dict:
    """
    High-level entry point: transcribe audio and return the transcript
    together with a recommended text to pass into the hybrid pipeline.

    Returns:
      {
        "success":           bool,
        "transcript":        str,
        "text_for_analysis": str,   # formatted for hybrid_detect() body
        "language":          str,
        "audio_duration_s":  float,
        "model":             str,
        "reason":            str,
      }
    """
    transcription = transcribe_audio(audio_bytes, filename=filename, model_size=model_size)

    if not transcription["success"]:
        return {**transcription, "text_for_analysis": ""}

    transcript = transcription["transcript"]
    # Wrap with context header so the intent classifier and rules have context
    text_for_analysis = (
        f"[Audio transcript — vishing detection]\n\n{transcript}"
    )
    return {**transcription, "text_for_analysis": text_for_analysis}
