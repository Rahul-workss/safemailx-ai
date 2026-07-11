"""
Tests for Feature 7: Voice/Vishing Detection
src/engines/vishing_analyzer.py

All tests mock openai-whisper so they run in the CI environment
without requiring torch or the actual model files.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

SRC_DIR = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, SRC_DIR)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _mock_whisper_result(text: str, lang: str = "en", duration_s: float = 10.0):
    """Build a fake whisper transcribe() return value."""
    return {
        "text": text,
        "language": lang,
        "segments": [{"start": 0.0, "end": duration_s, "text": text}],
    }


def _reset_module_cache():
    """Reset the lazy-load globals in vishing_analyzer between tests."""
    import engines.vishing_analyzer as mod
    mod._WHISPER_MODEL = None
    mod._WHISPER_LOAD_FAILED = False


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestTranscribeAudioWithMockedWhisper(unittest.TestCase):

    def setUp(self):
        _reset_module_cache()

    def _run_with_mock(self, audio_bytes, whisper_result):
        """Patch whisper.load_model and run transcribe_audio."""
        mock_model = MagicMock()
        mock_model.transcribe.return_value = whisper_result

        mock_whisper_module = MagicMock()
        mock_whisper_module.load_model.return_value = mock_model

        with patch.dict("sys.modules", {"whisper": mock_whisper_module}):
            # Re-import inside context so the lazy loader sees the mock
            _reset_module_cache()
            from engines.vishing_analyzer import transcribe_audio
            return transcribe_audio(audio_bytes, filename="test.wav", model_size="tiny")

    def test_successful_transcription(self):
        fake_audio = b"\x00" * 1024
        result = self._run_with_mock(
            fake_audio,
            _mock_whisper_result("Your account has been compromised. Call us immediately.", duration_s=15.0)
        )
        self.assertTrue(result["success"])
        self.assertIn("compromised", result["transcript"])
        self.assertEqual(result["language"], "en")
        self.assertAlmostEqual(result["audio_duration_s"], 15.0)
        self.assertEqual(result["model"], "tiny")
        self.assertEqual(result["reason"], "")

    def test_empty_audio_bytes_returns_failure(self):
        from engines.vishing_analyzer import transcribe_audio
        result = transcribe_audio(b"", filename="empty.wav")
        self.assertFalse(result["success"])
        self.assertEqual(result["transcript"], "")
        self.assertIn("Empty", result["reason"])

    def test_whisper_not_installed_returns_failure(self):
        """If whisper is not importable, returns graceful failure."""
        _reset_module_cache()
        import engines.vishing_analyzer as mod

        # Simulate ImportError on whisper import inside the loader
        original_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

        import builtins
        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "whisper":
                raise ImportError("No module named 'whisper'")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            _reset_module_cache()
            result = mod._get_whisper_model("tiny")

        self.assertIsNone(result)

    def test_return_schema_always_complete(self):
        """All required keys are present regardless of outcome."""
        from engines.vishing_analyzer import transcribe_audio
        result = transcribe_audio(b"", filename="x.wav")
        required_keys = {"success", "transcript", "language", "audio_duration_s", "model", "reason"}
        for key in required_keys:
            self.assertIn(key, result, f"Key '{key}' missing from result schema")

    def test_never_raises_on_model_crash(self):
        """Even if model.transcribe() raises, transcribe_audio must not propagate."""
        _reset_module_cache()

        mock_model = MagicMock()
        mock_model.transcribe.side_effect = RuntimeError("GPU OOM")
        mock_whisper_module = MagicMock()
        mock_whisper_module.load_model.return_value = mock_model

        with patch.dict("sys.modules", {"whisper": mock_whisper_module}):
            _reset_module_cache()
            from engines.vishing_analyzer import transcribe_audio
            try:
                result = transcribe_audio(b"\x00" * 512, filename="crash.wav")
                self.assertFalse(result["success"])
                self.assertIn("OOM", result["reason"])
            except Exception as exc:
                self.fail(f"transcribe_audio propagated exception: {exc}")


class TestAnalyzeAudioForVishing(unittest.TestCase):

    def setUp(self):
        _reset_module_cache()

    def test_successful_analysis_returns_text_for_analysis(self):
        mock_model = MagicMock()
        mock_model.transcribe.return_value = _mock_whisper_result(
            "Verify your bank account now or it will be suspended.", duration_s=8.0
        )
        mock_whisper_module = MagicMock()
        mock_whisper_module.load_model.return_value = mock_model

        with patch.dict("sys.modules", {"whisper": mock_whisper_module}):
            _reset_module_cache()
            from engines.vishing_analyzer import analyze_audio_for_vishing
            result = analyze_audio_for_vishing(b"\x00" * 512, filename="vishing.wav")

        self.assertTrue(result["success"])
        self.assertIn("text_for_analysis", result)
        self.assertIn("Audio transcript", result["text_for_analysis"])
        self.assertIn("Verify your bank account", result["text_for_analysis"])

    def test_failure_returns_empty_text_for_analysis(self):
        from engines.vishing_analyzer import analyze_audio_for_vishing
        result = analyze_audio_for_vishing(b"", filename="empty.wav")
        self.assertFalse(result["success"])
        self.assertEqual(result["text_for_analysis"], "")

    def test_schema_includes_text_for_analysis_key(self):
        from engines.vishing_analyzer import analyze_audio_for_vishing
        result = analyze_audio_for_vishing(b"", filename="x.wav")
        self.assertIn("text_for_analysis", result)


class TestVishingAttachmentRouting(unittest.TestCase):
    """Test that the attachment_analyzer routes audio files to vishing detection."""

    def setUp(self):
        _reset_module_cache()

    def test_audio_attachment_triggers_vishing_branch(self):
        """With FEATURE_VISHING_DETECTION_ENABLED=True and mocked whisper,
        an audio attachment should produce a finding with vishing_analysis."""
        from engines import attachment_analyzer as att_mod

        # Patch the feature flag and the analyzer function
        fake_vishing = {
            "success": True,
            "transcript": "Call us or your account will be closed.",
            "text_for_analysis": "[Audio transcript]\n\nCall us or your account will be closed.",
            "language": "en",
            "audio_duration_s": 5.0,
            "model": "tiny",
            "reason": "",
        }

        with patch.object(att_mod, "FEATURE_VISHING_DETECTION_ENABLED", True), \
             patch.object(att_mod, "_VISHING_AVAILABLE", True), \
             patch.object(att_mod, "analyze_audio_for_vishing", return_value=fake_vishing), \
             patch.object(att_mod, "WHISPER_MODEL_SIZE", "tiny"):

            result = att_mod.analyze_attachments([
                {"filename": "message.mp3", "bytes": b"\x00" * 512}
            ])

        # Should have a finding for the audio
        self.assertIsNotNone(result.get("attachment_findings"))
        findings = result["attachment_findings"]
        audio_findings = [f for f in findings if f.get("file_type") == "audio"]
        self.assertEqual(len(audio_findings), 1)
        self.assertIn("vishing_analysis", audio_findings[0])
        self.assertIn("transcript", audio_findings[0])

    def test_non_audio_attachment_not_processed_by_vishing(self):
        """A PDF attachment should not trigger vishing analysis."""
        from engines import attachment_analyzer as att_mod
        from unittest.mock import patch as upatch

        mock_analyze = MagicMock()

        with upatch.object(att_mod, "FEATURE_VISHING_DETECTION_ENABLED", True), \
             upatch.object(att_mod, "_VISHING_AVAILABLE", True), \
             upatch.object(att_mod, "analyze_audio_for_vishing", mock_analyze):

            # Use a high-risk extension so it exits early (before vishing check)
            att_mod.analyze_attachments([
                {"filename": "invoice.exe", "bytes": b"\x00" * 128}
            ])

        mock_analyze.assert_not_called()


class TestFeature7Integration(unittest.TestCase):

    def test_vishing_analyzer_imports_cleanly(self):
        from engines.vishing_analyzer import transcribe_audio, analyze_audio_for_vishing

    def test_config_flags_importable(self):
        from utils.config import FEATURE_VISHING_DETECTION_ENABLED, WHISPER_MODEL_SIZE
        self.assertIsInstance(FEATURE_VISHING_DETECTION_ENABLED, bool)
        self.assertIsInstance(WHISPER_MODEL_SIZE, str)
        self.assertEqual(WHISPER_MODEL_SIZE, "tiny")  # default must be tiny

    def test_attachment_analyzer_still_importable(self):
        from engines.attachment_analyzer import analyze_attachments

    def test_feature_disabled_by_default(self):
        """FEATURE_VISHING_DETECTION_ENABLED must default to False (memory safety)."""
        import os
        # Only assert if env var not overridden
        if "FEATURE_VISHING_DETECTION_ENABLED" not in os.environ:
            from utils.config import FEATURE_VISHING_DETECTION_ENABLED
            self.assertFalse(FEATURE_VISHING_DETECTION_ENABLED)


if __name__ == "__main__":
    unittest.main()
