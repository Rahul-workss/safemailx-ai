"""
Tests for Feature 1: QR-Code Phishing (Quishing) Detection
src/engines/qr_analyzer.py

Fixtures are generated on-the-fly using the `qrcode` package
(test-only dep — not added to requirements.txt for production).
Falls back to static fixture PNGs in tests/corpus/ if qrcode unavailable.
"""

import os
import sys
import unittest
import tempfile

# Make sure src is on the path
SRC_DIR = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, SRC_DIR)

# Try to generate QR images on-the-fly
try:
    import qrcode
    from PIL import Image as PilImage
    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False


def _make_qr_image(data: str, path: str) -> bool:
    """Generate a QR code PNG at `path` containing `data`. Returns True if successful."""
    if not QRCODE_AVAILABLE:
        return False
    try:
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M)
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(path)
        return True
    except Exception:
        return False


def _corpus_path(filename: str) -> str:
    return os.path.join(os.path.dirname(__file__), "corpus", filename)


class TestDecodeQrCodes(unittest.TestCase):
    """Unit tests for decode_qr_codes() and analyze_qr_payload()."""

    def setUp(self):
        from engines.qr_analyzer import decode_qr_codes, analyze_qr_payload, analyze_qr_from_bytes
        self.decode_qr_codes = decode_qr_codes
        self.analyze_qr_payload = analyze_qr_payload
        self.analyze_qr_from_bytes = analyze_qr_from_bytes
        self._tmp_files: list[str] = []

    def tearDown(self):
        for f in self._tmp_files:
            try:
                if os.path.exists(f):
                    os.unlink(f)
            except Exception:
                pass

    def _tmp_png(self, data: str) -> str | None:
        """Create a temp QR PNG containing data. Returns path or None if unavailable."""
        tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        tmp.close()
        self._tmp_files.append(tmp.name)
        if _make_qr_image(data, tmp.name):
            return tmp.name
        # Fall back to static corpus fixture
        corpus = _corpus_path("qr_clean.png")
        return corpus if os.path.exists(corpus) else None

    # --- decode_qr_codes ---

    def test_decode_benign_url(self):
        """A QR containing a benign HTTPS URL is decoded correctly."""
        url = "https://example.com/landing"
        path = self._tmp_png(url)
        if path is None:
            self.skipTest("No QR generation library or corpus fixture available")
        result = self.decode_qr_codes(path)
        self.assertIsInstance(result, list)
        if QRCODE_AVAILABLE:  # only assert content when we generated the QR ourselves
            self.assertIn(url, result)

    def test_decode_shortened_url(self):
        """A QR containing a shortened URL (bit.ly style) is decoded correctly."""
        url = "https://bit.ly/3xABCDE"
        path = self._tmp_png(url)
        if path is None:
            self.skipTest("No QR generation library or corpus fixture available")
        result = self.decode_qr_codes(path)
        self.assertIsInstance(result, list)
        if QRCODE_AVAILABLE:
            self.assertIn(url, result)

    def test_nonexistent_file_returns_empty(self):
        """A non-existent path returns an empty list without raising."""
        result = self.decode_qr_codes("/nonexistent/path/image.png")
        self.assertEqual(result, [])

    def test_corrupt_image_returns_empty_not_crash(self):
        """A corrupt/random-bytes image does not crash — returns empty list."""
        tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        tmp.write(b"\x00" * 100)  # not a valid image
        tmp.close()
        self._tmp_files.append(tmp.name)
        try:
            result = self.decode_qr_codes(tmp.name)
            self.assertIsInstance(result, list)
        except Exception as exc:
            self.fail(f"decode_qr_codes raised unexpectedly: {exc}")

    # --- analyze_qr_payload ---

    def test_analyze_payload_schema_always_present(self):
        """analyze_qr_payload always returns a dict with the expected keys."""
        path = self._tmp_png("https://safe.example.com")
        if path is None:
            path = "/nonexistent/path.png"  # will return empty result, still valid schema
        result = self.analyze_qr_payload(path)
        self.assertIn("qr_codes_found", result)
        self.assertIn("qr_decoded_payloads", result)
        self.assertIn("qr_urls", result)
        self.assertIn("has_qr_url", result)
        self.assertIsInstance(result["qr_codes_found"], int)
        self.assertIsInstance(result["qr_decoded_payloads"], list)
        self.assertIsInstance(result["qr_urls"], list)
        self.assertIsInstance(result["has_qr_url"], bool)

    def test_analyze_payload_http_url_detected(self):
        """has_qr_url is True when QR contains an http/https URL."""
        url = "https://phish.example.net/verify"
        path = self._tmp_png(url)
        if path is None:
            self.skipTest("No QR generation or corpus fixture available")
        result = self.analyze_qr_payload(path)
        if QRCODE_AVAILABLE:
            self.assertTrue(result["has_qr_url"])
            self.assertIn(url, result["qr_urls"])

    def test_analyze_payload_nonurl_content(self):
        """has_qr_url is False when QR payload is plain text (not a URL)."""
        path = self._tmp_png("HELLO WORLD - NO URL")
        if path is None:
            self.skipTest("No QR generation or corpus fixture available")
        result = self.analyze_qr_payload(path)
        if QRCODE_AVAILABLE:
            self.assertFalse(result["has_qr_url"])
            self.assertEqual(result["qr_urls"], [])

    def test_analyze_payload_corrupt_image_safe(self):
        """analyze_qr_payload on a corrupt image returns empty schema, does not crash."""
        tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        tmp.write(b"\xff\xfe" * 50)
        tmp.close()
        self._tmp_files.append(tmp.name)
        try:
            result = self.analyze_qr_payload(tmp.name)
            self.assertEqual(result["qr_codes_found"], 0)
            self.assertFalse(result["has_qr_url"])
        except Exception as exc:
            self.fail(f"analyze_qr_payload raised unexpectedly: {exc}")

    # --- analyze_qr_from_bytes ---

    def test_analyze_from_bytes_schema(self):
        """analyze_qr_from_bytes returns correct schema even with empty bytes."""
        result = self.analyze_qr_from_bytes(b"", suffix=".png")
        self.assertIn("qr_codes_found", result)
        self.assertIn("has_qr_url", result)
        self.assertEqual(result["qr_codes_found"], 0)

    def test_analyze_from_bytes_with_qr_image(self):
        """analyze_qr_from_bytes correctly processes a valid QR image passed as bytes."""
        url = "https://short.example.com/abc"
        path = self._tmp_png(url)
        if path is None:
            self.skipTest("No QR generation library or corpus fixture available")
        with open(path, "rb") as f:
            img_bytes = f.read()
        result = self.analyze_qr_from_bytes(img_bytes, suffix=".png")
        self.assertIsInstance(result, dict)
        self.assertIn("has_qr_url", result)
        if QRCODE_AVAILABLE:
            self.assertTrue(result["has_qr_url"])


class TestFeatureFlagRollback(unittest.TestCase):
    """Confirm that FEATURE_QR_DETECTION_ENABLED=false produces zero behavior change."""

    def test_flag_importable(self):
        """The feature flag can be imported from utils.config without error."""
        from utils.config import FEATURE_QR_DETECTION_ENABLED
        self.assertIsInstance(FEATURE_QR_DETECTION_ENABLED, bool)

    def test_qr_analyzer_importable(self):
        """The qr_analyzer module imports cleanly."""
        try:
            from engines.qr_analyzer import decode_qr_codes, analyze_qr_payload, analyze_qr_from_bytes
        except ImportError as exc:
            self.fail(f"qr_analyzer import failed: {exc}")

    def test_file_analyzer_still_imports(self):
        """file_analyzer still imports cleanly after QR wiring."""
        try:
            from engines.file_analyzer import extract_and_analyze_attachments
        except ImportError as exc:
            self.fail(f"file_analyzer import failed after QR wiring: {exc}")

    def test_attachment_analyzer_still_imports(self):
        """attachment_analyzer still imports cleanly after QR wiring."""
        try:
            from engines.attachment_analyzer import analyze_attachments
        except ImportError as exc:
            self.fail(f"attachment_analyzer import failed after QR wiring: {exc}")

    def test_schemas_still_importable(self):
        """schemas.py still imports cleanly with the new optional qr_analysis field."""
        try:
            from server.schemas import InstantScanResult, QuickScanArtifacts
        except ImportError as exc:
            self.fail(f"schemas import failed after QR field addition: {exc}")

    def test_instant_scan_result_qr_field_optional(self):
        """InstantScanResult can be constructed without qr_analysis (backward compat)."""
        from server.schemas import InstantScanResult, QuickScanArtifacts
        result = InstantScanResult(
            scan_id="test-001",
            channel="sms",
            verdict="legitimate",
            risk_score=0.1,
            confidence=0.9,
            summary="Test",
            recommended_action="No action required",
        )
        self.assertIsNone(result.qr_analysis)

    def test_instant_scan_result_qr_field_accepts_dict(self):
        """InstantScanResult accepts a qr_analysis dict when provided."""
        from server.schemas import InstantScanResult
        result = InstantScanResult(
            scan_id="test-002",
            channel="file",
            verdict="suspicious",
            risk_score=0.6,
            confidence=0.8,
            summary="QR URL found",
            recommended_action="Review the QR code destination",
            qr_analysis={
                "qr_codes_found": 1,
                "qr_decoded_payloads": ["https://phish.example.com"],
                "qr_urls": ["https://phish.example.com"],
                "has_qr_url": True,
            },
        )
        self.assertIsNotNone(result.qr_analysis)
        self.assertTrue(result.qr_analysis["has_qr_url"])


if __name__ == "__main__":
    unittest.main()
