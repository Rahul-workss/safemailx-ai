"""
Unit tests for Aadhaar Secure QR Decoder and UIDAI RSA-2048 verification.
src/engines/aadhaar_decoder.py
"""

import os
import sys
import unittest

SRC_DIR = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, SRC_DIR)

from engines.aadhaar_decoder import (
    decode_aadhaar_secure_qr,
    _load_uidai_certificates,
    _verify_uidai_signature,
    _decimal_to_bytes,
)


class TestAadhaarDecoder(unittest.TestCase):
    def test_uidai_certificates_loaded(self):
        """Ensure all official UIDAI certificates from src/data/*.cer are loaded."""
        certs = _load_uidai_certificates()
        self.assertGreaterEqual(len(certs), 7, "Should load at least 7 UIDAI certificates")
        for cert in certs:
            self.assertIn("UNIQUE IDENTIFICATION AUTHORITY OF INDIA", cert.subject.rfc4514_string().upper())

    def test_non_numeric_payload(self):
        """Ensure non-numeric payloads are cleanly rejected."""
        result = decode_aadhaar_secure_qr("abc123xyz")
        self.assertFalse(result["success"])
        self.assertIn("Not a numeric", result["error"])

    def test_empty_payload(self):
        """Ensure empty payloads are rejected."""
        result = decode_aadhaar_secure_qr("")
        self.assertFalse(result["success"])

    def test_decimal_to_bytes(self):
        """Ensure large decimal string converts to big-endian bytes correctly."""
        b = _decimal_to_bytes("255")
        self.assertEqual(b, b"\xff")
        b2 = _decimal_to_bytes("65535")
        self.assertEqual(b2, b"\xff\xff")

    def test_signature_tamper_detection(self):
        """Ensure random or tampered signatures fail against UIDAI certificates."""
        fake_data = b"tampered_aadhaar_payload"
        fake_signature = b"\x00" * 256
        res = _verify_uidai_signature(fake_data, fake_signature)
        self.assertFalse(res, "Tampered signature should return False (failed verification)")


if __name__ == "__main__":
    unittest.main()
