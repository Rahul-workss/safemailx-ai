"""
Tests for bot_reply_formatter.py (Feature: SMS Bot Integration)
"""
import os
import sys
import unittest

ROOT = __file__
for _ in range(2):
    ROOT = os.path.dirname(ROOT)
sys.path.insert(0, os.path.join(ROOT, "src"))


class _FakeResult:
    """Minimal stand-in for InstantScanResult to avoid heavy imports."""
    def __init__(self, verdict, risk_score, scan_category=None):
        self.verdict = verdict
        self.risk_score = risk_score
        self.scan_category = scan_category


class TestWhatsAppReply(unittest.TestCase):
    def setUp(self):
        from server.bot_reply_formatter import format_whatsapp_reply
        self.fmt = format_whatsapp_reply

    def test_phishing_contains_verdict(self):
        r = _FakeResult("phishing", 92, "credential_theft")
        reply = self.fmt(r)
        self.assertIn("PHISHING", reply)
        self.assertIn("92%", reply)
        self.assertIn("Credential theft", reply)

    def test_phishing_second_line_warns(self):
        r = _FakeResult("phishing", 88)
        reply = self.fmt(r)
        lines = reply.strip().split("\n")
        self.assertEqual(len(lines), 2)
        self.assertIn("NOT", lines[1])

    def test_suspicious_second_line_caution(self):
        r = _FakeResult("suspicious", 55)
        reply = self.fmt(r)
        lines = reply.strip().split("\n")
        self.assertEqual(len(lines), 2)
        self.assertIn("caution", lines[1].lower())

    def test_legitimate_second_line_reassurance(self):
        r = _FakeResult("legitimate", 8, "otp")
        reply = self.fmt(r)
        lines = reply.strip().split("\n")
        self.assertEqual(len(lines), 2)
        self.assertIn("safe", lines[1].lower())

    def test_risk_rounded_to_integer(self):
        r = _FakeResult("phishing", 87.6, "financial_fraud")
        reply = self.fmt(r)
        self.assertIn("88%", reply)

    def test_unknown_category_humanised(self):
        r = _FakeResult("suspicious", 60, "some_new_category")
        reply = self.fmt(r)
        self.assertIn("Some New Category", reply)

    def test_no_category_fallback(self):
        r = _FakeResult("legitimate", 5, None)
        reply = self.fmt(r)
        self.assertIn("Unknown", reply)


class TestTelegramReply(unittest.TestCase):
    def setUp(self):
        from server.bot_reply_formatter import format_telegram_reply
        self.fmt = format_telegram_reply

    def test_html_bold_tags_present(self):
        r = _FakeResult("phishing", 90, "credential_theft")
        reply = self.fmt(r)
        self.assertIn("<b>PHISHING</b>", reply)

    def test_two_lines(self):
        r = _FakeResult("suspicious", 55)
        reply = self.fmt(r)
        self.assertEqual(len(reply.strip().split("\n")), 2)


class TestHelpMessages(unittest.TestCase):
    def test_whatsapp_help_not_empty(self):
        from server.bot_reply_formatter import format_help_message_whatsapp
        msg = format_help_message_whatsapp()
        self.assertGreater(len(msg), 20)
        self.assertIn("SafeMail X", msg)

    def test_telegram_help_html_tags(self):
        from server.bot_reply_formatter import format_help_message_telegram
        msg = format_help_message_telegram()
        self.assertIn("<b>", msg)

    def test_error_reply_not_empty(self):
        from server.bot_reply_formatter import format_error_reply
        msg = format_error_reply()
        self.assertGreater(len(msg), 10)


if __name__ == "__main__":
    unittest.main()
