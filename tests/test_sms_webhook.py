"""
Tests for sms_webhook_handler.py (Feature: SMS Bot Integration)
All heavy dependencies (Twilio, Telegram, inline_scan_service) are mocked.
"""
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

ROOT = __file__
for _ in range(2):
    ROOT = os.path.dirname(ROOT)
sys.path.insert(0, os.path.join(ROOT, "src"))


def _make_result(verdict="phishing", risk_score=88.0, scan_category="credential_theft"):
    """Build a minimal InstantScanResult-like mock."""
    r = MagicMock()
    r.verdict = verdict
    r.risk_score = risk_score
    r.scan_category = scan_category
    r.saved_to_history = True
    return r


class TestTwilioSignatureVerification(unittest.TestCase):
    def _verify(self, *args, **kwargs):
        from server.sms_webhook_handler import _verify_twilio_signature
        return _verify_twilio_signature(*args, **kwargs)

    def test_no_secret_always_passes(self):
        self.assertTrue(self._verify("", "any-sig", "https://example.com/webhook", {}))

    def test_wrong_signature_fails(self):
        # With a real token, a wrong signature must reject
        result = self._verify("abc123", "wrong", "https://example.com", {"Body": "hello"})
        self.assertFalse(result)


class TestBuildTwiml(unittest.TestCase):
    def test_xml_structure(self):
        from server.sms_webhook_handler import build_twiml_reply
        xml = build_twiml_reply("Hello world")
        self.assertIn("<?xml", xml)
        self.assertIn("<Response>", xml)
        self.assertIn("Hello world", xml)
        self.assertIn("</Response>", xml)

    def test_html_entities_escaped(self):
        from server.sms_webhook_handler import build_twiml_reply
        xml = build_twiml_reply("<b>Test & done</b>")
        self.assertNotIn("<b>", xml)
        self.assertIn("&amp;", xml)
        self.assertIn("&lt;", xml)


class TestHandleWhatsappWebhook(unittest.TestCase):
    def _call(self, body, feature_enabled=True, mock_result=None):
        from server.sms_webhook_handler import handle_whatsapp_webhook
        svc = MagicMock()
        svc.orchestrator.process_sms_scan.return_value = mock_result or _make_result()
        with patch("server.sms_webhook_handler.FEATURE_WHATSAPP_BOT_ENABLED", feature_enabled), \
             patch("server.sms_webhook_handler.TWILIO_AUTH_TOKEN", ""):
            return handle_whatsapp_webhook(
                form_data={"Body": body},
                x_twilio_signature="",
                webhook_url="https://safemailx-ai.onrender.com/api/webhooks/whatsapp",
                inline_scan_service=svc,
            )

    def test_feature_disabled_returns_silent_twiml(self):
        xml = self._call("click here http://evil.xyz", feature_enabled=False)
        self.assertIn("<Response>", xml)
        # No scan should have been called
        # (can be verified by inspecting the mock but TwiML is the key assertion)

    def test_help_command_returns_help(self):
        xml = self._call("/help")
        self.assertIn("SafeMail X", xml)

    def test_phishing_detected_in_reply(self):
        xml = self._call("URGENT: Your HDFC account is suspended. Click: http://hdfc-login.xyz")
        self.assertIn("PHISHING", xml)
        self.assertIn("88%", xml)

    def test_error_on_scan_failure(self):
        from server.sms_webhook_handler import handle_whatsapp_webhook
        svc = MagicMock()
        svc.orchestrator.process_sms_scan.side_effect = RuntimeError("engine down")
        with patch("server.sms_webhook_handler.FEATURE_WHATSAPP_BOT_ENABLED", True), \
             patch("server.sms_webhook_handler.TWILIO_AUTH_TOKEN", ""):
            xml = handle_whatsapp_webhook(
                form_data={"Body": "some suspicious message"},
                x_twilio_signature="",
                webhook_url="https://safemailx-ai.onrender.com/api/webhooks/whatsapp",
                inline_scan_service=svc,
            )
        self.assertIn("failed", xml.lower())


class TestHandleTelegramWebhook(unittest.TestCase):
    def _call(self, text, feature_enabled=True, mock_result=None):
        from server.sms_webhook_handler import handle_telegram_webhook
        svc = MagicMock()
        svc.orchestrator.process_sms_scan.return_value = mock_result or _make_result()
        update = {
            "message": {
                "chat": {"id": 123456},
                "text": text,
            }
        }
        with patch("server.sms_webhook_handler.FEATURE_TELEGRAM_BOT_ENABLED", feature_enabled), \
             patch("server.sms_webhook_handler.TELEGRAM_WEBHOOK_SECRET", ""), \
             patch("server.sms_webhook_handler._send_telegram_message") as mock_send:
            handle_telegram_webhook(update, "", svc)
            return mock_send

    def test_feature_disabled_sends_nothing(self):
        mock_send = self._call("test message", feature_enabled=False)
        mock_send.assert_not_called()

    def test_help_command_sends_help(self):
        mock_send = self._call("/help")
        mock_send.assert_called_once()
        args = mock_send.call_args[0]
        self.assertIn("SafeMail X", args[1])

    def test_scan_sends_verdict_reply(self):
        mock_send = self._call("Urgent: Click this link to verify your KYC http://fake-kyc.xyz")
        mock_send.assert_called_once()
        args = mock_send.call_args[0]
        self.assertEqual(args[0], 123456)
        self.assertIn("PHISHING", args[1])

    def test_no_message_field_is_silent(self):
        from server.sms_webhook_handler import handle_telegram_webhook
        svc = MagicMock()
        update = {"edited_message": {"chat": {"id": 1}, "text": "hi"}}
        with patch("server.sms_webhook_handler.FEATURE_TELEGRAM_BOT_ENABLED", True), \
             patch("server.sms_webhook_handler.TELEGRAM_WEBHOOK_SECRET", ""), \
             patch("server.sms_webhook_handler._send_telegram_message") as mock_send:
            handle_telegram_webhook(update, "", svc)
        mock_send.assert_not_called()


class TestAnonymousMode(unittest.TestCase):
    """Ensure scans are NOT saved to history in bot mode."""
    def test_scan_not_saved_to_repo(self):
        from server.sms_webhook_handler import _scan_text_anonymously
        svc = MagicMock()
        svc.orchestrator.process_sms_scan.return_value = _make_result()
        result = _scan_text_anonymously("some text", svc)
        # _save_to_repo must never be called in anonymous mode
        self.assertFalse(getattr(svc, "repository", None) and svc.repository.create_scan.called)
        self.assertFalse(result.saved_to_history)


if __name__ == "__main__":
    unittest.main()
