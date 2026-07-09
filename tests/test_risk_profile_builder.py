import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from engines.attachment_analyzer import analyze_attachments
from engines.risk_profile_builder import build_domain_risk_profile, build_risk_profile


class RiskProfileBuilderTests(unittest.TestCase):
    def test_detects_bec_bank_change_request(self):
        profile = build_risk_profile(
            subject="Updated vendor bank details",
            sender="vendor-payments@example.net",
            body="Please use our new bank details for this urgent invoice. Do not call, the CFO already approved the wire transfer.",
            source_type="business_request",
            hybrid_result={"final_label": "legitimate", "final_score": 0.1},
        )

        self.assertEqual(profile["primary_threat"], "bec_payment_fraud")
        self.assertIn("money_transfer", profile["requested_actions"])

    def test_detects_crypto_investment_lure(self):
        profile = build_risk_profile(
            subject="Private crypto trading group",
            body="Join our investment group and send USDT to this wallet for guaranteed daily profit.",
            source_type="social_chat",
            hybrid_result={"final_label": "legitimate", "final_score": 0.1},
        )

        self.assertEqual(profile["primary_threat"], "investment_crypto_scam")
        self.assertIn("crypto_transfer", profile["requested_actions"])

    def test_detects_tech_support_remote_access_scam(self):
        profile = build_risk_profile(
            subject="Virus detected",
            body="Your computer is infected. Call Microsoft support now and install AnyDesk for remote access.",
            source_type="screenshot",
            hybrid_result={"final_label": "legitimate", "final_score": 0.1},
        )

        self.assertEqual(profile["primary_threat"], "tech_support_scam")
        self.assertIn("app_install", profile["requested_actions"])

    def test_detects_romance_money_request(self):
        profile = build_risk_profile(
            subject="Need help",
            body="My love, I have an emergency at the hospital. Please send money or gift card today.",
            source_type="social_chat",
            hybrid_result={"final_label": "legitimate", "final_score": 0.1},
        )

        self.assertEqual(profile["primary_threat"], "romance_social_scam")

    def test_detects_otp_takeover_request(self):
        profile = build_risk_profile(
            subject="Account verification",
            body="Reply with your OTP verification code so we can confirm your account.",
            source_type="sms",
            hybrid_result={"final_label": "legitimate", "final_score": 0.1},
        )

        self.assertEqual(profile["primary_threat"], "identity_takeover")
        self.assertIn("share_otp", profile["requested_actions"])

    def test_detects_secret_leak(self):
        profile = build_risk_profile(
            subject="Debug log",
            body="OPENAI_API_KEY=sk-testvalue1234567890abcdef and password: Sup3rSecret!",
            source_type="document",
            hybrid_result={"final_label": "legitimate", "final_score": 0.1},
        )

        self.assertEqual(profile["primary_threat"], "data_leak")
        self.assertIn("openai_api_key", profile["signals"])

    def test_detects_high_risk_attachment(self):
        attachments = analyze_attachments([
            {"filename": "invoice.pdf", "bytes": b"MZ\x90\x00fake-executable"}
        ])
        profile = build_risk_profile(
            subject="Invoice",
            body="Please open the attached invoice.",
            source_type="document",
            hybrid_result={"final_label": "legitimate", "final_score": 0.1},
            attachment_result=attachments,
        )

        self.assertEqual(profile["primary_threat"], "malware_delivery")
        self.assertIn("file_open", profile["requested_actions"])

    def test_domain_profile_uses_passive_signals(self):
        profile = build_domain_risk_profile({
            "domain": "example.test",
            "risk_score": 0.72,
            "signals": ["dmarc_missing", "hsts_missing"],
        })

        self.assertEqual(profile["primary_threat"], "domain_exposure")
        self.assertIn("domain_exposure", profile["threat_categories"])


if __name__ == "__main__":
    unittest.main()
