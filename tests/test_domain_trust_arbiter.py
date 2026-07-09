import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from engines.domain_trust_arbiter import check_domain_trust


class DomainTrustArbiterTests(unittest.TestCase):
    def test_platinum_trust_tier(self):
        result = check_domain_trust(
            sender_domain="github.com",
            sender_full="GitHub <noreply@github.com>",
            spf_pass=True,
            dkim_pass=True,
            dmarc_pass=True,
            received_headers=[],
            url_details=[],
            security_headers={},
        )
        self.assertEqual(result.trust_tier, "PLATINUM")
        self.assertGreater(result.trust_score, 60)

    def test_unauthenticated_suspicious(self):
        result = check_domain_trust(
            sender_domain="unknown.xyz",
            sender_full="Billing <billing@unknown.xyz>",
            spf_pass=False,
            dkim_pass=False,
            dmarc_pass=False,
            received_headers=[],
            url_details=[],
            security_headers={},
        )
        self.assertEqual(result.trust_tier, "SUSPICIOUS")

    def test_no_reply_authenticated(self):
        result = check_domain_trust(
            sender_domain="custom-saas.io",
            sender_full="Support <no-reply@custom-saas.io>",
            spf_pass=True,
            dkim_pass=True,
            dmarc_pass=False,
            received_headers=[],
            url_details=[],
            security_headers={},
        )
        self.assertIn(result.trust_tier, ["SILVER", "GOLD"])

    def test_esp_routing(self):
        result = check_domain_trust(
            sender_domain="marketing-brand.com",
            sender_full="Marketing <hello@marketing-brand.com>",
            spf_pass=True,
            dkim_pass=False,
            dmarc_pass=False,
            received_headers=[{"by": "sendgrid.net"}],
            url_details=[],
            security_headers={},
        )
        self.assertIn(result.trust_tier, ["BRONZE", "SILVER"])


if __name__ == "__main__":
    unittest.main()
