import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from engines.hybrid_engine import hybrid_detect
from engines.url_analyzer import analyze_urls


def _llm_result(score: float, reason: str, intent: str = "marketing"):
    return {
        "llm_score": score,
        "confidence": 0.95,
        "urgency_score": 3,
        "legitimacy_score": 2,
        "grammar_score": 0,
        "coherence_score": 1,
        "tactics": ["reward_lure"] if score >= 0.7 else [],
        "intent": intent,
        "reasoning": reason,
    }


class PromoCtaDetectionTests(unittest.TestCase):
    @patch("engines.url_analyzer.WHOIS_AVAILABLE", False)
    @patch("engines.url_analyzer.requests.get")
    def test_url_analyzer_flags_resolved_domain_mismatch(self, mock_get):
        mock_response = Mock()
        mock_response.url = "https://promo.evil.test/final"
        mock_response.close = Mock()
        mock_get.return_value = mock_response

        url_details = [{
            "raw_url": "https://openart.ai/offer",
            "normalized_url": "https://openart.ai/offer",
            "domain": "openart.ai",
            "is_ip": False,
            "is_short": False,
            "flags": [],
            "safebrowsing_hit": False,
            "anchor_text": "Claim Offer Now",
            "href": "https://openart.ai/offer",
            "href_domain": "openart.ai",
            "is_cta": True,
            "link_source": "raw_href",
        }]

        flags = analyze_urls(url_details, sender_domain="openart.ai")

        self.assertIn("cta_link_present", flags)
        self.assertIn("cta_resolved_domain_mismatch:promo.evil.test", flags)
        self.assertEqual(url_details[0]["resolved_domain"], "promo.evil.test")

    @patch("engines.hybrid_engine.run_ai_model", return_value=(0.12, []))
    @patch("engines.hybrid_engine.run_llm_analysis")
    @patch("engines.url_analyzer.WHOIS_AVAILABLE", False)
    @patch("engines.url_analyzer.requests.get")
    def test_legitimate_promo_with_matching_cta_stays_legitimate(self, mock_get, mock_llm, _mock_ai):
        mock_response = Mock()
        mock_response.url = "https://offers.openart.ai/birthday"
        mock_response.close = Mock()
        mock_get.return_value = mock_response
        mock_llm.return_value = _llm_result(0.12, "This appears to be a normal branded anniversary promotion.")

        url_details = [{
            "raw_url": "https://offers.openart.ai/birthday",
            "normalized_url": "https://offers.openart.ai/birthday",
            "domain": "offers.openart.ai",
            "is_ip": False,
            "is_short": False,
            "flags": [],
            "safebrowsing_hit": False,
            "anchor_text": "Claim Offer Now",
            "href": "https://offers.openart.ai/birthday",
            "href_domain": "offers.openart.ai",
            "is_cta": True,
            "link_source": "raw_href",
        }]
        url_flags = analyze_urls(url_details, sender_domain="openart.ai")

        result = hybrid_detect(
            "OpenArt Birthday Offer",
            "OpenArt turns 3. Claim Offer Now for 50% off.",
            sender="OpenArt <offers@openart.ai>",
            url_flags=url_flags,
            url_details=url_details,
            source_type="email",
            link_evidence_mode="raw_href",
        )

        self.assertEqual(result["final_label"], "legitimate")

    @patch("engines.hybrid_engine.run_ai_model", return_value=(0.15, []))
    @patch("engines.hybrid_engine.run_llm_analysis")
    @patch("engines.url_analyzer.WHOIS_AVAILABLE", False)
    @patch("engines.url_analyzer.requests.get")
    def test_promo_phishing_with_offbrand_cta_scores_as_phishing(self, mock_get, mock_llm, _mock_ai):
        mock_response = Mock()
        mock_response.url = "https://promo.evil.test/claim"
        mock_response.close = Mock()
        mock_get.return_value = mock_response
        mock_llm.return_value = _llm_result(0.91, "The promo CTA resolves to an off-brand destination and is likely deceptive.", intent="credential_theft")

        url_details = [{
            "raw_url": "https://openart.ai/offer",
            "normalized_url": "https://openart.ai/offer",
            "domain": "openart.ai",
            "is_ip": False,
            "is_short": False,
            "flags": [],
            "safebrowsing_hit": False,
            "anchor_text": "Claim Offer Now",
            "href": "https://openart.ai/offer",
            "href_domain": "openart.ai",
            "is_cta": True,
            "link_source": "raw_href",
        }]
        url_flags = analyze_urls(url_details, sender_domain="openart.ai")

        result = hybrid_detect(
            "OpenArt Birthday Offer",
            "OpenArt turns 3. Claim Offer Now for 50% off until May 15.",
            sender="OpenArt <offers@openart.ai>",
            url_flags=url_flags,
            url_details=url_details,
            source_type="email",
            link_evidence_mode="raw_href",
        )

        self.assertEqual(result["final_label"], "phishing")

    @patch("engines.hybrid_engine.run_ai_model", return_value=(0.10, []))
    @patch("engines.hybrid_engine.run_llm_analysis")
    def test_trusted_auth_cannot_neutralize_offbrand_cta(self, mock_llm, _mock_ai):
        mock_llm.return_value = _llm_result(0.82, "The sender looks trusted but the CTA target is mismatched and risky.")

        url_details = [{
            "raw_url": "https://promo.evil.test/claim",
            "normalized_url": "https://promo.evil.test/claim",
            "domain": "promo.evil.test",
            "is_ip": False,
            "is_short": False,
            "flags": ["cta_sender_domain_mismatch:promo.evil.test"],
            "safebrowsing_hit": False,
            "anchor_text": "Claim Offer Now",
            "href": "https://promo.evil.test/claim",
            "href_domain": "promo.evil.test",
            "is_cta": True,
            "link_source": "raw_href",
        }]

        result = hybrid_detect(
            "OpenArt Birthday Offer",
            "Claim Offer Now and unlock 50% off.",
            sender="OpenArt <offers@openart.ai>",
            url_flags=["cta_sender_domain_mismatch:promo.evil.test"],
            security_headers={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            auth_context="original_headers",
            url_details=url_details,
            source_type="email",
            link_evidence_mode="raw_href",
        )

        self.assertNotEqual(result["final_label"], "legitimate")
        self.assertIsNone(result["trust_arbitration"]["tier"])

    @patch("engines.hybrid_engine.run_ai_model", return_value=(0.05, []))
    @patch("engines.hybrid_engine.run_llm_analysis")
    def test_screenshot_cta_without_visible_url_is_not_legitimate(self, mock_llm, _mock_ai):
        mock_llm.return_value = _llm_result(0.08, "This looks like polished marketing but the screenshot does not expose the real destination.")

        result = hybrid_detect(
            "OpenArt Birthday Offer",
            "OpenArt turns 3. Claim Offer Now. 50% off until May 15.",
            sender="OpenArt <offers@openart.ai>",
            url_flags=[],
            url_details=[],
            source_type="screenshot",
            link_evidence_mode="none_visible",
        )

        self.assertEqual(result["final_label"], "suspicious")


if __name__ == "__main__":
    unittest.main()
