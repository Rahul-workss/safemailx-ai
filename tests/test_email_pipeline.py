import unittest
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from server.repository import ScanRepository
from server.scan_service import ScanService
from server.worker import process_scan_job
from engines.llm_analyzer import run_llm_analysis
from engines.hybrid_engine import hybrid_detect


class TestEmailPipeline(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.repo = ScanRepository()
        cls.service = ScanService(cls.repo)

    def test_01_llm_analyzer_direct(self):
        """Test Qwen3 direct analysis on an email payload."""
        result = run_llm_analysis(
            channel="email",
            subject="Urgent: Security Alert from PayPal",
            sender="service-security@paypal-verification-check.com",
            email_text="Dear member, unauthorized access detected on your account. Please log in immediately at http://paypal-verify-login.xyz/auth to confirm your identity or your account will be permanently banned.",
        )
        self.assertIsNotNone(result, "LLM analysis returned None (LM Studio offline or unreachable)")
        self.assertTrue(result.get("llm_available"))
        self.assertGreaterEqual(result.get("llm_score", 0), 0.70, "Phishing email should score high threat on Qwen3")
        self.assertIn("intent", result)
        self.assertIn("reasoning", result)
        print("\n[TEST 1 PASSED] Qwen3 Direct LLM Score:", result.get("llm_score"), "Intent:", result.get("intent"))

    def test_02_hybrid_engine_email(self):
        """Test hybrid engine combining rules, ML, and Qwen3."""
        result = hybrid_detect(
            subject="Invoice #84920 Past Due",
            email_text="Kindly review the attached invoice. Immediate payment required: http://bit.ly/pay-overdue-now",
            sender="billing@invoice-payment-portal.net",
            source_type="email"
        )
        self.assertIn("final_score", result)
        self.assertIn("final_label", result)
        self.assertIn(result["final_label"], ["phishing", "suspicious"])
        print("\n[TEST 2 PASSED] Hybrid Engine Result:", result["final_label"], "Score:", result["final_score"])

    def test_03_scan_service_end_to_end(self):
        """Test full scan service running an email scan."""
        scan = self.service.run_manual_text_scan(
            subject="Google Security: New Sign-in Detected",
            sender="no-reply@accounts.google.com",
            body="A new device signed into your Google Account (rahul@gmail.com) on Windows. If this was you, you do not need to do anything. If this was not you, review your security settings.",
            scan_mode="balanced",
            source_type="email",
            user_id="local"
        )
        self.assertIsNotNone(scan)
        self.assertIn(scan["final_label"], ["legitimate", "safe", "suspicious"])
        self.assertTrue(scan.get("llm_used"), "Qwen3 should be recorded as used in scan results")
        print("\n[TEST 3 PASSED] Legitimate Email Scan:", scan["final_label"], "Score:", scan["final_score"])

    def test_04_process_scan_job_queued_execution(self):
        """Test process_scan_job completing an asynchronous job in-process."""
        scan_id = self.repo.create_queued_scan(
            subject="Test Queued Verification",
            sender="security@amazon-alert-support.com",
            user_id="local",
            evidence={"status": "queued", "source": "manual_text"}
        )
        job = {
            "type": "manual_text",
            "scan_id": scan_id,
            "user_id": "local",
            "subject": "Test Queued Verification",
            "sender": "security@amazon-alert-support.com",
            "body": "Your Amazon account has been locked. Click http://amazon-unlock-account.top/verify now.",
            "scan_mode": "balanced"
        }
        processed = process_scan_job(job, service=self.service, repository=self.repo)
        self.assertIsNotNone(processed)
        updated_scan = self.repo.get_scan(scan_id)
        self.assertNotEqual(updated_scan["final_label"], "queued", "Job should have transitioned out of queued")
        self.assertEqual(updated_scan["final_label"], "phishing")
        print("\n[TEST 4 PASSED] Queued Job Successfully Executed to Verdict:", updated_scan["final_label"])


if __name__ == "__main__":
    unittest.main()
