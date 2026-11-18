"""Test live email scanning pipeline with a realistic suspicious email."""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

import json
from utils.outlook_parser import parse_mime_message
from server.scan_service import ScanService
from server.repository import ScanRepository

RAW_PHISHING_EMAIL = b"""From: "Microsoft Security Team" <alert@microsoft-account-security-update.com>
To: user@safemailx.local
Subject: URGENT: Action Required - Your Microsoft Account Has Been Suspended
Date: Wed, 18 Nov 2026 12:00:00 +0000
Message-ID: <20261118120000.alert@microsoft-account-security-update.com>
Authentication-Results: spf=fail (sender IP is 198.51.100.42) dkim=fail header.d=microsoft-account-security-update.com dmarc=fail
Received-SPF: fail (domain of alert@microsoft-account-security-update.com does not designate 198.51.100.42 as permitted sender)
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: 7bit

<!DOCTYPE html>
<html>
<body>
    <h2>Security Alert: Unusual Sign-in Activity Detected</h2>
    <p>Dear Customer,</p>
    <p>We detected an unauthorized sign-in attempt to your Microsoft Account from Moscow, Russia (IP: 185.220.101.5).</p>
    <p>To prevent immediate account termination, you must verify your identity within <b>2 hours</b>.</p>
    <p>
        <a href="http://login.microsoft.com.account-verify-login.ru/auth/login.php?user=target">
            Click here to verify your Microsoft Account immediately
        </a>
    </p>
    <p>If you fail to act, your email access and OneDrive data will be permanently wiped.</p>
    <p>Regards,<br>Microsoft Account Security Team</p>
</body>
</html>
"""

def test_pipeline():
    print("=" * 65)
    print("TESTING OUTLOOK LIVE EMAIL SCANNING PIPELINE")
    print("=" * 65)

    # 1. Parse raw MIME
    print("\n[STEP 1] Parsing raw MIME email via outlook_parser...")
    parsed = parse_mime_message(RAW_PHISHING_EMAIL)
    print(f"  Subject: {parsed['subject']}")
    print(f"  Sender:  {parsed['sender']}")
    print(f"  Links:   {parsed['links']}")
    print(f"  SPF:     {parsed['security_headers'].get('spf')}")
    print(f"  DMARC:   {parsed['security_headers'].get('dmarc')}")

    # 2. Run through ScanService (SafeMail X Detection Engine)
    print("\n[STEP 2] Running through SafeMail X Scan Engine...")
    repo = ScanRepository()
    service = ScanService(repo)

    result = service.run_manual_text_scan(
        subject=parsed["subject"],
        sender=parsed["sender"],
        body=parsed["body"],
        scan_mode="strict",
        link_details_override=parsed["links"],
        source_type="email",
        security_headers_override=parsed["security_headers"],
        auth_context_override="original_headers",
        original_sender_override=parsed["sender"],
    )

    print("\n" + "=" * 65)
    print("SCAN RESULT SUMMARY:")
    print("=" * 65)
    print(f"  Scan ID:       {result['id']}")
    print(f"  Final Label:   {result['final_label'].upper()}")
    print(f"  Final Score:   {result['final_score'] * 100:.1f} / 100")
    print(f"  LLM Used:      {result['llm_used']}")
    print(f"  Degraded:      {result['degraded']}")

    verdict = result['final_label']
    verdict_key = {
        "legitimate": "safe",
        "suspicious": "suspicious",
        "phishing": "phishing",
    }.get(verdict, "failed")
    print(f"\n[STEP 3] Category to be applied on Outlook: 'SafeMail X {verdict_key.capitalize()}'")
    
    assert verdict in ("phishing", "suspicious"), f"Expected phishing/suspicious, got {verdict}"
    print("\n--> PIPELINE TEST PASSED: Successfully detected malicious indicators and assigned correct verdict!")

if __name__ == "__main__":
    test_pipeline()
