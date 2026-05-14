import contextlib
import io
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from forwarding_bot import print_evidence_dump


class EvidenceDumpTests(unittest.TestCase):
    def test_prints_full_text_without_truncation_marker(self):
        long_text = "Line " + ("full evidence " * 200)
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            print_evidence_dump("Fwd: demo", long_text, ["OCR Report Text"], long_text)

        rendered = output.getvalue()
        self.assertIn("EXTRACTED TEXT", rendered)
        self.assertIn("Subject: Fwd: demo", rendered)
        self.assertIn("OCR Report Text", rendered)
        self.assertIn("full evidence", rendered)
        self.assertNotIn("characters truncated", rendered)
        self.assertNotIn("Final Text Sent To LLM:", rendered)

    def test_hides_tracking_links_and_image_placeholders(self):
        text = """---------- Forwarded message ---------
From: TryHackMe <donotreply@tryhackme.com>

[image: TryHackMe Logo]
<https://e.customeriomail.com/tracking/link>
Quick check-in
PROMO-C03E30-857846
"""
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            print_evidence_dump("Fwd: demo", text, [], text)

        rendered = output.getvalue()
        self.assertIn("Quick check-in", rendered)
        self.assertIn("PROMO-C03E30-857846", rendered)
        self.assertNotIn("customeriomail", rendered)
        self.assertNotIn("[image:", rendered)


if __name__ == "__main__":
    unittest.main()
