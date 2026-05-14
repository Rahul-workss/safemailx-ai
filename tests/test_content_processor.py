import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from utils.content_processor import clean_extracted_text


class ContentProcessorTests(unittest.TestCase):
    def test_removes_invisible_email_padding(self):
        raw = "A quick nudge.\n\u2007\u034f \u2007\u034f \u2007\u034f\n\nUse SAL1 today."

        cleaned = clean_extracted_text(raw)

        self.assertEqual(cleaned, "A quick nudge.\n\nUse SAL1 today.")
        self.assertNotIn("\u034f", cleaned)
        self.assertNotIn("\u2007", cleaned)

    def test_preserves_forwarded_email_signal(self):
        raw = """
        ---------- Forwarded message ---------
        From: TryHackMe <donotreply@tryhackme.com>
        Date: Thu, 12 Feb 2026, 6:30 pm
        Subject: Your SAL1 discount is still waiting

        A quick nudge. Your 20% off SAL 1 code is still ready to use.
        \u2007\u034f \u2007\u034f \u2007\u034f \u2007\u034f
        Cold start complete. Time to heat
        """

        cleaned = clean_extracted_text(raw)

        self.assertIn("---------- Forwarded message ---------", cleaned)
        self.assertIn("From: TryHackMe <donotreply@tryhackme.com>", cleaned)
        self.assertIn("Your 20% off SAL 1 code is still ready to use.", cleaned)
        self.assertIn("Cold start complete. Time to heat", cleaned)
        self.assertNotIn("\u034f", cleaned)


if __name__ == "__main__":
    unittest.main()
