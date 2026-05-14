import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from utils.pdf_report import _build_llm_analyst_notes


class PdfLlmNotesTests(unittest.TestCase):
    def test_builds_readable_analyst_notes(self):
        headline, observations = _build_llm_analyst_notes({
            "llm_score": 0.25,
            "llm_confidence": 1.0,
            "llm_intent": "marketing",
            "llm_tactics": ["reward_lure"],
            "urgency_score": 2,
            "legitimacy_score": 1,
            "grammar_score": 0,
            "coherence_score": 1,
        })

        self.assertIn("25% threat", headline)
        self.assertIn("confidence 100%", headline)
        self.assertIn("Intent classification: Marketing.", observations)
        self.assertIn("Reward Lure", observations[1])
        self.assertTrue(any(note.startswith("Reassuring:") for note in observations))


if __name__ == "__main__":
    unittest.main()
