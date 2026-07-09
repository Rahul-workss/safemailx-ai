import json
import logging
import os
import unittest
from pathlib import Path

from engines.instant_scan_engine import SmartVetoOrchestrator

# Disable noisy logging during tests
logging.getLogger("INSTANT_SCAN_ENGINE").setLevel(logging.CRITICAL)


class TestCorpusRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = SmartVetoOrchestrator()
        cls.corpus_dir = Path(__file__).parent / "corpus"

    def run_corpus_tests(self, channel: str):
        channel_dir = self.corpus_dir / channel
        if not channel_dir.exists():
            self.skipTest(f"Corpus directory not found: {channel_dir}")
        
        test_files = list(channel_dir.glob("*.txt"))
        if not test_files:
            self.skipTest(f"No test files found in {channel_dir}")

        for test_file in test_files:
            expected_file = test_file.with_name(test_file.name.replace(".txt", ".expected.json"))
            if not expected_file.exists():
                self.fail(f"Missing expected result file: {expected_file}")

            with open(test_file, "rb") as f:
                content = f.read()

            with open(expected_file, "r", encoding="utf-8") as f:
                expected = json.load(f)

            with self.subTest(file=test_file.name):
                if channel == "sms":
                    text_content = content.decode("utf-8", errors="replace")
                    result = self.engine.process_sms_scan(text_content)
                elif channel == "url":
                    text_content = content.decode("utf-8", errors="replace").strip()
                    result = self.engine.process_url_scan(text_content)
                elif channel == "file":
                    result = self.engine.process_file_scan(test_file.name, "text/plain", content)
                else:
                    self.fail(f"Unknown channel: {channel}")

                self.assertEqual(
                    result.verdict,
                    expected["expected_verdict"],
                    f"Verdict mismatch for {test_file.name}. Expected {expected['expected_verdict']}, got {result.verdict}. Signals: {[s.name for s in result.top_signals]}",
                )
                if expected.get("expected_category") is not None:
                    self.assertEqual(
                        result.scan_category,
                        expected["expected_category"],
                        f"Category mismatch for {test_file.name}. Expected {expected['expected_category']}, got {result.scan_category}.",
                    )

    def test_sms_corpus(self):
        self.run_corpus_tests("sms")

    def test_url_corpus(self):
        self.run_corpus_tests("url")

    def test_file_corpus(self):
        self.run_corpus_tests("file")


if __name__ == "__main__":
    unittest.main()
