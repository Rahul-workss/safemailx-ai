"""
Tests for Feature 5: Adaptive Trust Baseline Engine
src/engines/adaptive_trust_engine.py
"""

import os
import sys
import tempfile
import unittest

SRC_DIR = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, SRC_DIR)

from engines.adaptive_trust_engine import (
    init_baseline_db,
    record_trusted_sender,
    get_trust_entry,
    apply_adaptive_trust,
    clear_all_baseline_data,
    list_baseline_summary,
    TRUST_MULTIPLIER,
    PHISHING_FLOOR,
)


def _tmp_db() -> str:
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    init_baseline_db(tmp.name)
    return tmp.name


class TestRecordAndGetTrustedSender(unittest.TestCase):

    def setUp(self):
        self.db = _tmp_db()

    def tearDown(self):
        try: os.unlink(self.db)
        except: pass

    def test_record_creates_entry(self):
        record_trusted_sender("local", "payroll.company.com", db_path=self.db)
        entry = get_trust_entry("local", "payroll.company.com", db_path=self.db)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["trusted_scan_count"], 1)

    def test_record_increments_count(self):
        for _ in range(4):
            record_trusted_sender("local", "payroll.company.com", db_path=self.db)
        entry = get_trust_entry("local", "payroll.company.com", db_path=self.db)
        self.assertEqual(entry["trusted_scan_count"], 4)

    def test_get_nonexistent_returns_none(self):
        entry = get_trust_entry("local", "never-seen-domain.com", db_path=self.db)
        self.assertIsNone(entry)

    def test_scoped_to_user_id(self):
        record_trusted_sender("alice", "safe.com", db_path=self.db)
        entry = get_trust_entry("bob", "safe.com", db_path=self.db)
        self.assertIsNone(entry)

    def test_empty_domain_is_ignored(self):
        record_trusted_sender("local", "", db_path=self.db)
        record_trusted_sender("local", "   ", db_path=self.db)
        # Should not crash or create entries
        entries = list_baseline_summary("local", db_path=self.db)
        self.assertEqual(len(entries), 0)

    def test_domain_normalized_to_lowercase(self):
        record_trusted_sender("local", "PAYROLL.COMPANY.COM", db_path=self.db)
        entry = get_trust_entry("local", "payroll.company.com", db_path=self.db)
        self.assertIsNotNone(entry)


class TestApplyAdaptiveTrust(unittest.TestCase):

    def setUp(self):
        self.db = _tmp_db()

    def tearDown(self):
        try: os.unlink(self.db)
        except: pass

    def _seed_trusted(self, domain: str, count: int, user_id: str = "local"):
        for _ in range(count):
            record_trusted_sender(user_id, domain, db_path=self.db)

    def test_trust_bonus_applied_when_criteria_met(self):
        self._seed_trusted("payroll.company.com", count=3)
        score = 0.40
        adjusted, applied, entry = apply_adaptive_trust(
            final_score=score,
            user_id="local",
            sender_domain="payroll.company.com",
            verdict="suspicious",
            db_path=self.db,
            min_trusted_scans=3,
        )
        self.assertTrue(applied)
        self.assertAlmostEqual(adjusted, round(score * TRUST_MULTIPLIER, 3))

    def test_trust_bonus_not_applied_below_min_scans(self):
        self._seed_trusted("payroll.company.com", count=2)  # one below threshold
        score = 0.40
        adjusted, applied, _ = apply_adaptive_trust(
            final_score=score,
            user_id="local",
            sender_domain="payroll.company.com",
            verdict="suspicious",
            db_path=self.db,
            min_trusted_scans=3,
        )
        self.assertFalse(applied)
        self.assertEqual(adjusted, score)

    def test_trust_bonus_never_applied_above_phishing_floor(self):
        self._seed_trusted("evil.com", count=5)
        score = PHISHING_FLOOR + 0.01   # above floor
        adjusted, applied, _ = apply_adaptive_trust(
            final_score=score,
            user_id="local",
            sender_domain="evil.com",
            verdict="suspicious",
            db_path=self.db,
            min_trusted_scans=1,
        )
        self.assertFalse(applied)
        self.assertEqual(adjusted, score)

    def test_trust_bonus_never_applied_for_phishing_verdict(self):
        self._seed_trusted("evil.com", count=5)
        score = 0.30
        adjusted, applied, _ = apply_adaptive_trust(
            final_score=score,
            user_id="local",
            sender_domain="evil.com",
            verdict="phishing",   # explicitly blocked
            db_path=self.db,
            min_trusted_scans=1,
        )
        self.assertFalse(applied)
        self.assertEqual(adjusted, score)

    def test_unknown_sender_domain_returns_unchanged_score(self):
        score = 0.35
        adjusted, applied, _ = apply_adaptive_trust(
            final_score=score,
            user_id="local",
            sender_domain="never-seen.example.com",
            verdict="suspicious",
            db_path=self.db,
        )
        self.assertFalse(applied)
        self.assertEqual(adjusted, score)

    def test_never_raises(self):
        try:
            apply_adaptive_trust(
                final_score=0.5,
                user_id="local",
                sender_domain="test.com",
                verdict="suspicious",
                db_path="/nonexistent/path/that/does/not/exist.db",
            )
        except Exception as exc:
            self.fail(f"apply_adaptive_trust raised unexpectedly: {exc}")


class TestClearAndList(unittest.TestCase):

    def setUp(self):
        self.db = _tmp_db()

    def tearDown(self):
        try: os.unlink(self.db)
        except: pass

    def test_clear_removes_all_entries_for_user(self):
        for d in ["a.com", "b.com", "c.com"]:
            record_trusted_sender("alice", d, db_path=self.db)
        record_trusted_sender("bob", "z.com", db_path=self.db)

        deleted = clear_all_baseline_data("alice", db_path=self.db)
        self.assertEqual(deleted, 3)

        # Bob's data untouched
        remaining = list_baseline_summary("bob", db_path=self.db)
        self.assertEqual(len(remaining), 1)

    def test_list_returns_correct_schema(self):
        record_trusted_sender("local", "mybank.com", db_path=self.db)
        record_trusted_sender("local", "mybank.com", db_path=self.db)
        entries = list_baseline_summary("local", db_path=self.db)
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertIn("sender_domain", entry)
        self.assertIn("trusted_scan_count", entry)
        self.assertIn("last_seen_at", entry)
        self.assertEqual(entry["trusted_scan_count"], 2)


class TestFeature5Integration(unittest.TestCase):

    def test_adaptive_trust_engine_imports_cleanly(self):
        from engines.adaptive_trust_engine import (
            record_trusted_sender, apply_adaptive_trust, clear_all_baseline_data,
            list_baseline_summary,
        )

    def test_config_flags_importable(self):
        from utils.config import FEATURE_ADAPTIVE_TRUST_ENABLED, ADAPTIVE_TRUST_MIN_SCANS
        self.assertIsInstance(FEATURE_ADAPTIVE_TRUST_ENABLED, bool)
        self.assertIsInstance(ADAPTIVE_TRUST_MIN_SCANS, int)

    def test_scan_service_still_importable(self):
        from server.scan_service import ScanService

    def test_app_still_importable(self):
        try:
            import server.app as _app
        except ImportError as exc:
            self.fail(f"app.py import failed after Feature 5: {exc}")


if __name__ == "__main__":
    unittest.main()
