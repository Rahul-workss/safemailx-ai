"""
Tests for Feature 4: Campaign Correlation Engine
src/engines/campaign_correlator.py

Tests:
  - compute_campaign_fingerprint is deterministic and short
  - store_fingerprint persists correctly to DB
  - query_matching_fingerprints returns correct window matches
  - analyze_campaign_correlation detects campaigns after N+ matches
  - analyze_campaign_correlation does NOT flag below threshold
  - analyze_campaign_correlation never raises on errors
"""

import os
import sys
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone, timedelta

SRC_DIR = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, SRC_DIR)

from engines.campaign_correlator import (
    compute_campaign_fingerprint,
    store_fingerprint,
    query_matching_fingerprints,
    analyze_campaign_correlation,
    DEFAULT_CAMPAIGN_MIN_MATCHES,
    DEFAULT_CAMPAIGN_WINDOW_HOURS,
)


def _make_test_db() -> str:
    """Create a temp SQLite DB with the scan_fingerprints schema."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    conn = sqlite3.connect(tmp.name)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_fingerprints (
            scan_id       TEXT NOT NULL,
            user_id       TEXT NOT NULL DEFAULT 'local',
            fingerprint   TEXT NOT NULL,
            sender_domain TEXT NOT NULL DEFAULT '',
            intent        TEXT NOT NULL DEFAULT 'unknown',
            created_at    TEXT NOT NULL,
            PRIMARY KEY (scan_id)
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_sf_user_fp "
        "ON scan_fingerprints (user_id, fingerprint, created_at)"
    )
    conn.commit()
    conn.close()
    return tmp.name


def _get_conn(db_path: str):
    """Return a sqlite3 connection with row_factory for easy row access."""
    conn = sqlite3.connect(db_path)
    return conn


class TestComputeCampaignFingerprint(unittest.TestCase):

    def test_deterministic(self):
        fp1 = compute_campaign_fingerprint("evil.com", ["credential_theft"], "phishing")
        fp2 = compute_campaign_fingerprint("evil.com", ["credential_theft"], "phishing")
        self.assertEqual(fp1, fp2)

    def test_12_hex_chars(self):
        fp = compute_campaign_fingerprint("evil.com", [], "unknown")
        self.assertEqual(len(fp), 12)
        self.assertRegex(fp, r"^[0-9a-f]+$")

    def test_different_domains_different_fingerprints(self):
        fp1 = compute_campaign_fingerprint("evil.com", ["phishing"], "credential_theft")
        fp2 = compute_campaign_fingerprint("good.com", ["phishing"], "credential_theft")
        self.assertNotEqual(fp1, fp2)

    def test_tactics_order_invariant(self):
        """Tactic list order should not affect fingerprint."""
        fp1 = compute_campaign_fingerprint("evil.com", ["a", "b", "c"], "phishing")
        fp2 = compute_campaign_fingerprint("evil.com", ["c", "a", "b"], "phishing")
        self.assertEqual(fp1, fp2)

    def test_empty_tactics_still_works(self):
        fp = compute_campaign_fingerprint("evil.com", [], "unknown")
        self.assertIsInstance(fp, str)
        self.assertEqual(len(fp), 12)

    def test_case_insensitive_domain(self):
        fp1 = compute_campaign_fingerprint("EVIL.COM", [], "unknown")
        fp2 = compute_campaign_fingerprint("evil.com", [], "unknown")
        self.assertEqual(fp1, fp2)


class TestStoreFingerprintAndQuery(unittest.TestCase):

    def setUp(self):
        self.db_path = _make_test_db()

    def tearDown(self):
        try:
            os.unlink(self.db_path)
        except Exception:
            pass

    def test_store_and_retrieve(self):
        conn = _get_conn(self.db_path)
        fp = compute_campaign_fingerprint("evil.com", ["phishing"], "credential_theft")
        store_fingerprint(conn, "scan-001", "local", fp, "evil.com", "credential_theft")
        conn.commit()
        matches = query_matching_fingerprints(conn, "local", fp, "scan-999", window_hours=48)
        conn.close()
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["scan_id"], "scan-001")

    def test_query_excludes_current_scan(self):
        conn = _get_conn(self.db_path)
        fp = compute_campaign_fingerprint("evil.com", [], "unknown")
        store_fingerprint(conn, "scan-001", "local", fp, "evil.com", "unknown")
        conn.commit()
        # Query excluding "scan-001" — should return 0
        matches = query_matching_fingerprints(conn, "local", fp, "scan-001", window_hours=48)
        conn.close()
        self.assertEqual(len(matches), 0)

    def test_query_respects_window(self):
        """Scans older than the window should not be returned."""
        conn = _get_conn(self.db_path)
        fp = compute_campaign_fingerprint("evil.com", [], "unknown")
        old_time = (datetime.now(timezone.utc) - timedelta(hours=100)).isoformat()
        conn.execute(
            "INSERT INTO scan_fingerprints VALUES (?, ?, ?, ?, ?, ?)",
            ("old-scan", "local", fp, "evil.com", "unknown", old_time),
        )
        conn.commit()
        matches = query_matching_fingerprints(conn, "local", fp, "current-scan", window_hours=48)
        conn.close()
        # old-scan is outside 48h window — should not appear
        self.assertEqual(len(matches), 0)

    def test_query_scoped_to_user_id(self):
        """A match from another user_id should never appear in results."""
        conn = _get_conn(self.db_path)
        fp = compute_campaign_fingerprint("evil.com", [], "unknown")
        store_fingerprint(conn, "scan-A", "user-alice", fp, "evil.com", "unknown")
        conn.commit()
        matches = query_matching_fingerprints(conn, "user-bob", fp, "scan-B", window_hours=48)
        conn.close()
        self.assertEqual(len(matches), 0)


class TestAnalyzeCampaignCorrelation(unittest.TestCase):

    def setUp(self):
        self.db_path = _make_test_db()

    def tearDown(self):
        try:
            os.unlink(self.db_path)
        except Exception:
            pass

    def _run_n_scans(self, n: int, domain="evil.com", tactics=None, intent="credential_theft"):
        """Run N dummy scans to build up fingerprint history."""
        import uuid
        conn = _get_conn(self.db_path)
        for i in range(n):
            scan_id = f"scan-{i:04d}"
            result = analyze_campaign_correlation(
                db_conn=conn,
                scan_id=scan_id,
                user_id="local",
                sender_domain=domain,
                tactics=tactics or ["credential_theft"],
                intent=intent,
                window_hours=48,
                min_matches=DEFAULT_CAMPAIGN_MIN_MATCHES,
            )
        conn.close()
        return result

    def test_not_detected_below_threshold(self):
        """No campaign should be detected below the min_matches threshold."""
        # Run threshold-1 scans, then check the current scan
        n = DEFAULT_CAMPAIGN_MIN_MATCHES - 1
        conn = _get_conn(self.db_path)
        # Pre-populate with n-1 scans
        for i in range(n - 1):
            fp = compute_campaign_fingerprint("evil.com", ["phishing"], "credential_theft")
            store_fingerprint(conn, f"pre-{i}", "local", fp, "evil.com", "credential_theft")
        conn.commit()
        result = analyze_campaign_correlation(
            db_conn=conn,
            scan_id="current-scan",
            user_id="local",
            sender_domain="evil.com",
            tactics=["phishing"],
            intent="credential_theft",
            window_hours=48,
            min_matches=DEFAULT_CAMPAIGN_MIN_MATCHES,
        )
        conn.close()
        self.assertFalse(result["campaign_detected"])

    def test_detected_at_or_above_threshold(self):
        """Campaign should be detected when min_matches are present."""
        conn = _get_conn(self.db_path)
        # Pre-populate with exactly min_matches scans
        for i in range(DEFAULT_CAMPAIGN_MIN_MATCHES):
            fp = compute_campaign_fingerprint("evil.com", ["phishing"], "credential_theft")
            store_fingerprint(conn, f"pre-{i}", "local", fp, "evil.com", "credential_theft")
        conn.commit()
        result = analyze_campaign_correlation(
            db_conn=conn,
            scan_id="current-scan",
            user_id="local",
            sender_domain="evil.com",
            tactics=["phishing"],
            intent="credential_theft",
            window_hours=48,
            min_matches=DEFAULT_CAMPAIGN_MIN_MATCHES,
        )
        conn.close()
        self.assertTrue(result["campaign_detected"])
        self.assertEqual(result["matching_scan_count"], DEFAULT_CAMPAIGN_MIN_MATCHES)
        self.assertGreater(result["campaign_confidence"], 0.0)

    def test_schema_always_present(self):
        """Result schema always has all required keys."""
        conn = _get_conn(self.db_path)
        result = analyze_campaign_correlation(
            db_conn=conn, scan_id="test", user_id="local",
            sender_domain="safe.com", tactics=[], intent="unknown",
        )
        conn.close()
        for key in ["campaign_detected", "fingerprint", "matching_scan_count",
                    "matching_scan_ids", "campaign_confidence", "window_hours"]:
            self.assertIn(key, result)

    def test_never_raises(self):
        """analyze_campaign_correlation must not raise even with a closed connection."""
        import sqlite3
        bad_conn = sqlite3.connect(":memory:")
        bad_conn.close()
        try:
            result = analyze_campaign_correlation(
                db_conn=bad_conn, scan_id="x", user_id="local",
                sender_domain="evil.com", tactics=[], intent="unknown",
            )
            self.assertFalse(result["campaign_detected"])
        except Exception as exc:
            self.fail(f"analyze_campaign_correlation raised unexpectedly: {exc}")


class TestFeature4Integration(unittest.TestCase):

    def test_campaign_correlator_importable(self):
        from engines.campaign_correlator import (
            compute_campaign_fingerprint, analyze_campaign_correlation
        )

    def test_config_flags_importable(self):
        from utils.config import (
            FEATURE_CAMPAIGN_CORRELATION_ENABLED,
            CAMPAIGN_CORRELATION_WINDOW_HOURS,
            CAMPAIGN_CORRELATION_MIN_MATCHES,
        )
        self.assertIsInstance(FEATURE_CAMPAIGN_CORRELATION_ENABLED, bool)
        self.assertIsInstance(CAMPAIGN_CORRELATION_WINDOW_HOURS, int)
        self.assertIsInstance(CAMPAIGN_CORRELATION_MIN_MATCHES, int)

    def test_scan_service_still_importable(self):
        try:
            from server.scan_service import ScanService
        except ImportError as exc:
            self.fail(f"scan_service import failed after Feature 4 wiring: {exc}")


if __name__ == "__main__":
    unittest.main()
