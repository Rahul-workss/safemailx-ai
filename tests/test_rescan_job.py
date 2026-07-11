"""
Tests for Feature 6: Second-Look Rescan Job
src/server/rescan_job.py
"""

import json
import os
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

SRC_DIR = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, SRC_DIR)

from server.rescan_job import (
    _get_recent_suspicious_scans,
    _already_rescanned,
    _record_rescan_event,
    run_rescan_pass,
)


def _make_mock_repo(scans: list, db_path: str):
    """
    Build a minimal mock ScanRepository that returns given scans.
    DB has the rescan_events table.
    """
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS rescan_events (
            scan_id       TEXT NOT NULL PRIMARY KEY,
            old_verdict   TEXT NOT NULL DEFAULT '',
            new_verdict   TEXT NOT NULL DEFAULT '',
            rescanned_at  TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()

    from contextlib import contextmanager

    repo = MagicMock()
    repo.list_scans.return_value = scans
    repo.is_postgres = False

    @contextmanager
    def _db():
        c = sqlite3.connect(db_path)
        try:
            yield c
            c.commit()
        finally:
            c.close()

    repo._db = _db
    repo.update_scan_verdict = MagicMock()
    repo.update_evidence = MagicMock()
    repo.list_push_tokens.return_value = []
    return repo


def _make_suspicious_scan(scan_id: str, hours_ago: int = 2) -> dict:
    created = (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()
    return {
        "id": scan_id,
        "subject": "Urgent: verify your account",
        "sender": "attacker@evil.com",
        "final_label": "suspicious",
        "final_score": 0.55,
        "created_at": created,
        "evidence_json": json.dumps({
            "scan_mode": "balanced",
            "source_type": "text",
            "scan_input": {
                "body_text": "Click here to verify your bank account immediately.",
                "subject": "Urgent: verify your account",
                "sender": "attacker@evil.com",
            },
        }),
    }


class TestGetRecentSuspiciousScans(unittest.TestCase):

    def test_returns_only_suspicious_within_window(self):
        now = datetime.now(timezone.utc)
        scans = [
            {
                "id": "s1", "final_label": "suspicious",
                "created_at": (now - timedelta(hours=12)).isoformat(),
            },
            {
                "id": "s2", "final_label": "phishing",
                "created_at": (now - timedelta(hours=1)).isoformat(),
            },
            {
                "id": "s3", "final_label": "legitimate",
                "created_at": (now - timedelta(hours=1)).isoformat(),
            },
            {
                "id": "s4", "final_label": "suspicious",
                "created_at": (now - timedelta(hours=100)).isoformat(),  # too old
            },
        ]
        repo = MagicMock()
        repo.list_scans.return_value = scans
        result = _get_recent_suspicious_scans(repo, "local", lookback_hours=24)
        ids = [s["id"] for s in result]
        self.assertIn("s1", ids)
        self.assertNotIn("s2", ids)
        self.assertNotIn("s3", ids)
        self.assertNotIn("s4", ids)

    def test_returns_empty_when_no_suspicious(self):
        repo = MagicMock()
        repo.list_scans.return_value = [
            {"id": "x", "final_label": "legitimate", "created_at": datetime.now(timezone.utc).isoformat()}
        ]
        result = _get_recent_suspicious_scans(repo, "local", 24)
        self.assertEqual(result, [])

    def test_returns_empty_on_repo_error(self):
        repo = MagicMock()
        repo.list_scans.side_effect = Exception("DB error")
        result = _get_recent_suspicious_scans(repo, "local", 24)
        self.assertEqual(result, [])


class TestAlreadyRescanned(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        self.db_path = tmp.name
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS rescan_events "
            "(scan_id TEXT NOT NULL PRIMARY KEY, old_verdict TEXT, new_verdict TEXT, rescanned_at TEXT)"
        )
        conn.commit()
        conn.close()

    def tearDown(self):
        try: os.unlink(self.db_path)
        except: pass

    def _make_repo(self):
        from contextlib import contextmanager
        repo = MagicMock()
        db_path = self.db_path

        @contextmanager
        def _db():
            c = sqlite3.connect(db_path)
            try:
                yield c
                c.commit()
            finally:
                c.close()

        repo._db = _db
        return repo

    def test_not_rescanned_when_no_record(self):
        repo = self._make_repo()
        result = _already_rescanned(repo, "scan-001", window_hours=24)
        self.assertFalse(result)

    def test_already_rescanned_when_recent_record(self):
        conn = sqlite3.connect(self.db_path)
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO rescan_events VALUES (?, ?, ?, ?)",
            ("scan-001", "suspicious", "phishing", now)
        )
        conn.commit()
        conn.close()
        repo = self._make_repo()
        result = _already_rescanned(repo, "scan-001", window_hours=24)
        self.assertTrue(result)

    def test_not_rescanned_when_old_record(self):
        conn = sqlite3.connect(self.db_path)
        old_time = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        conn.execute(
            "INSERT INTO rescan_events VALUES (?, ?, ?, ?)",
            ("scan-old", "suspicious", "phishing", old_time)
        )
        conn.commit()
        conn.close()
        repo = self._make_repo()
        result = _already_rescanned(repo, "scan-old", window_hours=24)
        self.assertFalse(result)


class TestRunRescanPass(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        self.db_path = tmp.name

    def tearDown(self):
        try: os.unlink(self.db_path)
        except: pass

    def test_escalation_calls_update_scan_verdict(self):
        """Suspicious→phishing escalation should call update_scan_verdict."""
        scan = _make_suspicious_scan("scan-001")
        repo = _make_mock_repo([scan], self.db_path)

        service = MagicMock()
        service.run_manual_text_scan.return_value = {
            "final_label": "phishing", "id": "new-scan-001"
        }

        summary = run_rescan_pass(
            repository=repo,
            scan_service=service,
            user_id="local",
            lookback_hours=24,
        )
        self.assertEqual(summary["escalated_count"], 1)
        self.assertEqual(summary["rescanned_count"], 1)
        repo.update_scan_verdict.assert_called_once_with("scan-001", "phishing")

    def test_de_escalation_calls_update_scan_verdict(self):
        """Suspicious→legitimate should call update_scan_verdict (no notification)."""
        scan = _make_suspicious_scan("scan-002")
        repo = _make_mock_repo([scan], self.db_path)

        service = MagicMock()
        service.run_manual_text_scan.return_value = {
            "final_label": "legitimate", "id": "new-scan-002"
        }

        summary = run_rescan_pass(
            repository=repo, scan_service=service, user_id="local", lookback_hours=24
        )
        self.assertEqual(summary["de_escalated_count"], 1)
        repo.update_scan_verdict.assert_called_once_with("scan-002", "legitimate")

    def test_unchanged_verdict_no_update(self):
        """Unchanged verdict should not update the scan."""
        scan = _make_suspicious_scan("scan-003")
        repo = _make_mock_repo([scan], self.db_path)

        service = MagicMock()
        service.run_manual_text_scan.return_value = {"final_label": "suspicious"}

        summary = run_rescan_pass(
            repository=repo, scan_service=service, user_id="local", lookback_hours=24
        )
        self.assertEqual(summary["unchanged_count"], 1)
        repo.update_scan_verdict.assert_not_called()

    def test_empty_scan_list_returns_zero_summary(self):
        repo = _make_mock_repo([], self.db_path)
        service = MagicMock()
        summary = run_rescan_pass(
            repository=repo, scan_service=service, user_id="local", lookback_hours=24
        )
        self.assertEqual(summary["rescanned_count"], 0)
        self.assertEqual(summary["escalated_count"], 0)

    def test_dedup_skips_already_rescanned(self):
        """A scan already rescanned within the window should be skipped."""
        scan = _make_suspicious_scan("scan-004")
        repo = _make_mock_repo([scan], self.db_path)

        # Pre-insert a rescan event for this scan
        now = datetime.now(timezone.utc).isoformat()
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT INTO rescan_events VALUES (?, ?, ?, ?)",
            ("scan-004", "suspicious", "suspicious", now)
        )
        conn.commit()
        conn.close()

        service = MagicMock()
        summary = run_rescan_pass(
            repository=repo, scan_service=service, user_id="local", lookback_hours=24
        )
        service.run_manual_text_scan.assert_not_called()
        self.assertEqual(summary["rescanned_count"], 0)

    def test_never_raises_on_service_error(self):
        """run_rescan_pass must not propagate exceptions from scan_service."""
        scan = _make_suspicious_scan("scan-005")
        repo = _make_mock_repo([scan], self.db_path)

        service = MagicMock()
        service.run_manual_text_scan.side_effect = RuntimeError("Unexpected crash")

        try:
            summary = run_rescan_pass(
                repository=repo, scan_service=service, user_id="local", lookback_hours=24
            )
            self.assertEqual(summary["errors"], 1)
        except Exception as exc:
            self.fail(f"run_rescan_pass raised unexpectedly: {exc}")


class TestFeature6Integration(unittest.TestCase):

    def test_rescan_job_importable(self):
        from server.rescan_job import run_rescan_pass, run_periodic_rescan

    def test_config_flags_importable(self):
        from utils.config import (
            FEATURE_SECOND_LOOK_RESCAN_ENABLED,
            RESCAN_INTERVAL_HOURS,
            RESCAN_LOOKBACK_HOURS,
        )
        self.assertIsInstance(FEATURE_SECOND_LOOK_RESCAN_ENABLED, bool)

    def test_repository_has_update_scan_verdict(self):
        from server.repository import ScanRepository
        self.assertTrue(hasattr(ScanRepository, "update_scan_verdict"))

    def test_repository_has_update_evidence(self):
        from server.repository import ScanRepository
        self.assertTrue(hasattr(ScanRepository, "update_evidence"))


if __name__ == "__main__":
    unittest.main()
