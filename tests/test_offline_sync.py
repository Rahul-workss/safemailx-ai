"""
Tests for Feature 3: Offline Hash-Prefix Safe-Browsing Check
src/engines/offline_sync.py

Key assertions:
  - url_to_hash_prefix is deterministic and produces 8 hex chars
  - sync_prefixes_from_feed stores ONLY prefixes, never full hashes
  - check_url_against_offline_db is correct and makes ZERO network calls
  - check_url_against_offline_db returns True/False correctly
  - empty OFFLINE_HASH_FEED_URL is a clean no-op
"""

import os
import sys
import sqlite3
import tempfile
import unittest
from unittest.mock import patch, MagicMock

SRC_DIR = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, SRC_DIR)


class TestUrlToHashPrefix(unittest.TestCase):
    """Tests for url_to_hash_prefix()."""

    def setUp(self):
        from engines.offline_sync import url_to_hash_prefix, PREFIX_LENGTH
        self.url_to_hash_prefix = url_to_hash_prefix
        self.PREFIX_LENGTH = PREFIX_LENGTH

    def test_output_is_exactly_2x_prefix_length_hex_chars(self):
        prefix = self.url_to_hash_prefix("https://example.com/path")
        self.assertEqual(len(prefix), self.PREFIX_LENGTH * 2)

    def test_output_is_hex_string(self):
        prefix = self.url_to_hash_prefix("https://example.com")
        self.assertRegex(prefix, r"^[0-9a-f]+$")

    def test_deterministic_same_url_same_prefix(self):
        url = "https://phish.example.net/verify-account"
        p1 = self.url_to_hash_prefix(url)
        p2 = self.url_to_hash_prefix(url)
        self.assertEqual(p1, p2)

    def test_different_urls_produce_different_prefixes(self):
        # Different full URLs should (very probably) produce different prefixes
        p1 = self.url_to_hash_prefix("https://evil.com/steal")
        p2 = self.url_to_hash_prefix("https://safe.com/home")
        # Not guaranteed (hash collision) but overwhelmingly likely
        self.assertNotEqual(p1, p2)

    def test_prefix_is_not_full_hash(self):
        """The returned value must be a prefix (8 chars), NOT the full 64-char SHA-256."""
        import hashlib
        url = "https://test.example.com"
        full_hash = hashlib.sha256(url.encode()).hexdigest()
        prefix = self.url_to_hash_prefix(url)
        self.assertNotEqual(prefix, full_hash)
        self.assertLess(len(prefix), len(full_hash))

    def test_normalizes_case(self):
        """Upper and lower case URLs should produce the same prefix (normalized)."""
        p1 = self.url_to_hash_prefix("https://EVIL.COM/PHISH")
        p2 = self.url_to_hash_prefix("https://evil.com/phish")
        self.assertEqual(p1, p2)


class TestSyncPrefixesFromFeed(unittest.TestCase):
    """Tests for sync_prefixes_from_feed() with mocked HTTP."""

    def setUp(self):
        # Use a temp DB so we don't corrupt the real one
        self._tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp_db.close()
        self._orig_db_path = None

    def tearDown(self):
        try:
            os.unlink(self._tmp_db.name)
        except Exception:
            pass

    def _patch_db(self):
        """Patch DB_PATH to point to the temp DB."""
        import engines.offline_sync as mod
        mod.init_db.__module__  # ensure module is imported
        return patch.object(mod, "DB_PATH", self._tmp_db.name)

    def test_empty_feed_url_is_no_op(self):
        """sync_prefixes_from_feed with empty URL returns 0 without making network call."""
        from engines.offline_sync import sync_prefixes_from_feed
        with patch("engines.offline_sync.DB_PATH", self._tmp_db.name):
            # Ensure init_db creates the table in the temp DB
            conn = sqlite3.connect(self._tmp_db.name)
            conn.execute("CREATE TABLE IF NOT EXISTS prefixes (prefix_hex TEXT PRIMARY KEY)")
            conn.commit()
            conn.close()

            with patch("requests.get") as mock_get:
                result = sync_prefixes_from_feed("")
                mock_get.assert_not_called()  # zero network calls
                self.assertEqual(result, 0)

    def test_mocked_feed_inserts_prefixes(self):
        """Mocked feed lines produce prefix insertions."""
        import engines.offline_sync as mod
        # Set up temp DB
        conn = sqlite3.connect(self._tmp_db.name)
        conn.execute("CREATE TABLE IF NOT EXISTS prefixes (prefix_hex TEXT PRIMARY KEY)")
        conn.commit()
        conn.close()

        feed_content = "\n".join([
            "https://evil.com/phish",
            "https://phish.bad.net/steal",
            "# comment line — skip",
            "",
            "https://another.malicious.site/hook",
        ])

        mock_response = MagicMock()
        mock_response.text = feed_content
        mock_response.raise_for_status = MagicMock()

        with patch.object(mod, "DB_PATH", self._tmp_db.name):
            with patch("requests.get", return_value=mock_response):
                count = mod.sync_prefixes_from_feed("https://fake-feed.example.com/list.txt")

        self.assertEqual(count, 3)  # 3 valid URLs, 1 comment, 1 blank

    def test_db_never_contains_full_hash(self):
        """After a sync, the DB contains ONLY 8-char prefixes, never full hashes."""
        import engines.offline_sync as mod
        conn = sqlite3.connect(self._tmp_db.name)
        conn.execute("CREATE TABLE IF NOT EXISTS prefixes (prefix_hex TEXT PRIMARY KEY)")
        conn.commit()
        conn.close()

        feed_content = "https://evil.com/steal\nhttps://phish.net/verify\n"
        mock_response = MagicMock()
        mock_response.text = feed_content
        mock_response.raise_for_status = MagicMock()

        with patch.object(mod, "DB_PATH", self._tmp_db.name):
            with patch("requests.get", return_value=mock_response):
                mod.sync_prefixes_from_feed("https://fake-feed.example.com/list.txt")

        # Check every stored prefix is exactly PREFIX_LENGTH * 2 hex chars
        conn = sqlite3.connect(self._tmp_db.name)
        rows = conn.execute("SELECT prefix_hex FROM prefixes").fetchall()
        conn.close()

        self.assertGreater(len(rows), 0)
        for (prefix_hex,) in rows:
            self.assertEqual(len(prefix_hex), mod.PREFIX_LENGTH * 2,
                             f"Found a non-prefix value: {prefix_hex!r}")
            self.assertRegex(prefix_hex, r"^[0-9a-f]+$",
                             f"Non-hex value stored: {prefix_hex!r}")


class TestCheckUrlAgainstOfflineDb(unittest.TestCase):
    """Tests for check_url_against_offline_db()."""

    def setUp(self):
        import engines.offline_sync as mod
        self.mod = mod
        # Temp DB
        self._tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp_db.close()
        conn = sqlite3.connect(self._tmp_db.name)
        conn.execute("CREATE TABLE IF NOT EXISTS prefixes (prefix_hex TEXT PRIMARY KEY)")
        conn.commit()
        conn.close()

    def tearDown(self):
        try:
            os.unlink(self._tmp_db.name)
        except Exception:
            pass

    def _insert_prefix(self, url: str):
        prefix = self.mod.url_to_hash_prefix(url)
        conn = sqlite3.connect(self._tmp_db.name)
        conn.execute("INSERT OR IGNORE INTO prefixes (prefix_hex) VALUES (?)", (prefix,))
        conn.commit()
        conn.close()

    def test_known_bad_url_returns_true(self):
        evil_url = "https://evil-phish.example.com/steal-creds"
        self._insert_prefix(evil_url)
        with patch.object(self.mod, "DB_PATH", self._tmp_db.name):
            result = self.mod.check_url_against_offline_db(evil_url)
        self.assertTrue(result)

    def test_unknown_url_returns_false(self):
        with patch.object(self.mod, "DB_PATH", self._tmp_db.name):
            result = self.mod.check_url_against_offline_db("https://totally-clean-site.com")
        self.assertFalse(result)

    def test_empty_url_returns_false(self):
        with patch.object(self.mod, "DB_PATH", self._tmp_db.name):
            result = self.mod.check_url_against_offline_db("")
        self.assertFalse(result)

    def test_zero_network_calls(self):
        """check_url_against_offline_db must never make a network call."""
        with patch.object(self.mod, "DB_PATH", self._tmp_db.name):
            with patch("requests.get") as mock_get:
                self.mod.check_url_against_offline_db("https://any-url.example.com")
                mock_get.assert_not_called()


class TestFeature3Integration(unittest.TestCase):
    """Integration: confirm existing callers still work after Feature 3."""

    def test_url_analyzer_imports_cleanly(self):
        try:
            from engines.url_analyzer import check_offline_prefix, analyze_urls
        except ImportError as exc:
            self.fail(f"url_analyzer import failed: {exc}")

    def test_offline_sync_imports_cleanly(self):
        try:
            from engines.offline_sync import (
                init_db, check_url_prefix, sync_prefixes,
                check_url_against_offline_db, sync_prefixes_from_feed,
                url_to_hash_prefix, run_periodic_sync
            )
        except ImportError as exc:
            self.fail(f"offline_sync import failed: {exc}")

    def test_feature_flags_importable(self):
        from utils.config import (
            FEATURE_OFFLINE_SAFEBROWSING_ENABLED,
            OFFLINE_HASH_FEED_URL,
            OFFLINE_HASH_SYNC_INTERVAL_HOURS,
        )
        self.assertIsInstance(FEATURE_OFFLINE_SAFEBROWSING_ENABLED, bool)
        self.assertIsInstance(OFFLINE_HASH_FEED_URL, str)
        self.assertIsInstance(OFFLINE_HASH_SYNC_INTERVAL_HOURS, float)

    def test_legacy_check_url_prefix_still_works(self):
        """Legacy check_url_prefix() should still be callable and return bool."""
        from engines.offline_sync import check_url_prefix
        result = check_url_prefix("https://completely-unknown-url.example.com")
        self.assertIsInstance(result, bool)


if __name__ == "__main__":
    unittest.main()
