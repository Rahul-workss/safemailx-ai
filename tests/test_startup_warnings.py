import unittest

from server.persistence_checks import SQLITE_PERSISTENCE_WARNING, check_database_persistence


class StartupWarningTests(unittest.TestCase):
    def test_sqlite_database_url_emits_warning(self):
        warning = check_database_persistence("sqlite:///safemailx_app.db")
        self.assertEqual(warning, SQLITE_PERSISTENCE_WARNING)

    def test_postgres_database_url_is_silent(self):
        warning = check_database_persistence("postgresql://user:pass@host:5432/safemailx")
        self.assertIsNone(warning)


if __name__ == "__main__":
    unittest.main()
