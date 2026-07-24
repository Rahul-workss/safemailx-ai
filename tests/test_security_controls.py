import io
import sys
import unittest
import zipfile
from unittest.mock import patch


sys.path.insert(0, "src")

from engines.url_analyzer import is_safe_external_url
from server import auth, settings
from server.uploads import validate_upload_bytes


class SecurityControlTests(unittest.TestCase):
    def test_private_and_non_http_urls_are_rejected(self):
        self.assertFalse(is_safe_external_url("http://127.0.0.1/admin"))
        self.assertFalse(is_safe_external_url("http://169.254.169.254/latest/meta-data"))
        self.assertFalse(is_safe_external_url("file:///etc/passwd"))

    def test_upload_path_and_executable_content_are_rejected(self):
        with self.assertRaises(ValueError):
            validate_upload_bytes("../secret.txt", b"text")
        with self.assertRaises(ValueError):
            validate_upload_bytes("photo.png", b"MZnot-an-image")

    def test_zip_path_traversal_is_rejected(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("../../outside.txt", "unsafe")
        with self.assertRaises(ValueError):
            validate_upload_bytes("report.docx", buffer.getvalue())

    def test_oauth_exchange_code_is_single_use_without_redis_in_local_mode(self):
        with patch.object(auth, "_revocation_client", return_value=None):
            code = auth.create_oauth_exchange_code("user@example.com", "user-1")
            self.assertEqual(auth.consume_oauth_exchange_code(code)["uid"], "user-1")
            self.assertIsNone(auth.consume_oauth_exchange_code(code))

    def test_refresh_token_cannot_be_used_as_access_token(self):
        refresh = auth.create_signed_token({"sub": "user@example.com", "uid": "user-1", "type": "refresh"})
        with self.assertRaises(Exception):
            auth.verify_access_token(refresh, expected_type="access")

    def test_production_validation_rejects_disabled_auth(self):
        with patch.object(settings, "SAFEMAILX_PRODUCTION", True), patch.object(settings, "SAFEMAILX_REQUIRE_AUTH", False):
            with self.assertRaises(RuntimeError):
                settings.validate_security_settings()


if __name__ == "__main__":
    unittest.main()
