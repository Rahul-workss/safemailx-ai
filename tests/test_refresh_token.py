import sys
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(ROOT))

import server.app as server_app
from server.auth import create_access_token, create_refresh_token, create_signed_token, hash_password, verify_access_token


class RefreshTokenTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(server_app.app)

    def _create_user(self) -> tuple[str, str]:
        email = f"refresh-{uuid.uuid4().hex[:10]}@example.com"
        password_hash, salt = hash_password("refresh-password-123")
        user_id = server_app.repository.create_user(
            email=email,
            password_hash=password_hash,
            salt=salt,
        )
        return email, user_id

    def _delete_user(self, user_id: str) -> None:
        placeholder = "%s" if server_app.repository.is_postgres else "?"
        with server_app.repository._db() as conn:  # type: ignore[attr-defined]
            conn.execute(f"DELETE FROM users WHERE id = {placeholder}", (user_id,))

    def test_refresh_token_issues_new_access_token(self):
        email, user_id = self._create_user()
        refresh_token = create_refresh_token(email, user_id)

        response = self.client.post("/auth/refresh", json={"refresh_token": refresh_token})

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("access_token", payload)
        self.assertIn("refresh_token", payload)
        decoded_access = verify_access_token(payload["access_token"])
        decoded_refresh = verify_access_token(payload["refresh_token"])
        self.assertEqual(decoded_access["uid"], user_id)
        self.assertEqual(decoded_access["sub"], email)
        self.assertEqual(decoded_refresh["type"], "refresh")

    def test_refresh_rejects_invalid_token(self):
        response = self.client.post("/auth/refresh", json={"refresh_token": "invalid-refresh-token-value"})

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"], "Invalid or expired token")

    def test_refresh_rejects_access_token(self):
        email, user_id = self._create_user()
        access_token = create_access_token(email, user_id)

        response = self.client.post("/auth/refresh", json={"refresh_token": access_token})

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"], "Not a refresh token")

    def test_refresh_rejects_deleted_user(self):
        email, user_id = self._create_user()
        refresh_token = create_refresh_token(email, user_id)
        self._delete_user(user_id)

        response = self.client.post("/auth/refresh", json={"refresh_token": refresh_token})

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"], "Account no longer exists")

    def test_refresh_endpoint_can_be_disabled(self):
        email, user_id = self._create_user()
        refresh_token = create_signed_token({"uid": user_id, "sub": email, "type": "refresh"})

        with patch("server.app.FEATURE_REFRESH_TOKEN_ENABLED", False):
            response = self.client.post("/auth/refresh", json={"refresh_token": refresh_token})

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["detail"], "Refresh token flow disabled")


if __name__ == "__main__":
    unittest.main()
