import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

import server.app as server_app
from server.auth import hash_password


app = server_app.app


class FakeScanQueue:
    def __init__(self):
        self.jobs = []

    def enqueue(self, job):
        self.jobs.append(job)
        return len(self.jobs)

    def ping(self):
        return True


class ServerAppTests(unittest.TestCase):
    def auth_headers(self, client: TestClient) -> dict[str, str]:
        response = client.post(
            "/auth/login",
            json={
                "email": "admin@trustmail.local",
                "password": "change-me-before-production",
            },
        )
        self.assertEqual(response.status_code, 200)
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    def test_login_returns_signed_bearer_token(self):
        client = TestClient(app)

        response = client.post(
            "/auth/login",
            json={
                "email": "admin@trustmail.local",
                "password": "change-me-before-production",
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["token_type"], "bearer")
        self.assertEqual(len(payload["access_token"].split(".")), 3)

    def test_health_and_scan_list_endpoints(self):
        client = TestClient(app)
        headers = self.auth_headers(client)

        health = client.get("/api/health")
        scans = client.get("/api/scans", headers=headers)

        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json()["api"], "online")
        self.assertEqual(scans.status_code, 200)
        self.assertIsInstance(scans.json(), list)

    def test_manual_scan_queue_endpoint_persists_and_enqueues_job(self):
        original_queue = server_app.scan_queue
        fake_queue = FakeScanQueue()
        server_app.scan_queue = fake_queue
        try:
            client = TestClient(app)
            headers = self.auth_headers(client)

            response = client.post(
                "/api/scans/manual/queue",
                headers=headers,
                json={
                    "subject": "Queued test",
                    "sender": "tester@example.com",
                    "body": "Please verify your account immediately.",
                    "scan_mode": "balanced",
                },
            )

            self.assertEqual(response.status_code, 202)
            payload = response.json()
            self.assertEqual(payload["final_label"], "queued")
            self.assertEqual(fake_queue.jobs[0]["scan_id"], payload["id"])
            self.assertEqual(fake_queue.jobs[0]["type"], "manual_text")
        finally:
            server_app.scan_queue = original_queue

    def test_upload_scan_accepts_text_file(self):
        client = TestClient(app)
        headers = self.auth_headers(client)

        response = client.post(
            "/api/scans/upload",
            headers=headers,
            data={"subject": "Uploaded test", "sender": "upload@example.com"},
            files={
                "file": (
                    "message.txt",
                    b"Please verify your password immediately.",
                    "text/plain",
                )
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["subject"], "Uploaded test")
        self.assertEqual(payload["evidence"]["upload"]["filename"], "message.txt")

    def test_upload_scan_rejects_unsupported_file_type(self):
        client = TestClient(app)
        headers = self.auth_headers(client)

        response = client.post(
            "/api/scans/upload",
            headers=headers,
            files={"file": ("payload.exe", b"MZ...", "application/octet-stream")},
        )

        self.assertEqual(response.status_code, 415)

    def test_report_link_downloads_with_signed_token(self):
        client = TestClient(app)
        headers = self.auth_headers(client)

        with TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "report.json"
            report_path.write_text('{"status":"ok"}', encoding="utf-8")
            user_id = server_app.repository.get_user_by_email("admin@trustmail.local")["id"]
            scan_id = server_app.repository.create_scan(
                user_id=user_id,
                subject="Downloadable report",
                sender="report@example.com",
                final_label="legitimate",
                final_score=0.05,
                llm_used=False,
                degraded=False,
                evidence={"status": "ok"},
                report_pdf=None,
                report_json=str(report_path),
            )

            link_response = client.post(
                f"/api/scans/{scan_id}/report-link?kind=json",
                headers=headers,
            )
            self.assertEqual(link_response.status_code, 200)
            url = link_response.json()["url"]
            token = url.split("token=", 1)[1]

            download_response = client.get(f"/api/reports/download?token={token}")
            self.assertEqual(download_response.status_code, 200)
            self.assertEqual(download_response.json(), {"status": "ok"})

        bad_response = client.get("/api/reports/download?token=not-a-token")
        self.assertEqual(bad_response.status_code, 401)

    def test_register_push_token(self):
        client = TestClient(app)
        headers = self.auth_headers(client)

        response = client.post(
            "/api/notifications/register",
            headers=headers,
            json={"token": "ExponentPushToken[test-token]", "platform": "ios"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "registered")

    def test_readiness_reports_local_warnings_without_blocking(self):
        client = TestClient(app)
        headers = self.auth_headers(client)

        with TemporaryDirectory() as temp_dir, patch.dict(
            "os.environ",
            {"TRUSTMAIL_PRODUCTION": "false", "TRUSTMAIL_REQUIRE_AUTH": "false"},
            clear=False,
        ), patch(
            "server.readiness.GMAIL_CREDENTIALS_PATH",
            Path(temp_dir) / "missing-credentials.json",
        ):
            response = client.get("/api/readiness", headers=headers)

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["environment"], "local")
        self.assertFalse(payload["ready"])
        statuses = {item["key"]: item["status"] for item in payload["items"]}
        self.assertEqual(statuses["auth_mode"], "warning")
        self.assertEqual(statuses["gmail_credentials"], "missing")

    def test_readiness_accepts_production_shaped_configuration(self):
        client = TestClient(app)
        headers = self.auth_headers(client)

        with TemporaryDirectory() as temp_dir:
            credentials_path = Path(temp_dir) / "credentials.json"
            credentials_path.write_text(
                """
                {
                  "web": {
                    "client_id": "trustmail-client-id.apps.googleusercontent.com",
                    "client_secret": "trustmail-client-secret"
                  }
                }
                """,
                encoding="utf-8",
            )
            env = {
                "TRUSTMAIL_PRODUCTION": "true",
                "TRUSTMAIL_REQUIRE_AUTH": "true",
                "JWT_SECRET": "production-secret-with-at-least-32-characters",
                "TRUSTMAIL_ADMIN_EMAIL": "admin@example.com",
                "TRUSTMAIL_ADMIN_PASSWORD": "production-password-123",
                "GMAIL_OAUTH_REDIRECT_URI": "https://trustmail.example.com/api/gmail/oauth/callback",
                "GMAIL_TOKEN_ENCRYPTION_KEY": "not-validated-here",
                "SMTP_HOST": "smtp.example.com",
                "SMTP_FROM_EMAIL": "no-reply@example.com",
                "SMTP_USERNAME": "smtp-user",
                "SMTP_PASSWORD": "smtp-password",
                "EXPO_ACCESS_TOKEN": "expo-token",
            }
            with patch.dict("os.environ", env, clear=False), patch(
                "server.readiness.GMAIL_CREDENTIALS_PATH",
                credentials_path,
            ):
                response = client.get("/api/readiness", headers=headers)

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["environment"], "production")
        self.assertTrue(payload["ready"])
        statuses = {item["key"]: item["status"] for item in payload["items"]}
        self.assertEqual(statuses["jwt_secret"], "ready")
        self.assertEqual(statuses["gmail_redirect_uri"], "ready")
        self.assertEqual(statuses["oauth_consent"], "warning")

    def test_forgot_and_reset_password_flow(self):
        client = TestClient(app)
        user = server_app.repository.get_user_by_email("reset-user@example.com")
        if not user:
            password_hash, salt = hash_password("old-password-123")
            user_id = server_app.repository.create_user(
                email="reset-user@example.com",
                password_hash=password_hash,
                salt=salt,
            )
            user = server_app.repository.get_user_by_id(user_id)

        with patch("uuid.uuid4", return_value="reset-token-123"), patch("server.app.send_password_reset_email") as send_mail:
            forgot = client.post(
                "/auth/forgot-password",
                json={"email": "reset-user@example.com"},
            )

        self.assertEqual(forgot.status_code, 200)
        send_mail.assert_called_once_with("reset-user@example.com", "reset-token-123")

        reset = client.post(
            "/auth/reset-password",
            json={"token": "reset-token-123", "new_password": "new-password-123"},
        )
        self.assertEqual(reset.status_code, 200)

        login = client.post(
            "/auth/login",
            json={
                "email": "reset-user@example.com",
                "password": "new-password-123",
            },
        )
        self.assertEqual(login.status_code, 200)


if __name__ == "__main__":
    unittest.main()
