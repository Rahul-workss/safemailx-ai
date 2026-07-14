import sys
import unittest
import uuid
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(ROOT))

import server.app as server_app
import server.repository as repository_module
from server.auth import create_signed_token, hash_password
from server.schemas import InstantScanResult, QuickScanArtifacts, QuickScanSignal


app = server_app.app


def _instant_result(*, channel: str, verdict: str, summary: str) -> InstantScanResult:
    return InstantScanResult(
        scan_id="pending",
        channel=channel,
        verdict=verdict,
        risk_score=82.0 if verdict == "phishing" else 34.0,
        confidence=0.88,
        summary=summary,
        top_signals=[
            QuickScanSignal(
                name="primary_signal",
                description="Primary detection signal for inline regression coverage.",
                severity="high" if verdict == "phishing" else "medium",
                confidence=0.91,
            )
        ],
        artifacts=QuickScanArtifacts(
            urls=["https://example.com/offer"],
            domains=["example.com"],
            sender_id="VM-BANK",
            sender_type="alphanumeric",
            submitted_url="https://example.com/offer" if channel == "url" else None,
            normalized_url="https://example.com/offer" if channel == "url" else None,
            final_url="https://example.com/offer" if channel == "url" else None,
            final_domain="example.com" if channel == "url" else None,
            filename="sample.txt" if channel == "file" else None,
            detected_file_type="text/plain" if channel == "file" else None,
            parser_quality="high" if channel == "file" else None,
            extraction_method="text" if channel == "file" else None,
        ),
        recommended_action="Do not proceed until the destination is verified.",
        degraded=False,
        saved_to_history=False,
        llm_reasoning="LLM used only as ambiguity resolver.",
        evidence_quality="medium",
        analysis_mode="hybrid_cloud",
        external_checks_used=["safe_browsing"],
        external_checks_failed=[],
        degraded_reasons=[],
        privacy_notice="URLs or hashes may be checked against configured security providers.",
        scan_category="reward_lure" if channel == "sms" else "link_risk",
    )


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
                "email": "admin@safemailx.local",
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
                "email": "admin@safemailx.local",
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

    def test_upload_scan_accepts_xlsx_file(self):
        client = TestClient(app)
        headers = self.auth_headers(client)

        response = client.post(
            "/api/scans/upload",
            headers=headers,
            data={"subject": "Spreadsheet test", "sender": "upload@example.com"},
            files={
                "file": (
                    "sheet.xlsx",
                    b"not-a-real-zip-but-supported",
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                )
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["subject"], "Spreadsheet test")
        self.assertEqual(payload["evidence"]["upload"]["filename"], "sheet.xlsx")

    def test_upload_scan_rejects_unsupported_file_type(self):
        client = TestClient(app)
        headers = self.auth_headers(client)

        response = client.post(
            "/api/scans/upload",
            headers=headers,
            files={"file": ("payload.exe", b"MZ...", "application/octet-stream")},
        )

        self.assertEqual(response.status_code, 415)

    def test_screenshot_scan_accepts_image_upload(self):
        client = TestClient(app)
        headers = self.auth_headers(client)

        response = client.post(
            "/api/scans/screenshot",
            headers=headers,
            data={"subject": "Screenshot test", "sender": "screenshot@example.com"},
            files={"file": ("shot.png", b"fake-image-bytes", "image/png")},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["subject"], "Screenshot test")
        self.assertEqual(payload["evidence"]["upload"]["filename"], "shot.png")

    def test_url_scan_accepts_single_url(self):
        original_queue = server_app.scan_queue
        fake_queue = FakeScanQueue()
        server_app.scan_queue = fake_queue
        try:
            client = TestClient(app)
            headers = self.auth_headers(client)

            response = client.post(
                "/api/scans/url",
                headers=headers,
                json={"url": "https://example.com/login", "scan_mode": "balanced"},
            )

            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertIn("URL Scan:", payload["subject"])
            self.assertEqual(payload["sender"], "url_checker")
        finally:
            server_app.scan_queue = original_queue

    def test_instant_sms_returns_inline_result_and_saves_history(self):
        client = TestClient(app)
        headers = self.auth_headers(client)
        user_id = server_app.repository.get_user_by_email("admin@safemailx.local")["id"]

        with patch.object(
            server_app.inline_scan_service.orchestrator,
            "process_sms_scan",
            return_value=_instant_result(
                channel="sms",
                verdict="phishing",
                summary="Suspicious SMS with risky CTA link.",
            ),
        ):
            response = client.post(
                "/api/instant/sms",
                headers=headers,
                json={"text": "Claim your prize now: https://example.com/offer", "sender_number": "VM-BANK"},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["channel"], "sms")
        self.assertEqual(payload["verdict"], "phishing")
        self.assertEqual(payload["analysis_mode"], "hybrid_cloud")
        self.assertIn("safe_browsing", payload["external_checks_used"])
        self.assertTrue(payload["saved_to_history"])

        saved = server_app.repository.get_scan(payload["scan_id"], user_id=user_id)
        self.assertIsNotNone(saved)
        self.assertIsNone(saved["report_pdf"])
        self.assertIsNone(saved["report_json"])
        self.assertEqual(saved["evidence"]["privacy_notice"], payload["privacy_notice"])

    def test_instant_url_returns_provenance_fields(self):
        client = TestClient(app)
        headers = self.auth_headers(client)

        with patch.object(
            server_app.inline_scan_service.orchestrator,
            "process_url_scan",
            return_value=_instant_result(
                channel="url",
                verdict="suspicious",
                summary="Redirect chain could not be fully trusted.",
            ),
        ):
            response = client.post(
                "/api/instant/url",
                headers=headers,
                json={"url": "https://example.com/offer", "scan_mode": "balanced"},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["channel"], "url")
        self.assertEqual(payload["verdict"], "suspicious")
        self.assertEqual(payload["artifacts"]["final_domain"], "example.com")
        self.assertEqual(payload["evidence_quality"], "medium")
        self.assertEqual(payload["analysis_mode"], "hybrid_cloud")

    def test_instant_file_returns_inline_result_without_reports(self):
        client = TestClient(app)
        headers = self.auth_headers(client)
        user_id = server_app.repository.get_user_by_email("admin@safemailx.local")["id"]

        with patch.object(
            server_app.inline_scan_service.orchestrator,
            "process_file_scan",
            return_value=_instant_result(
                channel="file",
                verdict="suspicious",
                summary="Uploaded file contains risky links and needs review.",
            ),
        ):
            response = client.post(
                "/api/instant/file",
                headers=headers,
                data={"scan_mode": "balanced"},
                files={"file": ("sample.txt", b"Review this file", "text/plain")},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["channel"], "file")
        self.assertEqual(payload["artifacts"]["filename"], "sample.txt")
        self.assertEqual(payload["privacy_notice"], "URLs or hashes may be checked against configured security providers.")
        self.assertTrue(payload["saved_to_history"])

        saved = server_app.repository.get_scan(payload["scan_id"], user_id=user_id)
        self.assertIsNotNone(saved)
        self.assertIsNone(saved["report_pdf"])
        self.assertIsNone(saved["report_json"])

    def test_report_link_downloads_with_signed_token(self):
        client = TestClient(app)
        headers = self.auth_headers(client)

        with TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "report.json"
            report_path.write_text('{"status":"ok"}', encoding="utf-8")
            user_id = server_app.repository.get_user_by_email("admin@safemailx.local")["id"]
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

    def test_notification_preferences_round_trip(self):
        client = TestClient(app)
        headers = self.auth_headers(client)

        current = client.get("/api/notifications/preferences", headers=headers)
        self.assertEqual(current.status_code, 200)
        self.assertIn("critical_alerts", current.json())
        self.assertIn("weekly_summary", current.json())

        updated = client.put(
            "/api/notifications/preferences",
            headers=headers,
            json={"critical_alerts": False, "weekly_summary": True},
        )

        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["critical_alerts"], False)

    def test_scan_feedback_round_trip(self):
        client = TestClient(app)
        headers = self.auth_headers(client)
        user_id = server_app.repository.get_user_by_email("admin@safemailx.local")["id"]
        scan_id = server_app.repository.create_scan(
            user_id=user_id,
            subject="Feedback target",
            sender="qa@example.com",
            final_label="suspicious",
            final_score=0.55,
            llm_used=False,
            degraded=False,
            evidence={"summary": "Needs human verification."},
            report_pdf=None,
            report_json=None,
        )

        response = client.post(
            f"/api/scans/{scan_id}/feedback",
            headers=headers,
            json={"feedback": "false_positive", "note": "Known internal sender."},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["scan_id"], scan_id)
        self.assertEqual(payload["feedback"], "false_positive")

        stored = server_app.repository.get_scan(scan_id, user_id=user_id)
        self.assertEqual(stored["evidence"]["review_feedback"]["feedback"], "false_positive")
        self.assertEqual(stored["evidence"]["review_feedback"]["note"], "Known internal sender.")

    def test_register_creates_user_and_returns_token(self):
        client = TestClient(app)
        import uuid
        from datetime import datetime, timedelta, timezone

        email = f"fresh-user-{uuid.uuid4().hex[:10]}@example.com"
        otp = "123456"
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
        server_app.repository.store_otp(email, otp, expires_at)

        response = client.post(
            "/auth/register",
            json={"email": email, "password": "new-password-123", "otp": otp},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["token_type"], "bearer")
        self.assertIsNotNone(server_app.repository.get_user_by_email(email))

    def test_gmail_status_exposes_label_privacy_mode(self):
        client = TestClient(app)
        headers = self.auth_headers(client)

        response = client.get("/api/gmail/oauth/status", headers=headers)

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("connected", payload)
        self.assertEqual(payload["privacy_mode"], "label_only")
        self.assertEqual(payload["scan_label"], "SafeMail X Scan")

    def test_gmail_oauth_start_uses_request_host_for_local_mobile_callback(self):
        client = TestClient(app)
        headers = self.auth_headers(client)

        with patch("server.app.GMAIL_OAUTH_REDIRECT_URI", "http://127.0.0.1:8080/api/gmail/oauth/callback"), patch(
            "server.app.build_authorization_url",
            return_value="https://accounts.google.com/o/oauth2/auth",
        ) as build_auth:
            response = client.get(
                "/api/gmail/oauth/start",
                headers={**headers, "host": "172.25.189.18:8080"},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(
            payload["redirect_uri"],
            "http://172.25.189.18:8080/api/gmail/oauth/callback",
        )
        build_auth.assert_called_once()
        self.assertEqual(
            build_auth.call_args.kwargs["redirect_uri"],
            "http://172.25.189.18:8080/api/gmail/oauth/callback",
        )

    def test_google_oauth_callback_logs_when_creating_missing_user_record(self):
        client = TestClient(app)
        email = f"oauth-new-{uuid.uuid4().hex[:10]}@example.com"
        state = create_signed_token(
            {
                "sub": "guest",
                "uid": "temp_guest",
                "oauth_redirect_uri": "http://testserver/api/auth/google/callback",
                "purpose": "auth",
                "return_url": "safemailxai://oauth-callback",
            }
        )
        user_info_service = Mock()
        user_info_service.userinfo.return_value.get.return_value.execute.return_value = {
            "email": email,
            "name": "OAuth User",
        }

        with patch("server.app.exchange_code_for_token", return_value=object()), patch(
            "googleapiclient.discovery.build",
            return_value=user_info_service,
        ), patch("builtins.print") as print_mock:
            response = client.get(
                "/api/auth/google/callback",
                params={"code": "oauth-code", "state": state},
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Signed In Successfully!", response.text)
        self.assertIsNotNone(server_app.repository.get_user_by_email(email))
        printed = "\n".join(str(call.args[0]) for call in print_mock.call_args_list if call.args)
        self.assertIn(f"[AUTH] Creating new user record for {email} via Google OAuth", printed)

    def test_gmail_label_setup_and_run_once_use_connected_label_flow(self):
        from tests.test_gmail_watcher import FakeGmailService

        original_queue = server_app.scan_queue
        fake_queue = FakeScanQueue()
        fake_service = FakeGmailService(labeled_ids=["msg-1"], labels=[])
        server_app.scan_queue = fake_queue
        try:
            client = TestClient(app)
            headers = self.auth_headers(client)
            user_id = server_app.repository.get_user_by_email("admin@safemailx.local")["id"]
            previous_token = server_app.repository.get_gmail_token(user_id)
            server_app.repository.store_gmail_token(user_id, "fake-token")

            with patch("server.app.build_gmail_service_from_blob", return_value=fake_service):
                setup = client.post("/api/gmail/labels/ensure", headers=headers)
                run_once = client.post("/api/gmail/run-once", headers=headers)

            self.assertEqual(setup.status_code, 200)
            self.assertEqual(setup.json()["privacy_mode"], "label_only")
            self.assertEqual(setup.json()["labels"]["scan"], "SafeMail X Scan")
            self.assertEqual(run_once.status_code, 200)
            self.assertEqual(run_once.json()["enqueued"], 1)
            self.assertEqual(run_once.json()["scanned_label"], "SafeMail X Scan")
            self.assertEqual(fake_queue.jobs[0]["type"], "gmail_label_message")
            self.assertEqual(fake_queue.jobs[0]["source"], "gmail_label_app")
        finally:
            server_app.scan_queue = original_queue
            if "user_id" in locals():
                if "previous_token" in locals() and previous_token:
                    server_app.repository.store_gmail_token(user_id, previous_token)
                else:
                    server_app.repository.delete_gmail_token(user_id)

    def test_relative_sqlite_database_url_resolves_from_project_root(self):
        with patch.object(repository_module, "DATABASE_URL", "sqlite:///safemailx_app.db"):
            path = repository_module._sqlite_path()

        self.assertEqual(path, ROOT / "safemailx_app.db")

    def test_readiness_reports_local_warnings_without_blocking(self):
        client = TestClient(app)
        headers = self.auth_headers(client)

        with TemporaryDirectory() as temp_dir, patch.dict(
            "os.environ",
            {"SAFEMAILX_PRODUCTION": "false", "SAFEMAILX_REQUIRE_AUTH": "false"},
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
                    "client_id": "safemailx-client-id.apps.googleusercontent.com",
                    "client_secret": "safemailx-client-secret"
                  }
                }
                """,
                encoding="utf-8",
            )
            env = {
                "SAFEMAILX_PRODUCTION": "true",
                "SAFEMAILX_REQUIRE_AUTH": "true",
                "JWT_SECRET": "production-secret-with-at-least-32-characters",
                "SAFEMAILX_ADMIN_EMAIL": "admin@example.com",
                "SAFEMAILX_ADMIN_PASSWORD": "production-password-123",
                "GMAIL_OAUTH_REDIRECT_URI": "https://safemailx.example.com/api/gmail/oauth/callback",
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
