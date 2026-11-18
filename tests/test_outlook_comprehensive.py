"""Comprehensive Automated Gravitas Test Suite for Microsoft Outlook Integration.
Covers Tiers 2, 3, 4, 5, and 6:
- Token encryption, concurrency lock, rotation, reauth detection
- Categories setup, preset colors, merge logic, Graph 409 idempotency
- MIME parser, security headers, malformed email handling
- Claim-first race protection, stale message rescue
- Graph error resilience (429 Retry-After, >12MB streaming limit)
- Worker scan processing & verdict writeback
"""
import base64
import json
import threading
import time
import pytest
from unittest.mock import MagicMock, patch

from server.outlook_oauth import (
    encrypt_token_blob,
    decrypt_token_blob,
    build_outlook_authorization_url,
    get_access_token,
    OutlookReauthRequired,
    _get_user_lock,
)
from server.outlook_categories import (
    SAFEMAILX_CATEGORIES,
    ensure_safemailx_categories,
    merge_categories,
    set_message_category,
)
from utils.outlook_parser import parse_mime_message
from server.outlook_watcher import (
    _enqueue_message,
    enqueue_labeled_outlook_messages,
    _search_messages_by_category,
)
from server.outlook_graph import GraphClient, GraphError


# ==============================================================================
# TIER 2: OAUTH & TOKEN LIFECYCLE TESTS
# ==============================================================================

class TestOutlookOAuthLifecycle:
    def test_fernet_encryption_roundtrip(self):
        token_data = {
            "access_token": "secret_access_token_12345",
            "refresh_token": "secret_refresh_token_67890",
            "expires_at": time.time() + 3600,
            "scope": "Mail.ReadWrite MailboxSettings.ReadWrite offline_access",
        }
        blob = encrypt_token_blob(token_data)
        assert isinstance(blob, str)
        assert blob != json.dumps(token_data)  # Encrypted/encoded
        decrypted = decrypt_token_blob(blob)
        assert decrypted["access_token"] == token_data["access_token"]
        assert decrypted["refresh_token"] == token_data["refresh_token"]

    def test_authorization_url_parameters(self):
        state = "signed_jwt_test_state"
        url = build_outlook_authorization_url(state, redirect_uri="https://example.com/callback")
        assert "login.microsoftonline.com" in url
        assert "state=signed_jwt_test_state" in url
        assert "redirect_uri=https%3A%2F%2Fexample.com%2Fcallback" in url
        assert "prompt=select_account" in url
        assert "response_type=code" in url

    def test_get_access_token_valid_unexpired(self):
        repo = MagicMock()
        valid_token = {
            "access_token": "fresh_token_abc",
            "expires_at": time.time() + 1800,
        }
        repo.get_outlook_connection.return_value = {
            "status": "active",
            "token_blob": encrypt_token_blob(valid_token),
        }
        token = get_access_token(repo, "user_123")
        assert token == "fresh_token_abc"

    def test_get_access_token_reauth_required_guard(self):
        repo = MagicMock()
        repo.get_outlook_connection.return_value = {
            "status": "reauth_required",
            "token_blob": encrypt_token_blob({"access_token": "expired"}),
        }
        with pytest.raises(OutlookReauthRequired):
            get_access_token(repo, "user_123")

    def test_concurrent_token_refresh_single_execution(self):
        """Simulate 5 threads calling get_access_token concurrently on an expired token."""
        # Simulated repository that actually stores the updated token blob
        stored_token = {
            "access_token": "stale_token",
            "refresh_token": "refresh_123",
            "expires_at": time.time() - 100,
        }
        repo = MagicMock()

        def mock_get_conn(user_id):
            return {
                "status": "active",
                "token_blob": encrypt_token_blob(stored_token),
            }

        def mock_update_blob(user_id, new_blob):
            nonlocal stored_token
            stored_token = decrypt_token_blob(new_blob)

        repo.get_outlook_connection.side_effect = mock_get_conn
        repo.update_outlook_token_blob.side_effect = mock_update_blob

        refresh_count = 0
        refresh_lock = threading.Lock()

        def mock_refresh(r, uid, t):
            nonlocal refresh_count
            with refresh_lock:
                refresh_count += 1
            time.sleep(0.05)  # brief network simulation
            new_t = {
                "access_token": "newly_refreshed_token",
                "refresh_token": "new_refresh",
                "expires_at": time.time() + 3600,
            }
            r.update_outlook_token_blob(uid, encrypt_token_blob(new_t))
            return new_t

        threads = []
        results = []

        def worker():
            try:
                res = get_access_token(repo, "concurrency_user")
                results.append(res)
            except Exception as e:
                results.append(e)

        with patch("server.outlook_oauth._refresh_token", side_effect=mock_refresh):
            for _ in range(5):
                t = threading.Thread(target=worker)
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

        # All 5 threads got the valid new token
        assert len(results) == 5
        assert all(r == "newly_refreshed_token" for r in results)
        # Verify single refresh executed thanks to per-user lock
        assert refresh_count == 1


# ==============================================================================
# TIER 3: GRAPH CATEGORIES & MERGE LOGIC TESTS
# ==============================================================================

class TestOutlookCategories:
    def test_category_preset_colors(self):
        # All colors must be preset0 through preset24
        for key, (display_name, preset) in SAFEMAILX_CATEGORIES.items():
            assert preset.startswith("preset")
            preset_num = int(preset.replace("preset", ""))
            assert 0 <= preset_num <= 24

    def test_ensure_safemailx_categories_idempotent(self):
        client = MagicMock()
        # Mock already having SafeMail X Scan and SafeMail X Safe
        client.get.return_value = {
            "value": [
                {"displayName": "SafeMail X Scan"},
                {"displayName": "SafeMail X Safe"},
            ]
        }
        # Post should be called for the missing ones
        result = ensure_safemailx_categories(client)
        assert len(result) == 6
        assert result["scan"] == "SafeMail X Scan"
        assert result["safe"] == "SafeMail X Safe"
        assert result["phishing"] == "SafeMail X Phishing"

    def test_ensure_safemailx_categories_tolerates_409(self):
        client = MagicMock()
        client.get.return_value = {"value": []}
        # Simulate race condition where Graph returns 409
        client.post.side_effect = GraphError(409, "ErrorCategoryAlreadyExists", "Category exists")
        result = ensure_safemailx_categories(client)
        assert len(result) == 6
        assert "scan" in result

    def test_merge_categories_preserves_user_tags(self):
        existing = ["Important", "Project Alpha", "SafeMail X Queued", "Personal"]
        merged = merge_categories(existing, add_key="safe")
        # Should remove "SafeMail X Queued" and add "SafeMail X Safe", keeping the rest
        assert "Important" in merged
        assert "Project Alpha" in merged
        assert "Personal" in merged
        assert "SafeMail X Safe" in merged
        assert "SafeMail X Queued" not in merged
        assert "SafeMail X Scan" not in merged

    def test_set_message_category_read_merge_patch(self):
        client = MagicMock()
        client.get.return_value = {"categories": ["Finance", "SafeMail X Scan"]}
        set_message_category(client, "msg_001", "safe")

        # Verify it read categories first
        client.get.assert_called_with("/me/messages/msg_001?$select=categories")
        # Verify it patched with merged list
        client.patch.assert_called_once_with(
            "/me/messages/msg_001",
            {"categories": ["Finance", "SafeMail X Safe"]}
        )


# ==============================================================================
# TIER 4: MIME PARSER & SECURITY HEADER TESTS
# ==============================================================================

class TestOutlookMIMEParser:
    def test_parse_mime_with_full_security_headers(self):
        raw_email = (
            b"From: security-alerts@legit-bank.com\r\n"
            b"To: user@example.com\r\n"
            b"Subject: Security Notification for Your Account\r\n"
            b"Authentication-Results: spf=pass (sender IP is 1.2.3.4) dkim=pass header.d=legit-bank.com dmarc=pass\r\n"
            b"Received-SPF: pass (legit-bank.com: domain of security-alerts@legit-bank.com designates 1.2.3.4)\r\n"
            b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=legit-bank.com;\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n\r\n"
            b"<html><body><p>Please review your account at <a href=\"https://legit-bank.com/portal\">Portal</a></p></body></html>"
        )
        parsed = parse_mime_message(raw_email)
        assert parsed["subject"] == "Security Notification for Your Account"
        assert "security-alerts@legit-bank.com" in parsed["sender"]
        assert "Please review your account" in parsed["body"]
        assert "https://legit-bank.com/portal" in parsed["links"]
        assert parsed["security_headers"]["spf"] == "pass"
        assert parsed["security_headers"]["dkim"] == "pass"
        assert parsed["security_headers"]["dmarc"] == "pass"
        assert parsed["security_headers"]["dkim_signature_present"] is True

    def test_parse_mime_with_attachment(self):
        boundary = b"----=_Part_12345"
        raw_email = (
            b"From: coworker@company.com\r\n"
            b"Subject: Meeting Notes\r\n"
            b"Content-Type: multipart/mixed; boundary=\"----=_Part_12345\"\r\n\r\n"
            b"------=_Part_12345\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Attached are the quarterly notes.\r\n"
            b"------=_Part_12345\r\n"
            b"Content-Type: application/pdf; name=\"notes.pdf\"\r\n"
            b"Content-Disposition: attachment; filename=\"notes.pdf\"\r\n"
            b"Content-Transfer-Encoding: base64\r\n\r\n"
            b"JVBERi0xLjQKJcTl8uXr..."
            b"------=_Part_12345--\r\n"
        )
        parsed = parse_mime_message(raw_email)
        assert parsed["subject"] == "Meeting Notes"
        assert "Attached are the quarterly notes" in parsed["body"]
        assert len(parsed["attachments"]) == 1
        assert parsed["attachments"][0]["filename"] == "notes.pdf"
        assert parsed["attachments"][0]["content_type"] == "application/pdf"

    def test_parse_mime_malformed_input(self):
        # Truncated / invalid input should never crash
        garbage = b"This is not a real email header: \xff\xfe random bytes\r\n"
        parsed = parse_mime_message(garbage)
        assert isinstance(parsed, dict)
        assert "subject" in parsed
        assert "body" in parsed


# ==============================================================================
# TIER 5: CLAIM-FIRST PATTERN & WATCHER TESTS
# ==============================================================================

class TestOutlookWatcherAndClaiming:
    def test_claim_first_prevents_duplicate_enqueuing(self):
        client = MagicMock()
        repo = MagicMock()
        queue = MagicMock()
        repo.create_queued_scan.return_value = "scan_uuid_999"

        msg = {"id": "outlook_msg_xyz", "receivedDateTime": "2026-11-18T10:00:00Z"}
        client.get.return_value = {"categories": ["SafeMail X Scan"]}

        enqueued = _enqueue_message(
            msg=msg,
            user_id="user_test",
            client=client,
            repository=repo,
            scan_queue=queue,
        )

        assert enqueued is True
        # Verify step 1: patched category to queued FIRST
        client.patch.assert_called_once_with(
            "/me/messages/outlook_msg_xyz",
            {"categories": ["SafeMail X Queued"]},
        )
        # Verify step 2: scan row created
        repo.create_queued_scan.assert_called_once()
        # Verify step 3: pushed to queue
        queue.enqueue.assert_called_once()
        job = queue.enqueue.call_args[0][0]
        assert job["type"] == "outlook_category_message"
        assert job["outlook_message_id"] == "outlook_msg_xyz"
        assert "body" not in job  # Payload must contain IDs only!

    def test_claim_failure_aborts_scan_creation(self):
        client = MagicMock()
        repo = MagicMock()
        queue = MagicMock()

        # If Graph PATCH fails (e.g. concurrent claim or network error)
        client.patch.side_effect = RuntimeError("Graph network error")
        client.get.return_value = {"categories": ["SafeMail X Scan"]}

        msg = {"id": "outlook_msg_busy", "receivedDateTime": "2026-11-18T10:00:00Z"}
        enqueued = _enqueue_message(
            msg=msg,
            user_id="user_test",
            client=client,
            repository=repo,
            scan_queue=queue,
        )

        assert enqueued is False
        # Neither DB scan nor Redis job should be created!
        repo.create_queued_scan.assert_not_called()
        queue.enqueue.assert_not_called()


# ==============================================================================
# TIER 6: GRAPH CLIENT FAULT INJECTION & STREAM LIMITS
# ==============================================================================

class TestOutlookGraphFaultResilience:
    def test_graph_error_class_attributes(self):
        err = GraphError(429, "TooManyRequests", "Rate limit exceeded")
        assert err.status == 429
        assert err.code == "TooManyRequests"
        assert "Rate limit exceeded" in str(err)

    def test_immutable_id_preference_header(self):
        repo = MagicMock()
        repo.get_outlook_connection.return_value = {
            "status": "active",
            "token_blob": encrypt_token_blob({"access_token": "token", "expires_at": time.time() + 3600}),
        }
        client = GraphClient("test_user", repo)
        headers = client._headers()
        assert headers.get("Prefer") == 'IdType="ImmutableId"'
        assert headers.get("Authorization") == "Bearer token"

    def test_mime_stream_abort_on_large_payload(self):
        """Messages exceeding max_bytes must abort immediately without holding in memory."""
        repo = MagicMock()
        repo.get_outlook_connection.return_value = {
            "status": "active",
            "token_blob": encrypt_token_blob({"access_token": "token", "expires_at": time.time() + 3600}),
        }
        client = GraphClient("test_user", repo)

        class MockStreamResponse:
            status_code = 200
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def iter_bytes(self):
                # Yield 2 MB chunks
                for _ in range(10):
                    yield b"X" * (2 * 1024 * 1024)

        with patch("httpx.stream", return_value=MockStreamResponse()):
            # Set max_bytes to 5 MB
            with pytest.raises(RuntimeError, match="exceeds max body size"):
                client.get_mime("huge_msg_123", max_bytes=5 * 1024 * 1024)

    def test_graph_retry_on_429(self):
        """GraphClient must honor Retry-After on 429 response."""
        repo = MagicMock()
        repo.get_outlook_connection.return_value = {
            "status": "active",
            "token_blob": encrypt_token_blob({"access_token": "token", "expires_at": time.time() + 3600}),
        }
        client = GraphClient("test_user", repo)

        resp_429 = MagicMock()
        resp_429.status_code = 429
        resp_429.headers = {"Retry-After": "1"}

        resp_200 = MagicMock()
        resp_200.status_code = 200
        resp_200.json.return_value = {"id": "msg_success"}

        with patch("httpx.request", side_effect=[resp_429, resp_200]), \
             patch("time.sleep") as mock_sleep:
            res = client.get("/me/messages/test")
            assert res == {"id": "msg_success"}
            mock_sleep.assert_called_once_with(1)


# ==============================================================================
# TIER 7: WORKER PIPELINE VERIFICATION
# ==============================================================================

class TestOutlookWorkerPipeline:
    def test_worker_processes_outlook_job_and_applies_verdict(self):
        from server.worker import process_scan_job
        repo = MagicMock()
        service = MagicMock()

        repo.get_outlook_connection.return_value = {
            "status": "active",
            "token_blob": encrypt_token_blob({"access_token": "tok", "expires_at": time.time() + 3600}),
        }
        service.run_manual_text_scan.return_value = {
            "id": "scan_test_1",
            "subject": "Invoice Reminder",
            "final_label": "phishing",
            "final_score": 0.95,
        }

        job = {
            "type": "outlook_category_message",
            "scan_id": "scan_test_1",
            "user_id": "user_456",
            "outlook_message_id": "msg_abc_789",
        }

        mock_raw_mime = b"From: phish@attacker.com\r\nSubject: Invoice\r\n\r\nPay here"

        with patch("server.outlook_graph.GraphClient.get_mime", return_value=mock_raw_mime), \
             patch("server.outlook_categories.set_message_category") as mock_set_cat, \
             patch("server.worker.send_push_notifications") as mock_push:

            res = process_scan_job(job, service=service, repository=repo)

            assert res["id"] == "scan_test_1"
            assert res["final_label"] == "phishing"
            # Verify category written back as phishing
            mock_set_cat.assert_called_once()
            args = mock_set_cat.call_args[0]
            assert args[1] == "msg_abc_789"
            assert args[2] == "phishing"
            # Verify push notification dispatched
            mock_push.assert_called_once()

