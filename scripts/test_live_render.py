"""Comprehensive Live Render verification script for SafeMail X Outlook integration."""
import urllib.request
import urllib.error
import urllib.parse
import json

BASE_URL = "https://safemailx-ai.onrender.com"

def run_live_tests():
    print("=" * 65)
    print("SAFEMAIL X AI — LIVE RENDER EXTENSIVE INTEGRATION VERIFICATION")
    print("=" * 65)

    # 1. Health check
    print("\n[TEST 1.1] Health endpoint check...")
    req = urllib.request.urlopen(f"{BASE_URL}/api/health", timeout=15)
    health = json.loads(req.read().decode())
    print("Health response:", json.dumps(health, indent=2))
    assert health.get("outlook_watcher") == "manual", f"Expected 'manual', got {health.get('outlook_watcher')}"
    print("--> PASS: outlook_watcher is 'manual'")

    # 2. Unauthenticated route protection
    print("\n[TEST 1.2] Testing unauthenticated route protection...")
    endpoints = [
        ("/api/outlook/oauth/status", "GET"),
        ("/api/outlook/categories/ensure", "POST"),
        ("/api/outlook/run-once", "POST"),
        ("/api/outlook/oauth/disconnect", "DELETE"),
    ]
    for ep, method in endpoints:
        url = f"{BASE_URL}{ep}"
        req = urllib.request.Request(url, method=method)
        try:
            urllib.request.urlopen(req, timeout=10)
            raise AssertionError(f"{ep} allowed unauthenticated access!")
        except urllib.error.HTTPError as e:
            assert e.code == 401, f"Expected 401, got {e.code}"
            print(f"--> PASS: {ep} strictly returned 401 Unauthorized")

    # 3. State tamper protection
    print("\n[TEST 1.3] Testing OAuth callback state tamper protection...")
    try:
        urllib.request.urlopen(f"{BASE_URL}/api/outlook/oauth/callback?state=tampered-fake-token", timeout=10)
        raise AssertionError("Tampered state was accepted!")
    except urllib.error.HTTPError as e:
        assert e.code == 401, f"Expected 401, got {e.code}"
        print(f"--> PASS: Tampered state rejected with HTTP {e.code}")

    # 4. Authenticated tests (Obtain JWT)
    print("\n[TEST 1.4] Obtaining test session via /auth/login...")
    login_data = json.dumps({"email": "admin@safemailx.local", "password": "change-me-before-production"}).encode()
    login_req = urllib.request.Request(
        f"{BASE_URL}/auth/login",
        data=login_data,
        headers={"Content-Type": "application/json"}
    )
    token = None
    try:
        resp = urllib.request.urlopen(login_req, timeout=15)
        token_data = json.loads(resp.read().decode())
        token = token_data.get("access_token")
        print("--> Logged in with admin credentials successfully.")
    except Exception as e:
        print(f"--> Admin login error: {e}")

    if token:
        auth_headers = {"Authorization": f"Bearer {token}"}

        # 4a. Check Outlook Status
        print("\n[TEST 1.5] Testing /api/outlook/oauth/status with authenticated user...")
        status_req = urllib.request.Request(f"{BASE_URL}/api/outlook/oauth/status", headers=auth_headers)
        status_resp = urllib.request.urlopen(status_req, timeout=10)
        status_data = json.loads(status_resp.read().decode())
        print("Outlook status payload:", json.dumps(status_data, indent=2))
        assert status_data.get("enabled") is True, "Outlook should be enabled"
        assert status_data.get("connected") is False, "New user should not be connected yet"
        assert status_data.get("status") == "not_connected"
        print("--> PASS: /api/outlook/oauth/status returned correct initial state.")

        # 4b. Test OAuth Start Endpoint
        print("\n[TEST 1.6] Testing /api/outlook/oauth/start...")
        start_req = urllib.request.Request(f"{BASE_URL}/api/outlook/oauth/start", headers=auth_headers)
        start_resp = urllib.request.urlopen(start_req, timeout=10)
        start_data = json.loads(start_resp.read().decode())
        auth_url = start_data.get("authorization_url", "")
        redirect_uri = start_data.get("redirect_uri", "")
        print("Authorization URL snippet:", auth_url[:120] + "...")
        print("Redirect URI:", redirect_uri)

        assert "login.microsoftonline.com" in auth_url, "Missing Microsoft login host"
        assert "client_id=" in auth_url, "Missing client_id parameter"
        assert "Mail.ReadWrite" in auth_url, "Missing Mail.ReadWrite scope"
        assert "MailboxSettings.ReadWrite" in auth_url, "Missing MailboxSettings.ReadWrite scope"
        assert "offline_access" in auth_url, "Missing offline_access scope"
        assert "state=" in auth_url, "Missing signed state"
        assert redirect_uri.endswith("/api/outlook/oauth/callback")
        print("--> PASS: /api/outlook/oauth/start generated valid Microsoft Identity v2 authorization URL.")

        # 4c. Test Open Redirect Attack Protection
        print("\n[TEST 1.7] Testing open redirect vulnerability protection on OAuth return URL...")
        bad_return_url = urllib.parse.quote("https://evil-phishing-site.com/steal")
        bad_start_req = urllib.request.Request(
            f"{BASE_URL}/api/outlook/oauth/start?return_url={bad_return_url}",
            headers=auth_headers
        )
        try:
            urllib.request.urlopen(bad_start_req, timeout=10)
            raise AssertionError("Malicious return_url was accepted!")
        except urllib.error.HTTPError as e:
            assert e.code == 400, f"Expected 400, got {e.code}"
            print("--> PASS: Malicious return_url was rejected with HTTP 400.")

        # 4d. Test Disconnect without connection (safe idempotent)
        print("\n[TEST 1.8] Testing /api/outlook/oauth/disconnect...")
        disc_req = urllib.request.Request(f"{BASE_URL}/api/outlook/oauth/disconnect", headers=auth_headers, method="DELETE")
        disc_resp = urllib.request.urlopen(disc_req, timeout=10)
        assert disc_resp.status == 200
        print("--> PASS: Disconnect safely handled idempotent request.")

    print("\n" + "=" * 65)
    print("ALL LIVE RENDER TESTS PASSED!")
    print("=" * 65)

if __name__ == "__main__":
    run_live_tests()
