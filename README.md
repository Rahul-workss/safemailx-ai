# SafeMail X AI

SafeMail X AI is a local-first phishing and scam analysis stack with:

- FastAPI backend in `src/server/`
- Redis-backed worker queue for asynchronous scans
- Gmail OAuth + label-only Gmail scan flow
- Expo mobile client in `safemailx-mobile/`
- OCR-backed upload and screenshot scanning
- URL checking, SMS scanning, and report downloads
- Optional Google Drive backup and Expo push registration

## Current Product Surface

Backend routes:

- Auth: `/auth/login`, `/auth/register`, `/auth/forgot-password`, `/auth/reset-password`
- Scans: `/api/scans/manual`, `/api/scans/manual/queue`, `/api/scans/sms`, `/api/scans/upload`, `/api/scans/screenshot`, `/api/scans/url`
- Gmail: `/api/gmail/oauth/status`, `/api/gmail/oauth/start`, `/api/gmail/labels/ensure`, `/api/gmail/run-once`
- Reports: `/api/scans/{scan_id}/report-link`, `/api/reports/download`
- Notifications: `/api/notifications/register`, `/api/notifications/preferences`
- Backup: `/api/backup/oauth/status`, `/api/backup/oauth/start`, `/api/backup/sync`, `/api/backup/oauth/disconnect`

Mobile surfaces:

- Email/Gmail label scan
- Manual text scan
- SMS scan
- File upload scan
- Screenshot/image scan
- URL checker
- Report download actions
- Notification preference toggles

## Local Backend Setup

```powershell
cd C:\Users\rahul\Desktop\safemailx-ai
.\venv\Scripts\pip.exe install -r requirements.txt
$env:PYTHONPATH="src"
.\venv\Scripts\uvicorn.exe server.app:app --host 127.0.0.1 --port 8080
```

API docs:

```text
http://127.0.0.1:8080/docs
```

## Worker And Optional Watcher

Run the queue worker:

```powershell
cd C:\Users\rahul\Desktop\safemailx-ai
$env:PYTHONPATH="src"
.\venv\Scripts\python.exe -m server.worker
```

Run the legacy forwarded-email watcher if needed:

```powershell
cd C:\Users\rahul\Desktop\safemailx-ai
$env:PYTHONPATH="src"
.\venv\Scripts\python.exe -m server.gmail_watcher
```

Or use the helper script:

```powershell
.\scripts\start-local-stack.ps1
```

## Mobile Setup

```powershell
cd C:\Users\rahul\Desktop\safemailx-ai\safemailx-mobile
npm install
npx expo start
```

For LAN testing:

```env
EXPO_PUBLIC_API_BASE_URL=http://YOUR_LAN_IP:8080
```

The app also supports changing the API URL from Settings.

## Environment Notes

Common local settings in `.env`:

```env
SAFEMAILX_REQUIRE_AUTH=false
JWT_SECRET=change-me-before-production
SAFEMAILX_ADMIN_EMAIL=admin@safemailx.local
SAFEMAILX_ADMIN_PASSWORD=change-me-before-production
LM_STUDIO_URL=http://127.0.0.1:1234/v1/chat/completions
TESSERACT_CMD=C:\Program Files\Tesseract-OCR\tesseract.exe
GMAIL_OAUTH_REDIRECT_URI=http://127.0.0.1:8080/api/gmail/oauth/callback
```

For production-shaped local testing enable auth and set a real secret:

```env
SAFEMAILX_REQUIRE_AUTH=true
SAFEMAILX_PRODUCTION=true
JWT_SECRET=replace-with-a-long-random-secret-of-at-least-32-characters
SAFEMAILX_ADMIN_EMAIL=admin@example.com
SAFEMAILX_ADMIN_PASSWORD=replace-with-a-strong-password
GMAIL_TOKEN_ENCRYPTION_KEY=generated-fernet-key
```

Generate a Fernet key:

```powershell
.\venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

## Gmail Privacy Model

Connected Gmail accounts use a label-only model:

1. Connect Gmail in the app.
2. Call `Set Up Gmail Labels` to create the SafeMail X labels.
3. Apply `SafeMail X Scan` to a message in Gmail.
4. Call `Run Inbox Scan` in the app, or `POST /api/gmail/run-once`.

SafeMail X only queues explicitly labeled messages for this flow.

## OCR And LLM Requirements

OCR:

- Install Tesseract locally.
- Make it available on `PATH` or set `TESSERACT_CMD`.

LLM:

- LM Studio local server is supported out of the box.
- Set `LM_STUDIO_URL` or `LLM_BASE_URL`.
- If the LLM is unavailable, scans still run in degraded mode and tests continue to pass.

## Validation That Currently Passes

Backend:

```powershell
cd C:\Users\rahul\Desktop\safemailx-ai
$env:PYTHONPATH="src"
.\venv\Scripts\python.exe -m compileall src tests
.\venv\Scripts\python.exe -m unittest discover -s tests
```

Mobile:

```powershell
cd C:\Users\rahul\Desktop\safemailx-ai\safemailx-mobile
npx tsc --noEmit
```

## Smoke Checklist

Use this sequence after bringing the stack up:

1. Log in with the bootstrap admin account.
2. Register a new account.
3. Request a password reset and confirm it.
4. Run a manual text scan.
5. Run an SMS scan.
6. Upload a text or EML file.
7. Upload a screenshot/image scan.
8. Run a URL check.
9. Register a push token or toggle notification preferences.
10. Connect Gmail, ensure labels, and trigger `/api/gmail/run-once`.
11. Download a JSON or PDF report from a finished scan.

## External Work Not Completed In Repo

These are outside the repository and still require provider-console setup:

- Google OAuth consent verification
- production OAuth credentials and redirect URIs
- Expo/EAS build credentials
- production HTTPS domain and certificates
- SMTP provider configuration for production password reset delivery
