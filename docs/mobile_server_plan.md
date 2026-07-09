# SafeMail X AI Mobile + Server Runbook

This document reflects the current working scaffold and validation flow.

## Stack

- FastAPI API in `src/server/app.py`
- Redis-backed worker in `src/server/worker.py`
- Optional Gmail watcher in `src/server/gmail_watcher.py`
- Expo mobile app in `safemailx-mobile/`
- Local SQLite by default, PostgreSQL when `DATABASE_URL` points to Postgres
- OCR through Tesseract
- Local or self-hosted LLM via `LM_STUDIO_URL` or `LLM_BASE_URL`

## Main Features

- Auth: login, register, forgot/reset password
- Scan flows: manual text, queued text, SMS, upload, screenshot/image, URL
- Gmail OAuth with label-only message selection
- Report download links for PDF/JSON
- Push token registration and persisted notification preferences
- Optional Google Drive backup

## Local Development

### API

```powershell
cd C:\Users\rahul\Desktop\safemailx-ai
.\venv\Scripts\pip.exe install -r requirements.txt
$env:PYTHONPATH="src"
.\venv\Scripts\uvicorn.exe server.app:app --reload --host 127.0.0.1 --port 8080
```

### Worker

```powershell
cd C:\Users\rahul\Desktop\safemailx-ai
$env:PYTHONPATH="src"
.\venv\Scripts\python.exe -m server.worker
```

### Optional Watcher

```powershell
cd C:\Users\rahul\Desktop\safemailx-ai
$env:PYTHONPATH="src"
.\venv\Scripts\python.exe -m server.gmail_watcher
```

### Mobile

```powershell
cd C:\Users\rahul\Desktop\safemailx-ai\safemailx-mobile
npm install
npx expo start
```

For phone testing:

```env
EXPO_PUBLIC_API_BASE_URL=http://YOUR_LAN_IP:8080
```

## Auth And Production-Shaped Local Testing

Enable bearer auth:

```env
SAFEMAILX_REQUIRE_AUTH=true
SAFEMAILX_PRODUCTION=true
JWT_SECRET=replace-with-a-long-random-secret-of-at-least-32-characters
SAFEMAILX_ADMIN_EMAIL=admin@example.com
SAFEMAILX_ADMIN_PASSWORD=replace-with-a-strong-password
GMAIL_OAUTH_REDIRECT_URI=https://YOUR_DOMAIN/api/gmail/oauth/callback
```

Generate Gmail token encryption:

```powershell
.\venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Set the output as:

```env
GMAIL_TOKEN_ENCRYPTION_KEY=...
```

## Gmail Flow

Connected Gmail uses explicit user labels:

1. Connect Gmail in the mobile app.
2. Initialize labels from the app or `POST /api/gmail/labels/ensure`.
3. Apply `SafeMail X Scan` inside Gmail.
4. Trigger `POST /api/gmail/run-once` or tap `Run Inbox Scan`.

Returned status payloads now include:

- `privacy_mode`
- `scan_label`
- `queued_label`
- `result_labels`

## Validation Commands

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

## Practical Smoke Test

1. Start API and worker.
2. Log in with `admin@safemailx.local` / `change-me-before-production` if local auth defaults are still active.
3. Register a fresh account.
4. Test forgot/reset password.
5. Submit:
   - manual text scan
   - SMS scan
   - upload file scan
   - screenshot scan
   - URL scan
6. Toggle notification preferences and register push token.
7. Connect Gmail, ensure labels, and run a label scan.
8. Open report download links for a finished scan.

## Notes

- If Redis is unavailable, the mobile app still falls back from queued manual scans to the direct manual endpoint.
- If the LLM is unavailable, scans continue in degraded mode.
- OCR quality still depends on local Tesseract installation and the screenshot quality.
- External provider work remains outside repo scope: Google consent verification, Expo credentials, SMTP production delivery, and production HTTPS/domain setup.
