# TrustMail AI Mobile + 24/7 Server Scaffold

This scaffold turns the current local bot into a production-shaped app stack:

- React Native Expo mobile app in `trustmail-mobile/`
- FastAPI backend in `src/server/`
- Docker Compose services for API, worker, Gmail watcher, Redis, Nginx, and Qwen/vLLM
- Generic LLM configuration that can point at LM Studio locally or vLLM in production

## Local API Development

```powershell
cd C:\Users\rahul\Desktop\safemailx-ai
.\venv\Scripts\pip.exe install -r requirements.txt
$env:PYTHONPATH="src"
.\venv\Scripts\uvicorn.exe server.app:app --reload --host 127.0.0.1 --port 8080
```

Open:

```text
http://127.0.0.1:8080/docs
```

Auth is disabled by default for local development. To require bearer tokens:

```env
TRUSTMAIL_REQUIRE_AUTH=true
TRUSTMAIL_PRODUCTION=true
JWT_SECRET=replace-with-long-random-secret
TRUSTMAIL_ADMIN_EMAIL=admin@example.com
TRUSTMAIL_ADMIN_PASSWORD=replace-with-strong-password
GMAIL_OAUTH_REDIRECT_URI=https://YOUR_DOMAIN/api/gmail/oauth/callback
```

Generate an encrypted Gmail token key:

```powershell
.\venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Then set `GMAIL_TOKEN_ENCRYPTION_KEY` in `.env`.

The first admin user is bootstrapped from `TRUSTMAIL_ADMIN_EMAIL` and
`TRUSTMAIL_ADMIN_PASSWORD`. When auth is enabled, scans and push tokens are
scoped to the signed-in user.

Production readiness can be checked from the API:

```text
GET /api/readiness
```

The readiness endpoint validates deploy-time configuration such as JWT secret
strength, Google OAuth credentials, HTTPS OAuth callback URL, Gmail token
encryption, SMTP password reset delivery, and Expo push configuration. It also
flags Google OAuth consent verification and app-store provider setup as external
console work that must be completed outside the codebase.

For password reset email delivery, set:

```env
PASSWORD_RESET_URL_BASE=https://YOUR_DOMAIN/reset-password
SMTP_HOST=smtp.your-provider.com
SMTP_PORT=587
SMTP_USERNAME=your-user
SMTP_PASSWORD=your-password
SMTP_FROM_EMAIL=no-reply@your-domain.com
SMTP_USE_TLS=true
```

Without SMTP config, the API falls back to printing the reset link in the server log for local testing.

## Mobile App Development

```powershell
cd trustmail-mobile
npm install
npx expo start
```

For phone testing against your computer, set:

```env
EXPO_PUBLIC_API_BASE_URL=http://YOUR_LAN_IP:8080
```

For an installable Android testing APK, log in to Expo and run the preview
build profile:

```powershell
cd trustmail-mobile
npm run eas:login
npm run build:android:apk
```

The `preview` EAS profile in `trustmail-mobile/eas.json` produces an APK. The
Android app also includes a Settings field for the API server URL; for a phone
on the same Wi-Fi as your computer, set it to:

```text
http://YOUR_LAN_IP:8080
```

Do not use `127.0.0.1` on a physical Android phone, because that points to the
phone itself rather than your computer.

## Quick Local End-to-End Test

From the repo root, start Redis, the API, and the worker:

```powershell
.\scripts\start-local-stack.ps1
```

Skip Docker Redis only if you already have Redis running on `127.0.0.1:6379`:

```powershell
.\scripts\start-local-stack.ps1 -SkipRedis
```

Start the watcher too if you want Gmail polling locally:

```powershell
.\scripts\start-local-stack.ps1 -WithWatcher
```

Start Expo from the same script if needed:

```powershell
.\scripts\start-local-stack.ps1 -WithMobile
```

Then run the local API smoke test:

```powershell
.\scripts\smoke-test-local.ps1
```

If auth is enabled, pass the bootstrap admin credentials:

```powershell
.\scripts\smoke-test-local.ps1 -Email admin@example.com -Password your-admin-password
```

This checks `/api/health`, submits a queued manual scan, and polls until the worker finishes it.
If Redis is offline, it automatically falls back to the direct manual scan endpoint so local bring-up still works.

## 24/7 Server Deployment Shape

```bash
docker compose up -d --build
```

Services:

- `trustmail-api`: FastAPI backend
- `trustmail-worker`: queued scan processor
- `trustmail-gmail-watcher`: 24/7 Gmail polling shell
- `trustmail-llm`: Qwen served through vLLM
- `redis`: job queue
- `nginx`: reverse proxy
- `certbot`: optional HTTPS certificate helper profile

For HTTPS on a VPS:

```bash
docker compose up -d nginx
docker compose --profile https run --rm certbot certonly --webroot -w /var/www/certbot -d YOUR_DOMAIN --email YOU@example.com --agree-tos --no-eff-email
cp deploy/nginx.https.conf.template deploy/nginx.conf
# edit trustmail.example.com to YOUR_DOMAIN in deploy/nginx.conf
docker compose restart nginx
```

## Current Scaffold Status

Implemented now:

- FastAPI health/dashboard/scans/settings endpoints
- manual text scan endpoint
- queued manual scan endpoint backed by Redis
- upload scan endpoint for TXT/EML/HTML/PDF/DOCX/images
- SQLite local scan history adapter
- PostgreSQL scan history adapter for Docker/server deployment
- report PDF/JSON download endpoints
- WebSocket event scaffold
- worker queue entrypoint that completes queued scans
- Gmail watcher queue producer for unread forwarded mail
- worker Gmail reply flow after queued scan completion
- Expo mobile dashboard/scans/new scan/reports/settings UI
- mobile file picker for upload scans
- mobile Settings API server override for Android APK/LAN testing
- mobile report actions backed by short-lived signed PDF/JSON download links
- JWT login with optional production auth enforcement
- local user table with hashed passwords and per-user scan history
- password reset request/confirm endpoints
- SMTP-backed password reset email delivery with local log fallback
- encrypted Gmail token storage when `GMAIL_TOKEN_ENCRYPTION_KEY` is set
- per-user Gmail OAuth start/callback/status endpoints
- mobile Gmail connect/status controls
- mobile password reset request/confirm controls
- Expo push token registration and scan-complete push notification hook
- Docker Compose production skeleton with PostgreSQL, Redis, API, worker, watcher, Nginx, Certbot, and vLLM
- HTTPS Nginx template for Let's Encrypt certificates
- production readiness endpoint for auth, Gmail OAuth, SMTP, encryption, push, and external consent checks

Still to finish in next phase:

- app-store OAuth consent verification and production provider credentials
