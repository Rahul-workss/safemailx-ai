<div align="center">

<img src="https://img.shields.io/badge/SafeMail_X_AI-Threat_Intelligence-7c3aed?style=for-the-badge&logo=shield&logoColor=white" />

# SafeMail X AI

**AI-Powered Phishing & Threat Detection Platform**

A production-grade, multi-layer cybersecurity platform that detects phishing, smishing, malicious URLs, and scam content across email, SMS, files, and web — powered by a hybrid AI pipeline of rule-based heuristics, TF-IDF/ML scoring, and a locally-hosted Qwen 2.5 LLM.

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React Native](https://img.shields.io/badge/React_Native-Expo-0ea5e9?style=flat-square&logo=expo&logoColor=white)](https://expo.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Detection Pipeline](#detection-pipeline)
- [Features](#features)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
  - [Docker (Recommended)](#docker-recommended)
  - [Local Development](#local-development)
- [Mobile App Setup](#mobile-app-setup)
- [Environment Variables](#environment-variables)
- [LLM Integration](#llm-integration)
- [Gmail Integration](#gmail-integration)
- [API Reference](#api-reference)
- [Deployment](#deployment)
- [Testing](#testing)
- [Contributing](#contributing)

---

## Overview

SafeMail X AI is a **security-first, local-first** threat detection platform built for individuals and teams who need deep, real-time analysis of suspicious content. Unlike cloud-only solutions, SafeMail X AI can run entirely on your own hardware — your data never leaves your control unless you choose to connect external services.

### What It Detects

| Threat Type | Channels Covered |
|---|---|
| Phishing & Credential Harvesting | Email, SMS, URL, File |
| Smishing (SMS Phishing) | SMS, Screenshots |
| Malicious URL & Redirect Chains | URL Scanner, Email Links |
| Social Engineering Tactics | All channels |
| Malware Delivery Attempts | File uploads, Email attachments |
| Brand Impersonation | Email, SMS, URLs |
| Financial Fraud & Scam Patterns | Email, SMS |
| Data Exfiltration Attempts | File analysis, Email |
| Ransomware Indicators | File uploads |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Mobile App (Expo)                       │
│              React Native · TypeScript · iOS/Android         │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTPS (Cloudflare Tunnel)
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   FastAPI Backend (Python)                    │
│   ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│   │  Auth Layer │  │  Scan Router │  │  Gmail OAuth 2.0 │  │
│   └─────────────┘  └──────┬───────┘  └──────────────────┘  │
│                            │                                  │
│          ┌─────────────────▼─────────────────────┐          │
│          │         Hybrid Detection Engine         │          │
│          │  ┌────────────────────────────────┐   │          │
│          │  │  Layer 1: Rule Engine          │   │          │
│          │  │  (heuristics, YARA, regex)     │   │          │
│          │  ├────────────────────────────────┤   │          │
│          │  │  Layer 2: TF-IDF + ML Model    │   │          │
│          │  │  (scikit-learn, joblib)         │   │          │
│          │  ├────────────────────────────────┤   │          │
│          │  │  Layer 3: LLM (Qwen 2.5 7B)    │   │          │
│          │  │  via LM Studio / OpenAI API    │   │          │
│          │  ├────────────────────────────────┤   │          │
│          │  │  Ensemble Scoring + Smart Veto │   │          │
│          │  └────────────────────────────────┘   │          │
│          └───────────────────────────────────────┘          │
│                                                              │
│   ┌──────────────┐  ┌──────────┐  ┌────────────────────┐   │
│   │  PostgreSQL  │  │  Redis   │  │  Worker Queue       │   │
│   │  (scan data) │  │  (queue) │  │  (async scan jobs)  │   │
│   └──────────────┘  └──────────┘  └────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                         │
          ┌──────────────▼──────────────┐
          │   LM Studio (local)          │
          │   Qwen 2.5 7B Instruct 1M   │
          │   OpenAI-compatible API      │
          └─────────────────────────────┘
```

---

## Detection Pipeline

Every scan goes through a **3-layer hybrid pipeline** with ensemble scoring:

```
Input Content
      │
      ▼
┌─────────────────────────────────────┐
│  LAYER 1 — Rule Engine              │
│  • 50+ heuristic rules              │
│  • YARA pattern matching            │
│  • Domain reputation checks         │
│  • SPF/DKIM/DMARC authentication    │
│  • URL redirect chain analysis      │
│  Score: 0.0 – 1.0                  │
└─────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────┐
│  LAYER 2 — TF-IDF + ML Model        │
│  • Trained phishing corpus          │
│  • Logistic regression classifier   │
│  • N-gram feature extraction        │
│  Score: 0.0 – 1.0                  │
└─────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────┐
│  LAYER 3 — LLM Analysis (Qwen 2.5) │
│  • Forensic 3-phase reasoning       │
│  • Intent classification            │
│  • Social engineering tactic ID     │
│  • Urgency / legitimacy scoring     │
│  Score: 0.0 – 1.0                  │
│  Fallback: graceful (if offline)    │
└─────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────┐
│  ENSEMBLE SCORING + SMART VETO      │
│  • Multi-signal correlation         │
│  • Confidence-weighted blending     │
│  • Hard/soft veto logic             │
│  Final Score: 0 – 100              │
│  Verdict: Legitimate / Suspicious   │
│           / Phishing                │
└─────────────────────────────────────┘
```

---

## Features

### Backend
- **Hybrid AI Detection** — 3-layer pipeline (Rules → TF-IDF ML → Qwen 2.5 LLM) with ensemble scoring
- **Instant Scan Endpoints** — synchronous SMS, URL, and file scans with sub-second rule + ML response
- **Async Queue Processing** — Redis-backed worker for heavy Gmail and manual text scans
- **Gmail OAuth 2.0** — label-only privacy model; only explicitly labeled emails are scanned
- **OCR Support** — Tesseract-powered image/screenshot analysis for visual phishing detection
- **File Analysis** — `.eml`, `.pdf`, `.docx`, `.xlsx`, `.pptx` parsing with link and hash extraction
- **URL Analysis** — full redirect chain resolution, domain age, entropy, typosquatting detection
- **External Threat Intel** — optional Google Safe Browsing, VirusTotal, IPQualityScore integration
- **YARA Rules** — local malware pattern matching on file uploads
- **JWT Authentication** — hardware-backed session tokens, 24h expiry, secure logout
- **Google Drive Backup** — encrypted scan report backup to user's own Drive folder
- **Push Notifications** — Expo push token registration with per-user preferences
- **PDF/JSON Reports** — downloadable forensic scan reports

### Mobile App (React Native / Expo)
- **Dashboard** — live threat feed, security engine status, security bulletin
- **Email Scanner** — Gmail OAuth connect, label setup, batch inbox scan with auto-redirect to results
- **SMS Scanner** — paste or type SMS content, Qwen-powered smishing detection
- **Text Analyzer** — manual text/email body analysis with full forensic breakdown
- **URL Checker** — paste any URL for redirect analysis, reputation check, and LLM verdict
- **File Scanner** — upload documents and images for multi-engine analysis
- **Scan History** — full results history with verdict badges, scores, and signal breakdown
- **Reports** — download JSON or PDF forensic reports per scan
- **Settings** — configurable API URL, notification preferences, account management
- **Help Center** — expandable FAQ with 10+ questions covering all scan types
- **Privacy Policy** — in-app policy with 6 detailed sections

---

## Project Structure

```
safemailx-ai/
├── src/                          # Python backend source
│   ├── engines/                  # Detection engine modules
│   │   ├── hybrid_engine.py      # 3-layer pipeline orchestrator
│   │   ├── llm_analyzer.py       # Qwen 2.5 / LM Studio integration
│   │   ├── instant_scan_engine.py# Fast sync scan engine (SMS, URL, file)
│   │   ├── rule_engine.py        # Heuristic rule evaluation
│   │   ├── url_analyzer.py       # URL reputation + redirect analysis
│   │   ├── sms_engine.py         # SMS-specific feature extraction
│   │   ├── file_analyzer.py      # Document parsing (PDF, DOCX, EML)
│   │   ├── attachment_analyzer.py# Email attachment risk scoring
│   │   ├── domain_trust_arbiter.py # Domain reputation system
│   │   ├── fraud_scam_engine.py  # Financial fraud pattern detection
│   │   ├── identity_risk_engine.py # Identity theft risk signals
│   │   ├── payment_risk_engine.py# Payment/banking fraud signals
│   │   ├── ransomware_malware_engine.py # Malware indicator detection
│   │   ├── data_leak_engine.py   # Sensitive data exposure detection
│   │   ├── intent_classifier.py  # Message intent classification
│   │   ├── threat_taxonomy.py    # Threat categorization system
│   │   ├── smart_veto.py         # Ensemble confidence veto logic
│   │   └── yara_rules/           # YARA malware signature rules
│   │
│   ├── server/                   # FastAPI application
│   │   ├── app.py                # Main FastAPI app + all routes
│   │   ├── worker.py             # Redis queue worker
│   │   ├── scan_service.py       # Scan orchestration service
│   │   ├── inline_scan_service.py# Sync instant scan service
│   │   ├── repository.py         # Database access layer
│   │   ├── schemas.py            # Pydantic request/response models
│   │   ├── auth.py               # JWT authentication
│   │   ├── gmail_oauth.py        # Gmail OAuth 2.0 flow
│   │   ├── gmail_watcher.py      # Gmail label poll watcher
│   │   ├── gmail_labels.py       # Gmail label management
│   │   ├── google_backup.py      # Google Drive backup integration
│   │   ├── notifications.py      # Expo push notification service
│   │   ├── mailer.py             # SMTP email (password reset)
│   │   ├── queue.py              # Redis queue interface
│   │   ├── health.py             # /health endpoint
│   │   └── settings.py           # Server configuration
│   │
│   └── utils/
│       └── config.py             # Centralized env config
│
├── trustmail-mobile/             # React Native (Expo) mobile app
│   ├── App.tsx                   # Main app (~2800 lines, all screens)
│   ├── src/
│   │   ├── api.ts                # Typed API client (all endpoints)
│   │   ├── session.ts            # Secure token management (expo-secure-store)
│   │   └── theme.ts              # Design system tokens
│   └── app.json                  # Expo configuration
│
├── models/                       # Trained ML model artifacts
│   └── phishing_ai_model.joblib  # TF-IDF + Logistic Regression model
│
├── deploy/
│   ├── nginx.conf                # Production Nginx reverse proxy config
│   └── nginx.https.conf.template # HTTPS/TLS Nginx config template
│
├── tests/                        # Backend unit tests
├── docker-compose.yml            # Full stack Docker orchestration
├── Dockerfile                    # Backend container image
└── .env.example                  # Environment variable template
```

---

## Quick Start

### Docker (Recommended)

The fastest way to run the full stack locally.

**Prerequisites:** Docker Desktop, Git

```bash
git clone https://github.com/Rahul-workss/safemailx-ai.git
cd safemailx-ai

# Copy and configure environment
cp .env.example .env
# Edit .env with your settings (see Environment Variables below)

# Start all services (API, Worker, PostgreSQL, Redis, Nginx)
docker compose up -d

# Check everything is healthy
docker compose ps
```

The API will be available at `http://localhost:8080`  
Swagger docs: `http://localhost:8080/docs`

**Verify the stack:**
```bash
curl http://localhost:8080/health
```

### Local Development

**Prerequisites:** Python 3.11+, Redis, PostgreSQL, Node.js 18+

```bash
git clone https://github.com/Rahul-workss/safemailx-ai.git
cd safemailx-ai

# Create virtual environment
python -m venv venv
source venv/bin/activate        # Linux/macOS
# OR
.\venv\Scripts\Activate.ps1     # Windows PowerShell

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env (see Environment Variables)

# Run database migrations (SQLite by default for dev)
export PYTHONPATH=src
python -m server.app              # auto-creates tables on first run

# Start the API server
uvicorn server.app:app --host 0.0.0.0 --port 8080 --reload

# In a second terminal — start the queue worker
export PYTHONPATH=src
python -m server.worker

# Optional: Gmail label watcher
export PYTHONPATH=src
python -m server.gmail_watcher
```

---

## Mobile App Setup

**Prerequisites:** Node.js 18+, Expo CLI, Android Studio or Xcode (or Expo Go app on your device)

```bash
cd trustmail-mobile
npm install

# Configure your API URL
echo 'EXPO_PUBLIC_API_BASE_URL=http://YOUR_LOCAL_IP:8080' > .env

# Start Expo dev server
npx expo start
```

Scan the QR code with **Expo Go** (Android/iOS) or press `a` for Android emulator.

> **Tip:** The API URL can also be changed at runtime from the app's Settings screen.

---

## Environment Variables

Copy `.env.example` to `.env` and configure:

```env
# ─── Core ─────────────────────────────────────────────────────
SAFEMAILX_API_HOST=0.0.0.0
SAFEMAILX_API_PORT=8080
BACKEND_URL=https://your-domain.com

# ─── Database ─────────────────────────────────────────────────
DATABASE_URL=postgresql://trustmail:trustmail@postgres:5432/trustmail
# Or use SQLite for local dev:
# DATABASE_URL=sqlite:///./safemailx_app.db

# ─── Redis ────────────────────────────────────────────────────
REDIS_URL=redis://127.0.0.1:6379/0

# ─── Authentication ───────────────────────────────────────────
JWT_SECRET=your-long-random-secret-min-32-chars
JWT_EXPIRES_MINUTES=1440
FEATURE_REFRESH_TOKEN_ENABLED=true
REFRESH_TOKEN_EXPIRES_DAYS=30
SAFEMAILX_REQUIRE_AUTH=true
SAFEMAILX_ADMIN_EMAIL=admin@yourdomain.com
SAFEMAILX_ADMIN_PASSWORD=strong-password-here

# ─── LLM (Qwen 2.5 via LM Studio) ───────────────────────────
LLM_BASE_URL=http://host.docker.internal:1234/v1/chat/completions
LLM_PROVIDER=openai
LLM_MODEL=qwen2.5-7b-instruct-1m
LLM_TIMEOUT=300

# ─── OCR ──────────────────────────────────────────────────────
TESSERACT_CMD=tesseract
# Windows: TESSERACT_CMD=C:\Program Files\Tesseract-OCR\tesseract.exe

# ─── Gmail OAuth ──────────────────────────────────────────────
GMAIL_OAUTH_REDIRECT_URI=https://your-domain.com/api/gmail/oauth/callback
GMAIL_TOKEN_ENCRYPTION_KEY=your-fernet-key

# ─── Threat Intelligence (Optional) ──────────────────────────
SAFE_BROWSING_API_KEY=your-google-safe-browsing-key
VIRUSTOTAL_API_KEY=your-virustotal-key
IPQUALITYSCORE_API_KEY=your-ipqs-key

# ─── Email / SMTP (Password Reset) ───────────────────────────
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your@email.com
SMTP_PASSWORD=your-app-password
SMTP_FROM_EMAIL=noreply@yourdomain.com

# ─── Notifications ────────────────────────────────────────────
EXPO_ACCESS_TOKEN=your-expo-access-token
```

**Generate a Fernet encryption key:**
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

---

## LLM Integration

SafeMail X AI uses **Qwen 2.5 7B Instruct** as its deep reasoning layer via an OpenAI-compatible API. The system **always tries LLM first** and gracefully falls back to TF-IDF + rules if unavailable.

### Setup with LM Studio (Local)

1. Download [LM Studio](https://lmstudio.ai/)
2. Load the `qwen2.5-7b-instruct-1m` model
3. Start the local server on port `1234`
4. Set in `.env`:
   ```env
   LLM_BASE_URL=http://127.0.0.1:1234/v1/chat/completions
   LLM_MODEL=qwen2.5-7b-instruct-1m
   ```

### Setup for Cloud Deployment (Render, Railway, etc.)

Since cloud deployments cannot reach your local LM Studio directly, expose it via Cloudflare Tunnel:

```yaml
# ~/.cloudflared/config.yml
tunnel: YOUR_TUNNEL_ID
credentials-file: ~/.cloudflared/YOUR_TUNNEL_ID.json

ingress:
  - hostname: api.yourdomain.com
    service: http://localhost:8080
  - hostname: llm.yourdomain.com    # ← exposes LM Studio publicly
    service: http://localhost:1234
  - service: http_status:404
```

Then set on your cloud provider:
```env
LLM_BASE_URL=https://llm.yourdomain.com/v1/chat/completions
```

### Fallback Behavior

If LLM is offline:
- Rule engine + TF-IDF ML model still run
- Scan completes and returns results
- Response includes `"llm_available": false`
- Mobile UI shows `Qwen –` indicator

---

## Gmail Integration

SafeMail X AI uses a **label-only privacy model** — it only scans emails you explicitly mark:

```
1. Connect Gmail  →  OAuth 2.0 consent (read-only access)
2. Set Up Labels  →  Creates "SafeMail X Scan" label in Gmail
3. Label emails   →  Apply "SafeMail X Scan" to suspicious emails in Gmail app
4. Run Scan       →  App fetches and analyzes only labeled messages
```

**No continuous inbox monitoring.** Your inbox is never automatically scanned. Only messages you explicitly label are processed.

---

## API Reference

Full interactive docs available at `/docs` (Swagger UI) when running.

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/login` | Login, returns JWT |
| `POST` | `/api/auth/register` | Register new account |
| `POST` | `/api/auth/forgot-password` | Send password reset email |
| `POST` | `/api/auth/reset-password` | Reset with token |
| `POST` | `/api/auth/logout` | Invalidate session |

### Instant Scans (Synchronous)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/instant/sms` | SMS/smishing analysis |
| `POST` | `/api/instant/url` | URL threat check |
| `POST` | `/api/instant/file` | File/document analysis |

### Full Scans (Async Queue)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scans/manual` | Synchronous text/email scan |
| `POST` | `/api/scans/manual/queue` | Queue text/email scan |
| `POST` | `/api/scans/upload` | File upload scan |
| `POST` | `/api/scans/screenshot` | Image/OCR scan |
| `GET`  | `/api/scans` | List scan history |
| `GET`  | `/api/scans/{id}` | Get scan details |

### Gmail
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/gmail/oauth/status` | Connection status |
| `GET`  | `/api/gmail/oauth/start` | Begin OAuth flow |
| `POST` | `/api/gmail/labels/ensure` | Create SafeMail X labels |
| `POST` | `/api/gmail/run-once` | Scan labeled messages |

### Reports & Misc
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/scans/{id}/report-link` | Get report download URL |
| `POST` | `/api/notifications/register` | Register push token |
| `GET`  | `/api/backup/oauth/status` | Drive backup status |
| `POST` | `/api/backup/sync` | Trigger Drive backup |
| `GET`  | `/health` | API health check |

---

## Deployment

### Production with Docker + Cloudflare Tunnel

```bash
# 1. Clone and configure
git clone https://github.com/Rahul-workss/safemailx-ai.git
cd safemailx-ai
cp .env.example .env
# Edit .env with production values

# 2. Start the stack
docker compose up -d

# 3. Run tunnel (install cloudflared first)
cloudflared tunnel run
```

### Render / Railway / Fly.io

1. Connect GitHub repo
2. Set all environment variables from the table above
3. Set build command: (none, uses Dockerfile)
4. Set start command: `uvicorn server.app:app --host 0.0.0.0 --port 8080`
5. Add a Redis add-on for queue support
6. Add a PostgreSQL add-on for persistence

> **Important:** Set `LLM_BASE_URL` to your Cloudflare Tunnel URL for LM Studio if you want LLM analysis on cloud deployments.

### Production Persistence Requirements

- `DATABASE_URL` must point to a persistent managed Postgres instance in production.
- `REDIS_URL` must point to a persistent managed Redis instance in production.
- The SQLite fallback is for local development only. On platforms with ephemeral disks, local SQLite data can disappear after restarts, redeploys, or idle cycling.
- After any first production deployment or database move, manually restart or redeploy the service once and confirm existing users and scan history still exist afterward.

### Session Refresh Controls

- `FEATURE_REFRESH_TOKEN_ENABLED=true` enables silent session renewal for supported clients.
- `REFRESH_TOKEN_EXPIRES_DAYS=30` controls the refresh-token lifetime.
- Set `FEATURE_REFRESH_TOKEN_ENABLED=false` to fall back to the older hard-expiry behavior if you need to disable refresh-token rollout quickly.

### Mobile — EAS Build (Production APK/IPA)

```bash
cd trustmail-mobile
npm install -g eas-cli
eas login
eas build --platform android   # or ios
eas submit                     # submit to app stores
```

---

## Testing

### Backend Tests

```bash
# Run all unit tests
export PYTHONPATH=src
python -m unittest discover -s tests -v

# Syntax check all modules
python -m compileall src tests

# Quick smoke test against running API
curl -s http://localhost:8080/health | python -m json.tool
```

### Mobile Tests (TypeScript)

```bash
cd trustmail-mobile
npx tsc --noEmit
```

### Manual Smoke Checklist

After bringing the stack up, verify these flows work end-to-end:

- [ ] Register a new account
- [ ] Log in and receive JWT
- [ ] Request and complete password reset
- [ ] Run a manual text scan
- [ ] Run an instant SMS scan  
- [ ] Run an instant URL scan
- [ ] Upload a `.eml` file scan
- [ ] Upload a screenshot image scan
- [ ] Connect Gmail and run label scan
- [ ] Download a PDF report
- [ ] Register push notification token
- [ ] Verify LLM shows `"llm_available": true`

---

## Contributing

Contributions are welcome! Please follow these steps:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/your-feature-name`
3. **Commit** with a clear message: `git commit -m "feat(engine): add X detection"`
4. **Push** to your fork: `git push origin feature/your-feature-name`
5. **Open a Pull Request** against `main`

### Commit Message Format
```
type(scope): description

Types: feat, fix, docs, refactor, test, chore
Scopes: engine, api, mobile, auth, llm, ui
```

---

## Production Deployment

When deploying SafeMail X to a production environment (e.g. Render, Koyeb, AWS), you **must** configure persistent database connections. The default behavior is to use ephemeral SQLite/in-memory data for local development, which will be wiped on every container restart.

**Required Environment Variables for Production:**
- `DATABASE_URL`: Must point to a persistent, managed PostgreSQL instance (e.g., `postgresql://user:pass@host/dbname`). If left unset, it falls back to a local SQLite file which **will cause data loss** on restart.
- `REDIS_URL`: Must point to a persistent, managed Redis instance.

**Silent Refresh Token Flow:**
The backend supports a silent refresh-token flow to prevent users from being forcibly logged out every 24 hours.
- `FEATURE_REFRESH_TOKEN_ENABLED` (default: `true`): Enables the `/auth/refresh` endpoint.
- `REFRESH_TOKEN_EXPIRES_DAYS` (default: `30`): Lifetime of the refresh token. Access tokens still hard-expire frequently (`JWT_EXPIRES_MINUTES`).

---

## Security

SafeMail X AI is built security-first:

- **Session tokens** stored in hardware-encrypted Keychain / Android Keystore via `expo-secure-store`
- **Gmail tokens** encrypted with Fernet (AES-128) before database storage
- **No plaintext credentials** anywhere in storage or logs
- **JWT 24h expiry** with explicit logout support
- **Rate limiting** on auth endpoints
- **Read-only Gmail access** — no write permissions ever requested

To report a security vulnerability, please email the maintainer directly rather than opening a public issue.

---

## License

[MIT](LICENSE) © 2025 SafeMail X AI Contributors

---

<div align="center">

**Built with ❤️ for a safer digital world**

[Report Bug](https://github.com/Rahul-workss/safemailx-ai/issues) · [Request Feature](https://github.com/Rahul-workss/safemailx-ai/issues) · [Documentation](https://github.com/Rahul-workss/safemailx-ai/wiki)

</div>
