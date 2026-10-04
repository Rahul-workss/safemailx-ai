<div align="center">

<img src="https://img.shields.io/badge/SafeMail_X_AI-Threat_Intelligence-7c3aed?style=for-the-badge&logo=shield&logoColor=white" />

# SafeMail X AI

**AI-Powered Phishing, Scam & Identity Threat Detection Platform**

A production-grade, multi-layer cybersecurity platform that detects phishing, smishing, vishing, malicious QR codes, scam calls, and identity fraud — across email, SMS, calls, files, QR codes, and web. Powered by a hybrid AI pipeline of rule-based heuristics, TF-IDF/ML scoring, Whisper audio transcription, and a locally-hosted Qwen 2.5 LLM.

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React Native](https://img.shields.io/badge/React_Native-Expo_SDK_54-0ea5e9?style=flat-square&logo=expo&logoColor=white)](https://expo.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://www.docker.com/)
[![Railway](https://img.shields.io/badge/Deployed_on-Railway-0B0D0E?style=flat-square&logo=railway&logoColor=white)](https://railway.app/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

</div>

---

## Table of Contents

- [Overview](#overview)
- [What It Detects](#what-it-detects)
- [Architecture](#architecture)
- [Detection Pipeline](#detection-pipeline)
- [Features](#features)
  - [Backend Engines](#backend-engines)
  - [Mobile App](#mobile-app-react-native--expo)
  - [Call Analyzer](#call-analyzer--vishing-detection)
  - [QR Scanner](#qr-scanner--document-verifier)
  - [Government Document Verifier](#government-document-verifier)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [Mobile App Setup](#mobile-app-setup)
- [Environment Variables](#environment-variables)
- [LLM Integration](#llm-integration)
- [Gmail Integration](#gmail-integration)
- [API Reference](#api-reference)
- [Deployment](#deployment)
- [Security](#security)
- [Contributing](#contributing)

---

## Overview

SafeMail X AI is a **security-first, local-first** threat detection platform built for individuals and teams who need deep, real-time analysis of suspicious content. Unlike cloud-only solutions, SafeMail X AI can run entirely on your own hardware — your data never leaves your control unless you choose to connect external services.

The platform has evolved from a phishing email detector into a comprehensive **multi-vector fraud and identity threat intelligence system**, now including:

- 📞 **Call Analyzer** — detect scam calls by describing or recording what the caller said
- 📷 **Dual-Mode QR Scanner** — security-aware QR scanning + live government document verification
- 🪪 **Aadhaar QR Decoder** — parse and extract demographic data from Secure QR codes offline
- 🌐 **Scam Intelligence Engine** — classify calls, SMS, and emails against known Indian cybercrime patterns
- 🔊 **Vishing / Audio Analysis** — Whisper-powered call transcription with threat scoring
- 💬 **WhatsApp & Telegram Webhooks** — process forwarded suspicious messages from chat platforms

---

## What It Detects

| Threat Type | Channels Covered |
|---|---|
| Phishing & Credential Harvesting | Email, SMS, URL, File |
| Smishing (SMS Phishing) | SMS, Screenshots |
| **Vishing (Voice/Call Scams)** | **Call Audio, Call Description** |
| Malicious QR Codes | **QR Scanner, Uploaded Images** |
| **UPI Payment Fraud** | **QR Codes, SMS** |
| Malicious URL & Redirect Chains | URL Scanner, Email Links, QR Codes |
| Social Engineering Tactics | All channels |
| Malware Delivery Attempts | File uploads, Email attachments |
| Brand Impersonation | Email, SMS, URLs, QR |
| Financial Fraud & Scam Patterns | Email, SMS, **Calls** |
| Data Exfiltration Attempts | File analysis, Email |
| Ransomware Indicators | File uploads |
| **Identity Document Fraud** | **QR Scanner (Aadhaar, DigiLocker)** |
| **Digital Arrest Scams** | **Call Analyzer, SMS** |
| **Fake Government Notices** | **QR Scanner, Email** |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Mobile App (Expo SDK 54)                        │
│           React Native · TypeScript · Liquid Glass UI                │
│                                                                       │
│  [Dashboard] [SMS] [URL] [File] [QR Scanner] [Call Analyzer] [Email] │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ HTTPS (Railway / Cloudflare Tunnel)
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    FastAPI Backend (Python 3.11+)                     │
│   ┌─────────────┐  ┌──────────────┐  ┌──────────────────────────┐   │
│   │  Auth Layer │  │  Scan Router │  │  Gmail OAuth 2.0          │   │
│   │  (JWT+OTP)  │  │              │  │  WhatsApp / Telegram Hook │   │
│   └─────────────┘  └──────┬───────┘  └──────────────────────────┘   │
│                            │                                          │
│          ┌─────────────────▼──────────────────────────┐             │
│          │           Hybrid Detection Engine            │             │
│          │  ┌─────────────────────────────────────┐   │             │
│          │  │  Layer 1: Rule Engine               │   │             │
│          │  │  (heuristics, YARA, regex, bloom)   │   │             │
│          │  ├─────────────────────────────────────┤   │             │
│          │  │  Layer 2: TF-IDF + ML Model         │   │             │
│          │  │  (scikit-learn logistic regression) │   │             │
│          │  ├─────────────────────────────────────┤   │             │
│          │  │  Layer 3: LLM (Qwen 2.5 7B)         │   │             │
│          │  │  via LM Studio / OpenAI-compat API  │   │             │
│          │  ├─────────────────────────────────────┤   │             │
│          │  │  Ensemble Scoring + Smart Veto       │   │             │
│          │  └─────────────────────────────────────┘   │             │
│          └────────────────────────────────────────────┘             │
│                                                                       │
│  ┌──────────────────┐  ┌────────────────┐  ┌─────────────────────┐  │
│  │  QR Analyzer     │  │ Vishing Analyzer│  │ Scam Intelligence   │  │
│  │  (ZXing+pyzbar+  │  │ (Whisper STT + │  │ (Call + SMS fraud   │  │
│  │   OpenCV+ZBar)   │  │  LLM scoring)  │  │  pattern matching)  │  │
│  └──────────────────┘  └────────────────┘  └─────────────────────┘  │
│                                                                       │
│  ┌────────────────┐  ┌───────────┐  ┌────────────────────────────┐  │
│  │  Aadhaar QR    │  │  PostgreSQL│  │  Worker Queue (Redis)      │  │
│  │  Decoder       │  │  + Redis  │  │  (async scan jobs)         │  │
│  └────────────────┘  └───────────┘  └────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                           │
            ┌──────────────▼──────────────┐
            │   LM Studio (local/tunnel)   │
            │   Qwen 2.5 7B Instruct 1M   │
            │   OpenAI-compatible API      │
            └─────────────────────────────┘
```

---

## Detection Pipeline

### Email / SMS / Text — 3-Layer Hybrid Pipeline

```
Input Content
      │
      ▼
┌─────────────────────────────────────┐
│  LAYER 1 — Rule Engine              │
│  • 50+ heuristic rules              │
│  • YARA pattern matching            │
│  • Domain reputation (Bloom filter) │
│  • SPF/DKIM/DMARC authentication   │
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

### QR Code — Multi-Decoder Pipeline

```
Camera / Uploaded Image
         │
         ▼
┌─────────────────────────────────────┐
│  Phase 1: Full-Resolution Decode    │
│  • ZXing (primary), pyzbar,         │
│    OpenCV QR decoder                │
│  • No size cap — raw full res        │
└─────────────────────────────────────┘
         │ if failed
         ▼
┌─────────────────────────────────────┐
│  Phase 2: Preprocessing Strategies  │
│  • Grayscale, CLAHE, adaptive       │
│    threshold, unsharp mask          │
│  • Gaussian blur (Moiré handling)   │
│  • Capped at 3000px for memory      │
│  • Generator-based (lazy eval)      │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│  Payload Classifier                 │
│  URL · UPI · AADHAAR_SECURE ·       │
│  AADHAAR_XML · DIGILOCKER_DOC ·     │
│  COWIN · CBSE · DRIVING_LICENSE ·   │
│  WIFI · VCARD · EMAIL · SMS ·       │
│  PHONE · GEO · TEXT · UNKNOWN       │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│  Router                             │
│  ┌────────────┐  ┌───────────────┐  │
│  │  URL →     │  │  UPI →        │  │
│  │  Phishing  │  │  Fraud check  │  │
│  │  Pipeline  │  │  + Parse      │  │
│  └────────────┘  └───────────────┘  │
│  ┌────────────┐  ┌───────────────┐  │
│  │  Aadhaar → │  │  Gov Doc →    │  │
│  │  Offline   │  │  DigiLocker / │  │
│  │  Decoder   │  │  Portal route │  │
│  └────────────┘  └───────────────┘  │
└─────────────────────────────────────┘
```

---

## Features

### Backend Engines

- **Hybrid AI Detection** — 3-layer pipeline (Rules → TF-IDF ML → Qwen 2.5 LLM) with ensemble scoring
- **Instant Scan Endpoints** — synchronous SMS, URL, email, and file scans with sub-second response
- **Async Queue Processing** — Redis-backed worker for heavy Gmail and manual text scans
- **QR Code Analysis Engine** — multi-decoder (ZXing + pyzbar + OpenCV), multi-strategy preprocessing, handles PVC card photos taken by phone camera
- **Aadhaar Secure QR Decoder** — parses UIDAI's big-integer gzip QR format; extracts name, DOB, gender, address, masked UID, email/mobile link status, and JPEG photo; all offline, no PII stored
- **Scam Intelligence Engine** — classifies calls and messages against Indian cybercrime archetypes (CBI/digital-arrest, OTP scam, KYC freeze, lottery/prize, fake tech support, etc.)
- **Vishing / Audio Analyzer** — Whisper-powered audio transcription; threat-scores call recordings or typed call descriptions using LLM
- **URL Analysis** — full redirect chain resolution, domain age (RDAP), entropy, typosquatting (Levenshtein), punycode/homograph detection, IP-based URL detection
- **External Threat Intel** — optional Google Safe Browsing, VirusTotal, IPQualityScore integration
- **OCR Support** — Tesseract-powered image/screenshot analysis for visual phishing detection
- **File Analysis** — `.eml`, `.pdf`, `.docx`, `.xlsx`, `.pptx` parsing with link and hash extraction
- **YARA Rules** — local malware pattern matching on file uploads
- **Prompt Injection Guard** — protects the LLM layer from adversarial prompt injections in scanned content
- **Adaptive Trust Engine** — builds per-sender behavioral baseline to reduce false positives over time
- **Campaign Correlator** — links related scan results to detect coordinated phishing campaigns
- **Gmail OAuth 2.0** — label-only privacy model; only explicitly labeled emails are scanned
- **WhatsApp Webhook** — receive and analyze forwarded suspicious messages directly from WhatsApp
- **Telegram Webhook** — receive and analyze suspicious messages forwarded to a Telegram bot
- **Google Drive Backup** — encrypted scan report backup to user's own Drive folder
- **JWT Authentication** — hardware-backed session tokens, 24h expiry, OTP registration, silent refresh
- **Push Notifications** — Expo push token registration with per-user preferences
- **PDF/JSON Reports** — downloadable forensic scan reports

### Mobile App (React Native / Expo)

The app uses a **Liquid Glass / Glassmorphism** design system (`theme.ts`) — dark glass cards, blur backgrounds, gradient borders, and smooth spring animations throughout.

- **Dashboard** — live threat feed, engine status indicators (LLM, ML, Rules), security bulletin
- **Email Scanner** — Gmail OAuth connect, label setup wizard, batch inbox scan
- **SMS Analyzer** — paste or type SMS content, instant smishing verdict
- **Text Analyzer** — manual text/email body analysis with full forensic breakdown
- **URL Checker** — paste any URL for redirect analysis, reputation check, and LLM verdict
- **File Scanner** — upload documents and images for multi-engine analysis
- **📞 Call Analyzer** — describe or record a suspicious call; AI classifies scam type and risk
- **📷 QR Scanner** — dual-mode: Scan QR (security-aware) + Verify Document (gov doc analysis)
- **Scan History** — full results history with verdict badges, scores, and signal breakdown
- **Reports** — download JSON or PDF forensic reports per scan
- **Settings** — configurable API URL, notification preferences, account management
- **Help Center** — expandable FAQ covering all scan types
- **Privacy Policy** — in-app policy with detailed sections

---

### Call Analyzer — Vishing Detection

The Call Analyzer is a dedicated screen for detecting **phone scams and vishing attacks** in real time.

**Two input modes:**
1. **Describe the Call** — tap chips or fill a structured form describing what the caller claimed, what they asked you to do (OTP, card CVV, Aadhaar number, install an app, share screen, transfer money), and the caller's organization
2. **Record / Upload Audio** — record the call live or upload an audio file; Whisper transcribes it automatically and feeds the transcript to the LLM

**What it analyzes:**
- Caller's claimed organization and legitimacy
- Requested actions (especially dangerous ones: OTP, install app, screen share)
- Urgency and fear tactics (fake arrest warrants, account suspension, etc.)
- Match against known Indian cybercrime patterns (CBI/ED impersonation, digital arrest, KYC freeze, lottery, etc.)
- LLM reasoning about social engineering tactics used

**Output:**
- **Risk band**: CRITICAL / HIGH / MEDIUM / LOW
- **Scam archetype**: e.g., "Digital Arrest Scam (CBI Impersonation)"
- **Danger signals** list with plain-language explanations of why each element is suspicious
- **Recommended action**: e.g., "Hang up immediately. Do NOT comply. Report on cybercrime.gov.in"
- **Safe callback number** from official government directory (when applicable)

**Backend endpoint:** `POST /api/voice/analyze-call`

---

### QR Scanner — Dual Mode

The QR Scanner has two modes selectable via an **animated sliding pill toggle**:

#### Mode 1: Scan QR (Security-Aware)
General-purpose QR scanning with full threat analysis.

| QR Type | Analysis |
|---------|----------|
| **URL** | Full phishing pipeline — redirects, reputation, typosquatting, Safe Browsing, VirusTotal, LLM verdict, risk score 0–100 |
| **UPI Payment** | Parses VPA, payee name, amount, note; flags malformed or suspicious UPI strings |
| **Wi-Fi** | Displays SSID, security type, password; flags open networks and suspicious SSIDs |
| **vCard/Contact** | Displays name, phone, email; flags suspicious embedded URLs |
| **Email/SMS/Phone** | Displays content safely without auto-triggering |
| **Location** | Shows coordinates without auto-opening maps |
| **Text** | Displays raw content; runs through scam text heuristics |
| **Deep Links / Custom Schemes** | Flagged as potentially dangerous; never auto-opened |

**Smart cross-mode routing:** If you scan a government document QR while in Scan QR mode, the app detects it and offers to switch to Verify Document mode. Likewise, scanning a URL/UPI QR in Verify Document mode offers to switch to Scan QR mode.

#### Mode 2: Verify Document
Government document verification with mode-specific camera overlays (landscape violet card frame).

Supports offline analysis of QR codes from:

| Document | Detection | Can Parse | Notes |
|----------|-----------|-----------|-------|
| **Aadhaar Secure QR** (post-2019 PVC) | ✅ HIGH | ✅ Full | Extracts name, DOB, gender, address, photo, mobile/email link status |
| **Aadhaar XML QR** (pre-2019) | ✅ HIGH | ✅ Partial | Extracts demographic fields; no photo |
| **DigiLocker docs** (DL, CBSE, PAN digital copy) | ✅ HIGH | URL only | Detects `digilocker.gov.in` URL; opens official verification portal |
| **CoWIN Vaccination** | ✅ HIGH | URL only | Routes to official CoWIN portal |
| **mParivahan / Parivahan DL** | ✅ HIGH | URL only | Routes to mParivahan portal |
| **CBSE Marksheet** (via DigiLocker) | ✅ HIGH | URL only | Routes to DigiLocker portal |
| **Income Tax Notices** | ✅ HIGH | URL only | Fraud warning for non-portal QRs |
| **e-Court documents** | ✅ HIGH | URL only | CNR verification with digital-arrest scam warning |
| **Generic .gov.in / .nic.in** | ✅ HIGH | URL only | Generic government portal route |

> **Why physical PAN/DL/CBSE cards cannot be fully parsed:** Physical card QR codes use proprietary encrypted binary formats (MoRTH/SARATHI for DL, NSDL/UTIITSL for PAN) with non-public decryption keys. Only official government apps (mParivahan, IT Dept scanner) can decrypt them. DigiLocker-downloaded digital copies use HTTPS URLs, which we can detect and safely route.

---

### Government Document Verifier

A dedicated full-screen UI for verified Aadhaar Secure QR results:

**Aadhaar Secure QR card shows:**
- 🟢 **UIDAI SIGNATURE VALID ✓** — when signature is cryptographically verified (genuine card)
- 🔴 **SIGNATURE INVALID ✗** — when signature check fails (tampered/forged card, fraud warning)
- 🟡 **SIGNATURE UNVERIFIABLE** — when the card may use a newer UIDAI signing certificate not yet configured

Extracted data displayed in Liquid Glass cards:
- Document Photo (JPEG extracted from QR payload)
- Identity Details (Aadhaar masked UID, Name, DOB, Gender)
- Registered Address (Care Of, House, Street, Locality, Village/Town, District, State, PIN)
- Linked Accounts (mobile and email link indicators)
- Verification Note with plain-language explanation of the cryptographic result

**Privacy:** Aadhaar data is processed in-memory only. It is never stored to database, logged, or transmitted beyond the API response. The privacy note is displayed to the user on the result screen.

---

## Project Structure

```
safemailx-ai/
├── src/                              # Python backend source
│   ├── engines/                      # Detection engine modules
│   │   ├── hybrid_engine.py          # 3-layer pipeline orchestrator
│   │   ├── llm_analyzer.py           # Qwen 2.5 / LM Studio integration
│   │   ├── instant_scan_engine.py    # Fast sync scan engine (SMS, URL, file, QR)
│   │   ├── rule_engine.py            # Heuristic rule evaluation
│   │   ├── url_analyzer.py           # URL reputation + redirect analysis
│   │   ├── sms_engine.py             # SMS-specific feature extraction
│   │   ├── file_analyzer.py          # Document parsing (PDF, DOCX, EML)
│   │   ├── attachment_analyzer.py    # Email attachment risk scoring
│   │   ├── qr_analyzer.py            # QR multi-decoder + preprocessing pipeline
│   │   ├── aadhaar_decoder.py        # UIDAI Secure QR offline parser
│   │   ├── vishing_analyzer.py       # Whisper audio transcription + call scoring
│   │   ├── scam_intelligence_engine.py # Indian cybercrime pattern classifier
│   │   ├── domain_trust_arbiter.py   # Domain reputation system
│   │   ├── adaptive_trust_engine.py  # Per-sender behavioral baseline
│   │   ├── campaign_correlator.py    # Cross-scan campaign linkage
│   │   ├── prompt_injection_guard.py # LLM adversarial input protection
│   │   ├── intent_classifier.py      # Message intent classification
│   │   ├── local_slm_engine.py       # Local small LM fallback
│   │   ├── offline_sync.py           # Offline-mode scan queue
│   │   ├── fraud_scam_engine.py      # Financial fraud pattern detection
│   │   ├── identity_risk_engine.py   # Identity theft risk signals
│   │   ├── payment_risk_engine.py    # Payment/banking fraud signals
│   │   ├── ransomware_malware_engine.py # Malware indicator detection
│   │   ├── data_leak_engine.py       # Sensitive data exposure detection
│   │   ├── smart_veto.py             # Ensemble confidence veto logic
│   │   └── yara_rules/               # YARA malware signature rules
│   │
│   ├── server/                       # FastAPI application
│   │   ├── app.py                    # Main FastAPI app + all routes (1750+ lines)
│   │   ├── worker.py                 # Redis queue worker
│   │   ├── scan_service.py           # Scan orchestration service
│   │   ├── inline_scan_service.py    # Sync instant scan service
│   │   ├── repository.py             # Database access layer
│   │   ├── schemas.py                # Pydantic request/response models
│   │   ├── auth.py                   # JWT authentication
│   │   ├── gmail_oauth.py            # Gmail OAuth 2.0 flow
│   │   ├── gmail_watcher.py          # Gmail label poll watcher
│   │   ├── gmail_labels.py           # Gmail label management
│   │   ├── google_backup.py          # Google Drive backup integration
│   │   ├── notifications.py          # Expo push notification service
│   │   ├── mailer.py                 # SMTP email (password reset)
│   │   ├── queue.py                  # Redis queue interface
│   │   ├── health.py                 # /health endpoint
│   │   └── settings.py               # Server configuration
│   │
│   └── utils/
│       └── config.py                 # Centralized env config
│
├── trustmail-mobile/                 # React Native (Expo SDK 54) mobile app
│   ├── App.tsx                       # Main app (tabs, navigation, all screens)
│   ├── src/
│   │   ├── screens/
│   │   │   ├── CallAnalyzerScreen.tsx    # Call / vishing threat analyzer
│   │   │   ├── QRScannerScreen.tsx       # Dual-mode QR scanner (Scan + Verify)
│   │   │   └── GovDocVerifierScreen.tsx  # Government document result UI
│   │   ├── services/
│   │   │   ├── govDocDetector.ts         # QR payload type classifier (frontend)
│   │   │   └── aadhaarVerifier.ts        # Aadhaar API client + result mapper
│   │   ├── api.ts                        # Typed API client (all endpoints)
│   │   ├── session.ts                    # Secure token management
│   │   └── theme.ts                      # Liquid Glass design system tokens
│   └── app.json                          # Expo configuration
│
├── models/                           # Trained ML model artifacts
│   └── phishing_ai_model.joblib      # TF-IDF + Logistic Regression model
│
├── deploy/
│   ├── nginx.conf                    # Production Nginx reverse proxy config
│   └── nginx.https.conf.template     # HTTPS/TLS Nginx config template
│
├── tests/                            # Backend unit tests
├── docker-compose.yml                # Full stack Docker orchestration
├── Dockerfile                        # Backend container image
├── requirements.txt                  # Python dependencies
└── .env.example                      # Environment variable template
```

---

## Quick Start

### Docker (Recommended)

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

```bash
curl http://localhost:8080/api/health
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

# Start the API server
uvicorn server.app:app --host 0.0.0.0 --port 8080 --reload

# In a second terminal — start the queue worker
export PYTHONPATH=src
python -m server.worker
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

### Build Production APK

```bash
cd trustmail-mobile
npm install -g eas-cli
eas login
eas build --platform android   # or ios
eas submit                     # submit to app stores
```

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

# ─── Audio / Vishing (Whisper) ────────────────────────────────
WHISPER_MODEL_SIZE=tiny       # tiny / base / small / medium / large
# Larger = more accurate, slower. "tiny" is default for low-latency.

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

# ─── WhatsApp / Telegram Webhooks ────────────────────────────
# TELEGRAM_BOT_TOKEN=your-telegram-bot-token
# WHATSAPP_VERIFY_TOKEN=your-meta-verify-token
```

**Generate a Fernet encryption key:**
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

---

## LLM Integration

SafeMail X AI uses **Qwen 2.5 7B Instruct** as its deep reasoning layer via an OpenAI-compatible API.

### Setup with LM Studio (Local)

1. Download [LM Studio](https://lmstudio.ai/)
2. Load the `qwen2.5-7b-instruct-1m` model
3. Start the local server on port `1234`
4. Set in `.env`:
   ```env
   LLM_BASE_URL=http://127.0.0.1:1234/v1/chat/completions
   LLM_MODEL=qwen2.5-7b-instruct-1m
   ```

### Setup for Cloud Deployment (Railway, Render, etc.)

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
| `POST` | `/auth/login` | Login, returns JWT |
| `POST` | `/auth/register` | Register new account |
| `POST` | `/auth/send-otp` | Send OTP for registration |
| `POST` | `/auth/refresh` | Silent JWT refresh |
| `POST` | `/auth/forgot-password` | Send password reset email |
| `POST` | `/auth/reset-password` | Reset with token |
| `POST` | `/auth/logout` | Invalidate session |

### Instant Scans (Synchronous)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/instant/sms` | SMS/smishing analysis |
| `POST` | `/api/instant/url` | URL threat check |
| `POST` | `/api/instant/file` | File/document analysis |
| `POST` | `/api/instant/email` | Email body analysis |
| `POST` | `/api/instant/qr` | QR code security analysis (URL, UPI, Wi-Fi, etc.) |
| `POST` | `/api/instant/aadhaar` | Aadhaar Secure QR offline decode + parse |

### Call / Voice Analysis
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/voice/analyze-call` | Analyze call description or audio transcript for vishing/scam |

### Full Scans (Async Queue)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scans/manual` | Synchronous text/email scan |
| `POST` | `/api/scans/manual/queue` | Queue text/email scan |
| `POST` | `/api/scans/upload` | File upload scan |
| `POST` | `/api/scans/screenshot` | Image/OCR scan |
| `POST` | `/api/scans/sms` | Full SMS scan with history |
| `POST` | `/api/scans/url` | Full URL scan with history |
| `GET`  | `/api/scans` | List scan history |
| `GET`  | `/api/scans/{id}` | Get scan details |
| `POST` | `/api/scans/{id}/feedback` | Submit user feedback on verdict |
| `POST` | `/api/scans/{id}/rescan` | Re-run a previous scan |

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
| `GET`  | `/api/scans/{id}/report.pdf` | Download PDF forensic report |
| `GET`  | `/api/scans/{id}/evidence.json` | Download JSON evidence |
| `POST` | `/api/scans/{id}/report-link` | Get temporary report download link |
| `POST` | `/api/notifications/register` | Register push token |
| `GET`  | `/api/notifications/preferences` | Get notification preferences |
| `PUT`  | `/api/notifications/preferences` | Update notification preferences |
| `GET`  | `/api/backup/oauth/status` | Drive backup status |
| `POST` | `/api/backup/sync` | Trigger Drive backup |
| `GET`  | `/api/threat-bulletin` | Current threat bulletin |
| `GET`  | `/api/dashboard` | Dashboard data |
| `GET`  | `/api/health` | API health check |
| `GET`  | `/api/health/llm` | LLM availability check |

### Webhooks (Hidden from Swagger)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/webhooks/whatsapp` | WhatsApp Business API webhook |
| `POST` | `/api/webhooks/telegram` | Telegram bot webhook |

---

## Deployment

### Railway (Current Production Target)

SafeMail X AI is deployed on [Railway](https://railway.app/) with auto-deploy from the `main` branch.

1. Connect GitHub repo to Railway
2. Set all environment variables from the table above
3. Railway auto-detects the `Dockerfile` and builds
4. Add a Redis service and PostgreSQL service from Railway's marketplace
5. Set `DATABASE_URL` and `REDIS_URL` to Railway's provided connection strings

### Production with Docker + Cloudflare Tunnel

```bash
git clone https://github.com/Rahul-workss/safemailx-ai.git
cd safemailx-ai
cp .env.example .env
docker compose up -d
cloudflared tunnel run
```

### Production Persistence Requirements

- `DATABASE_URL` must point to a persistent managed PostgreSQL instance.
- `REDIS_URL` must point to a persistent managed Redis instance.
- SQLite fallback is for local development only — data will be lost on container restarts.

---

## Testing

### Backend Tests

```bash
export PYTHONPATH=src
python -m unittest discover -s tests -v

# Syntax check all modules
python -m compileall src tests

# Quick smoke test
curl -s http://localhost:8080/api/health | python -m json.tool
```

### Mobile Tests

```bash
cd trustmail-mobile
npx tsc --noEmit
```

### Manual Smoke Checklist

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
- [ ] Scan a QR code via the QR Scanner (Scan QR mode)
- [ ] Scan an Aadhaar QR code (Verify Document mode)
- [ ] Describe a suspicious call in the Call Analyzer
- [ ] Verify smart cross-mode QR routing modal

---

## Security

SafeMail X AI is built security-first:

- **Session tokens** stored in hardware-encrypted Keychain / Android Keystore via `expo-secure-store`
- **Gmail tokens** encrypted with Fernet (AES-128) before database storage
- **No plaintext credentials** anywhere in storage or logs
- **JWT 24h expiry** with silent refresh support and explicit logout
- **Rate limiting** on auth endpoints
- **Read-only Gmail access** — no write permissions ever requested
- **QR payloads treated as untrusted input** — never auto-opened, URL/deep links require explicit user action
- **Aadhaar data** processed in-memory only, never persisted or logged
- **Prompt injection guard** protects the LLM layer from adversarial content in scanned messages
- **SSRF protection** on URL analysis — controlled fetch with domain allowlist

To report a security vulnerability, please email the maintainer directly rather than opening a public issue.

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
Scopes: engine, api, mobile, auth, llm, ui, qr, call
```

---

## License

[MIT](LICENSE) © 2025 SafeMail X AI Contributors

---

<div align="center">

**Built with ❤️ for a safer digital world**

[Report Bug](https://github.com/Rahul-workss/safemailx-ai/issues) · [Request Feature](https://github.com/Rahul-workss/safemailx-ai/issues) · [Documentation](https://github.com/Rahul-workss/safemailx-ai/wiki)

</div>
