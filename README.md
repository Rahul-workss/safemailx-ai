# SafeMail-X

**Local email phishing analysis for forwarded Gmail messages.**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License: Proprietary](https://img.shields.io/badge/License-Proprietary-red)](LICENSE)
[![LLM: Qwen 2.5](https://img.shields.io/badge/LLM-Qwen%202.5%207B-green)](https://lmstudio.ai/)
[![Platform: Local Edge](https://img.shields.io/badge/Platform-Local%20Edge-orange)](https://github.com/)

---

## Overview

SafeMail-X monitors a Gmail inbox for forwarded messages, analyzes the forwarded content, and produces a forensic report for the user. The system combines rule-based checks, a local TF-IDF classification model, optional LLM-based analysis through LM Studio, URL inspection, OCR, and attachment analysis.

Optional reputation lookups only run when Safe Browsing or VirusTotal API keys are configured.

---

## Detection Flow

Each forwarded email is evaluated through three main stages:

**1. Rule Engine**  
Inspects the message structure, sender details, headers, and common phishing indicators such as spoofing patterns, suspicious routing, and impersonation signals.

**2. TF-IDF Classification Model**  
Uses a locally trained TF-IDF + Logistic Regression pipeline to score the email text for phishing-related language patterns.

**3. Local LLM Analysis**  
Uses Qwen 2.5 through LM Studio to produce a structured behavioural assessment of the message content.

The final decision is produced by the hybrid scoring engine. Authentication trust is only applied when original forwarded headers are available; otherwise forwarding headers are treated separately and the analysis stays conservative.

---

## Requirements

Install the following before running the project:

| What you need | Why | Where to get it |
|---|---|---|
| **Python 3.10 or newer** | Runs the project | [python.org](https://www.python.org/downloads/) |
| **Tesseract OCR** | Extracts text from image attachments | [UB-Mannheim installer](https://github.com/UB-Mannheim/tesseract/wiki) |
| **LM Studio** | Runs the local LLM analyzer | [lmstudio.ai](https://lmstudio.ai/) |
| **Qwen 2.5 7B Instruct 1M model** | Used by the LLM analyzer | Download inside LM Studio |

On Windows, make sure the Tesseract installation path is added to `PATH`, or set `TESSERACT_CMD` in `.env`.

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/your-org/safemailx-ai.git
cd safemailx-ai
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

Activate it:

```bash
# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Add Gmail credentials

Place these files in `src/`:

1. `credentials.json`
2. `token.pickle`

If `token.pickle` does not exist yet, it will be created after the first Google sign-in flow.

---

## Running SafeMail-X

The project uses two running components.

### Window 1 - Start LM Studio

1. Open **LM Studio**
2. Load the **Qwen 2.5 7B Instruct 1M** model
3. Open the **Local Server** tab
4. Start the server on port `1234`

SafeMail-X connects to `http://127.0.0.1:1234/v1` and uses model id `qwen2.5-7b-instruct-1m`.

### Window 2 - Start the bot

```bash
cd src
python forwarding_bot.py
```

The bot will poll Gmail, analyze forwarded messages, and generate PDF reports.

Optional `.env` settings:

```bash
LM_STUDIO_URL=http://127.0.0.1:1234/v1/chat/completions
LM_STUDIO_MODEL=qwen2.5-7b-instruct-1m
LM_STUDIO_AUTO_CONTEXT=true
LM_STUDIO_MAX_CONTEXT_TOKENS=1010000
LM_STUDIO_EMAIL_CHAR_LIMIT=120000
LM_STUDIO_MAX_OUTPUT_TOKENS=700
SAFEMAILX_DEBUG=false
TESSERACT_CMD=C:\Program Files\Tesseract-OCR\tesseract.exe
SAFE_BROWSING_API_KEY=
VIRUSTOTAL_API_KEY=
```

`SAFEMAILX_DEBUG=true` enables detailed local debug output for text and OCR processing.

---

## Project Structure

```text
safemailx-ai/
|
|-- src/
|   |-- engines/
|   |-- utils/
|   |-- forwarding_bot.py
|   `-- train_model.py
|
|-- data/
|-- models/
|   `-- phishing_ai_model.joblib
`-- reports/
```

---

## Troubleshooting

**The LLM analyzer is not responding**  
Check that LM Studio is running and the local server is active on port `1234`.

**`FileNotFoundError: credentials.json`**  
Make sure the Gmail credentials file exists in `src/`.

**OCR is not working**  
Check that Tesseract is installed and available through `PATH` or `TESSERACT_CMD`.

**A browser sign-in window opened on startup**  
This is expected when `token.pickle` is missing or expired.

---

## Privacy Notes

- Analysis runs locally except for optional reputation checks.
- Safe Browsing only receives URLs when `SAFE_BROWSING_API_KEY` is configured.
- VirusTotal only receives attachment hashes when `VIRUSTOTAL_API_KEY` is configured.
- There is no separate SafeMail-X cloud service in this repository.

---

## License

Proprietary software. All rights reserved. See [LICENSE](LICENSE) for full terms.
