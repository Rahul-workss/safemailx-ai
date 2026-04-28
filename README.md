# 🛡️ SafeMail-X

**Your inbox's personal cybersecurity analyst — running entirely on your own machine.**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License: Proprietary](https://img.shields.io/badge/License-Proprietary-red)](LICENSE)
[![LLM: Qwen 2.5](https://img.shields.io/badge/LLM-Qwen%202.5%207B-green)](https://lmstudio.ai/)
[![Platform: Local Edge](https://img.shields.io/badge/Platform-Local%20Edge-orange)](https://github.com/)

---

## What is SafeMail-X?

Phishing emails are getting scarily good. They pass spam filters, look legitimate, and sometimes even carry valid security certificates. SafeMail-X was built to catch what traditional tools miss.

It watches your Gmail inbox in real time, runs every suspicious email through three layers of AI-powered analysis, and hands you a detailed forensic report — all **without your emails ever leaving your computer**. No cloud. No subscriptions. No data sharing.

---

## How it works

When a new email lands in your inbox, SafeMail-X puts it through three independent checks simultaneously:

**1. 🔍 Custom Rule Engine** — A proprietary, deterministic module custom-developed to inspect the email's structure and headers for classic red flags: spoofed sender domains, tampered routing headers, and brand impersonation tricks.

**2. 🧠 Proprietary TF-IDF Machine Learning Model** — A custom, locally-trained statistical NLP model (TF-IDF + Logistic Regression) that reads the email's wording, looking for subtle linguistic patterns that consistently show up in phishing and social engineering attempts.

**3. 🤖 Local AI Analyzer (Qwen 2.5 7B)** — A full large language model running on your own hardware reads the email the way a human analyst would, identifying psychological manipulation tactics like manufactured urgency, fear, or false authority.

All three verdicts are then weighed by a **Smart Veto** fusion engine. Here's the clever part: even if an email has a valid security certificate (SPF/DKIM pass), the system can still flag it if the AI detects manipulative intent. Attackers know how to pass technical checks — this catches them anyway.

The result? A **forensic PDF report** saved to your machine with a full breakdown of every signal that was triggered.

---

## Before you begin

You'll need four things installed. None of them are complicated — just follow the links.

| What you need | Why | Where to get it |
|---|---|---|
| **Python 3.10 or newer** | Runs the core system | [python.org](https://www.python.org/downloads/) — tick *"Add to PATH"* during install |
| **Tesseract OCR** | Reads text hidden inside image attachments | [UB-Mannheim installer](https://github.com/UB-Mannheim/tesseract/wiki) (Windows) — add it to your Environment Variables after installing |
| **LM Studio** | Runs the local AI model | [lmstudio.ai](https://lmstudio.ai/) |
| **Qwen 2.5 7B model** | The brain behind behavioral analysis | Download inside LM Studio → search `Qwen2.5-7B-Instruct-GGUF`, pick the `Q4_K_M` version |

> 💡 **Not sure about Tesseract on Windows?** After installing, search for "Environment Variables" in the Start menu → Edit the system environment variables → find `Path` → add the folder where Tesseract was installed (usually `C:\Program Files\Tesseract-OCR`).

---

## Getting set up

### 1. Grab the code

```bash
git clone https://github.com/your-org/safemailx-ai.git
cd safemailx-ai
```

### 2. Create an isolated Python environment

This keeps SafeMail-X's dependencies separate from anything else on your machine — good practice and saves headaches later.

```bash
python -m venv venv
```

Now activate it:

```bash
# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

You'll know it worked when you see `(venv)` at the start of your terminal prompt.

### 3. Install the dependencies

```bash
pip install -r requirements.txt
```

### 4. Add your Gmail credentials

SafeMail-X needs read-only access to your Gmail inbox (it never modifies or deletes anything).

1. Drop your `credentials.json` file into the `src/` folder.
2. Drop your `token.pickle` file into the `src/` folder.

> 🔐 **No `token.pickle` yet?** No problem. Just run the system — on first launch it'll open a browser window and walk you through a standard Google sign-in. The token file gets created automatically after that.

---

## Running SafeMail-X

The system has two parts that need to run at the same time. Open two terminal windows (or tabs) and start them in order.

---

### Window 1 — Fire up the AI model

1. Open **LM Studio**
2. Load the **Qwen 2.5 7B Instruct** model
3. Click the **Local Server** tab (looks like `<->`)
4. Hit **Start Server** — make sure it's running on port `1234`

Leave this running. SafeMail-X talks to it at `http://localhost:1234/v1`.

---

### Window 2 — Start the email watcher

This is the main process. It monitors your inbox, runs the analysis pipeline, and generates the PDF reports.

```bash
# Make sure your venv is active, then:
cd src
python forwarding_bot.py
```

You should see startup messages as each engine initializes, followed by the bot starting to poll your inbox. That's it — SafeMail-X is now running. 🎉

---

---

## What's inside the project

```
safemailx-ai/
│
├── src/                          # Everything that runs the system
│   ├── engines/                  # The three detection engines + attachment scanners
│   ├── utils/                    # Gmail fetching, parsing, OCR, and report generation
│   ├── forwarding_bot.py         # ← Start this to run the system
│   └── train_model.py            # Retrain the ML model on new data
│
├── data/                         # Training datasets
├── models/
│   └── phishing_ai_model.joblib  # The trained ML model
└── reports/                      # Your forensic PDFs land here
```

---

## Something not working?

Here are the most common stumbling blocks:

**The AI analyzer isn't responding**
→ LM Studio's server probably isn't running. Go back to Window 1, check that the server is started and showing port `1234`.

**`FileNotFoundError: credentials.json`**
→ The Gmail credentials file is missing from `src/`. Re-check the setup step above.

**OCR on image attachments isn't working**
→ Tesseract likely isn't on your system PATH. On Windows, check Environment Variables and make sure the Tesseract install folder is listed.

**A browser sign-in window appeared on startup**
→ That's expected if `token.pickle` is missing or expired. Just sign in with your Google account and the file will be created automatically.

---

## Privacy, by design

SafeMail-X was built on a simple premise: your emails are yours.

- **Nothing leaves your machine.** Analysis happens 100% locally — the AI model, the rule engine, and the ML model all run on your own hardware.
- **No accounts, no cloud, no telemetry.** There's no SafeMail-X server receiving your data anywhere.
- **Read-only inbox access.** The Gmail integration can only read emails. It cannot send, delete, or modify anything.

---

## License

Proprietary software. All rights reserved. See [LICENSE](LICENSE) for full terms.
