9/23/26, 2:34 PM 

Markdown Live Preview 

 

# **SafeMail X AI — RAG Knowledge Base** 

## **Making the Call Analyzer Smarter: Official Bank Document Intelligence** 

## **1. What is SafeMail X AI?** 

SafeMail X AI is a **cybersecurity app** built for Indian users to protect themselves from: 

- 📧 Phishing emails 

- 📱 Scam SMS messages 

- 🔗 Dangerous URLs 

- 📞 Fraudulent phone calls 

- 📷 QR code scams 

The app has a mobile client (React Native), a web dashboard, and a Python backend that runs on Render (cloud server). It uses AI models like **Qwen3** (local LLM) and **Whisper** (voice transcription) to analyze threats. 

## **2. What is the Call Analyzer?** 

The **Call Analyzer** is one of SafeMail X AI's most important features. Here's how it works today: 

```
User receives suspicious call
        ↓
Opens Call Analyzer on phone
        ↓
Either:
  A) Records a 20-second voice description of what happened
     (Whisper AI transcribes it to text)
  OR
  B) Fills a form: "Who called?" + "What did they ask?"
        ↓
Backend analyzes the call description using 3 layers:
  Layer 1: Rule engine (pattern matching — instant)
  Layer 3: Live policy check (searches official sources)
  Layer 2: Qwen3 AI (local LLM — deep reasoning)
        ↓
Returns verdict: SAFE / SUSPICIOUS / CRITICAL SCAM
```

### **Real Example:** 

User says: _"Someone called claiming to be from SBI Bank and asked me to share my OTP to update KYC"_ 

App returns: 🔴 **CRITICAL SCAM** — SBI never asks for OTP over calls. This matches the KYC fraud pattern. Official callback: 1800-11-2211. 

https://markdownlivepreview.com 

1/9 

9/23/26, 2:34 PM 

Markdown Live Preview 

 

## **3. The Problem We're Solving** 

### **A. The "Plumbing" Bugs in Current Code (✅ FIXED)** 

_Note: As of October 2026, the plumbing bugs (scoring execution order, 2-layer override, and dynamic weights) have been completely fixed in the new 7-layer `scam_intelligence_engine.py`. We no longer need to worry about the core engine architecture failing to apply policy scores._
### **B. Current Layer 3 (Tavily) — What's Wrong** 

Right now, to verify **"Does SBI actually do this?"** , it calls **Tavily API** — a paid real-time web search. 

#### **Problems with this approach:** 

|**Problem**|**Impact**|
|---|---|
|🌐Needs internet every time|Fails when Render server has no connection|
|💰Costs money (Tavily credits)|Limited usage per month|
|🐢Takes 2–5 seconds|Slows down the verdict|
|🤔Can hallucinate|Tavily might return wrong/irrelevant pages|
|❓Only 17 orgs supported|Many Indian banks not covered|
|📅No source date|Can't tell if info is fresh or old|



### **What We Want Instead** 

A **self-contained, offline knowledge base** built from official Indian bank websites — so the app answers in under 5ms, for free, with a cited source, and actually feeds that source into Qwen3. 

## **4. The Solution — RAG Knowledge Base** 

**RAG** stands for **Retrieval-Augmented Generation** . It means: 

1. **Retrieval** — Search a pre-built database of official documents for relevant facts instantly. 

2. **Augmented** — Feed those facts directly to an AI (Qwen3). 

3. **Generation** — AI generates a clear, accurate verdict based on the facts. 

### **Simple Analogy** 

**Before (Tavily):** Every time someone asks "Does SBI ask for OTP?", we send a researcher to the public library to look it up. It is slow, costs money, and the researcher might read the wrong book. 

**After (RAG KB):** We already have the official answer in our own filing cabinet. It is instant, free, always from the right source, and handed directly to our AI brain before it decides. 

https://markdownlivepreview.com 

2/9 

9/23/26, 2:34 PM 

Markdown Live Preview 

 

## **5. Why BM25 Search (Not ChromaDB or FAISS)** 

Most RAG systems use **vector databases** (ChromaDB, FAISS). We chose **BM25** (keyword-based search) instead. Here's why: 

|**Factor**|**ChromaDB + Embeddings**|**BM25 (our choice)**|
|---|---|---|
|RAM needed|~800MB|~10MB|
|Render free tier RAM|512MB|512MB|
|Works on Render?|❌Crashes|✅Yes|
|Speed|~200ms|**~5ms**|
|Accuracy for our queries|85%|**95%**|
|New dependency size|500MB|**50KB**|



**Why is BM25 more accurate for us?** Official bank documents use **exact keyword phrases** like _"never ask for OTP"_ . BM25 finds these exact phrases better than semantic search, which tries to understand "meaning" and might pull up irrelevant FAQs. 

## **6. What We're Building — Complete List** 

### **New Files to Create** 

##### `scripts/` 

```
  parse_kb.py           ← Extracts clean text from manually saved HTML/PDFs
  chunk_kb.py           ← Splits text into 150-word searchable chunks + tags them
  build_kb.py           ← Master script that runs parsing and chunking
  refresh_kb.py         ← GitHub Action script to check if bank websites updated
```

```
src/engines/layers/
```

```
  kb_search.py          ← The BM25 search engine (loads at startup, <5ms)
```

```
data/
```

```
  kb_raw/               ← Folder for manually saved HTML files (avoids bot blocks)
  kb_chunks.json        ← The pre-built knowledge base (committed to repo)
  kb_version.json       ← Tracks when KB was last rebuilt
```

```
.github/workflows/
  refresh_kb.yml        ← Monthly auto-check of bank website headers
```

### **Files to Modify** 

```
src/engines/layers/live_policy_agent.py  ← Replace Tavily with KB search (BM25)
src/engines/layers/qwen_call_layer.py    ← Inject KB chunks into Qwen3 SYSTEM_PROMPT
src/engines/layers/policy_verification.py ← Inject KB chunks into offline deterministic logic
src/data/org_policies.json               ← Add 8 new orgs + Hinglish aliases + dates
requirements.txt                         ← Add: rank-bm25==0.2.2 (50KB only)
```

https://markdownlivepreview.com 

3/9 

9/23/26, 2:34 PM 

Markdown Live Preview 

 

## **7. Data Sources — 25+ Organizations** 

_Note: Because Indian banks block automated scrapers (HTTP 403), these pages are manually saved once via Chrome (Ctrl+S → HTML Only) into_ _`data/kb_raw/` ._ 

**Tier 1: Major Banks (Priority — highest scam impersonation rate)** 

|**Organization**|**Official Source**|**What We Extract**|
|---|---|---|
|**State Bank of India**|sbi.co.in/fraud-awareness|"Never ask for OTP/PIN/CVV on calls"|
|**HDFC Bank**|hdfcbank.com/security|"Never ask to install remote apps"|
|**ICICI Bank**|icicibank.com/security|KYC fraud warnings, callback numbers|
|**Axis Bank**|axisbank.com/safety-tips|Vishing (voice phishing) alerts|
|**Kotak Mahindra**|kotak.com/security|Official contact numbers|
|**Punjab National Bank**|pnbindia.in/safe-banking|Safe banking guidelines|
|**Bank of Baroda**|bankofbaroda.in/security|Fraud awareness content|
|**Canara Bank**|canarabank.com/safety|Customer safety rules|
|**Union Bank**|unionbankofindia.co.in|Fraud prevention|
|**Yes Bank**|yesbank.in/security|Phishing/vishing alerts|
|**IDFC First Bank**|idfcfirstbank.com/security|Safety guidelines|



### **Tier 2: Government & Regulators (Highest authority)** 

|**Organization**|**Official Source**|**What We Extract**|
|---|---|---|
|**RBI**|rbi.org.in (Be Safe Banking)|Banking fraud guidelines|
|**Income Tax Dept**|incometaxindia.gov.in/fraud-calls|Never demands cash/UPI|
|**UIDAI (Aadhaar)**|uidai.gov.in/fraud-alerts|Aadhaar misuse patterns|
|**TRAI**|trai.gov.in|SIM block scams, official advisory|
|**MHA Cybercrime**|cybercrime.gov.in|Digital arrest scam warning|
|**NPCI / UPI**|npci.org.in (UPI FAQs)|UPI payment fraud rules|



https://markdownlivepreview.com 

4/9 

9/23/26, 2:34 PM 

Markdown Live Preview 

 

### **Tier 3: Payment Apps & E-commerce** 

|**Organization**|**Official Source**|**What We Extract**|
|---|---|---|
|**Paytm**|paytm.com/fraud-alerts|Never ask for OTP, wallet scams|
|**PhonePe**|phonepe.com/security|UPI scam patterns|
|**Google Pay**|pay.google.com/security|Gift voucher scams|
|**Amazon India**|amazon.in/customer-service|Gift card scams|
|**Jio**|jio.com/safety|SIM swap fraud|
|**Airtel**|airtel.in/fraud-prevention|Number portability scams|



## **8. How Each Document Gets Processed** 

### **Step 1: Save & Extract (parse_kb.py)** 

```
Human manually saves HTML page to avoid bot-blocks.
BeautifulSoup → extracts main content text → removes nav/ads/footer
Result: clean plain text per org
```

### **Step 2: Chunk (chunk_kb.py)** 

Split each document into **150-word overlapping chunks** (75-word overlap). We use 150 words (not 300) so we don't overwhelm Qwen3's token budget. 

```
Original text: "SBI will never ask you to share your OTP, PIN,
                or password on a phone call. Anyone claiming
                to be from SBI and asking for this information
                is a fraudster."
```

```
Chunk 1: "SBI will never ask you to share your OTP, PIN,
          or password on a phone call. Anyone claiming"
```

```
Chunk 2: "or password on a phone call. Anyone claiming
          to be from SBI and asking for this information
          is a fraudster."
```

**Why overlap?** So the key sentence ("never ask for OTP") is never split and lost across two chunks. 

### **Step 3: Tag (chunk_kb.py with Offline Qwen3)** 

Instead of using dumb regex (which gets confused by sentences like "We never ask for PIN, but OTP is required for login"), `chunk_kb.py` will use your local **Qwen3 to read and tag** all chunks perfectly during the offline build phase. 

`{ "text": "SBI will never ask you to share your OTP or PIN on a phone call.", "org": "State Bank of India", "policy_type": "PROHIBITION", "action_keywords": ["otp", "pin", "phone call"], "confidence_base": 0.92, "source_url": "https://sbi.co.in/fraud-awareness", "source_date": "2024-09" }` 

**Tag types:** 

- `PROHIBITION` — explicitly says they DON'T do something (Highest priority) 
- `WARNING` — warns about a scam pattern 
- `PROCEDURE` — official process description 
- `PERMISSION` — confirms they DO something 
- `GENERAL` — background information 

## **9. How the Search Works at Runtime** 

When a user reports a call, the system: 

```
Input: org="SBI", action="asked for OTP to update KYC"
         ↓
Step 1: Org name resolution
  "SBI" → aliases check → matches "state_bank_of_india"
         ↓
Step 2: Build BM25 query & Synonym Expansion
  User says "AnyDesk" -> Engine expands to "AnyDesk remote access screen share"
  Query: "does SBI State Bank ask customers OTP PIN phone call KYC update AnyDesk remote access"
         ↓
Step 3: BM25 search in kb_chunks.json (in-memory, <5ms)
  Returns top chunks ranked by relevance (PROHIBITION chunks pushed to top)
  *Threshold Check:* If top score < X, abort injection to prevent irrelevant hallucination.
         ↓
Step 4: Chunk Merging & Dual Injection
  - Merger: If Top 2 chunks are adjacent in the original text, merge them to remove 75-word overlap and save LLM tokens.
  - Online (Qwen3): Inject merged chunks into `qwen_call_layer.py` SYSTEM_PROMPT.
  - Offline Fallback: Inject chunks into `policy_verification.py` to boost score deterministically.
         ↓
Step 5: Verdict generation
  Qwen3 (or fallback) generates the verdict with citation to the specific KB chunk.
         ↓
Output:
  risk_band: "CRITICAL"
  verdict_text: "This is a fraud call. SBI never asks for OTP..."
  source_url: "https://sbi.co.in/fraud-awareness"
  source_date: "September 2026"
```

## **10. Solving Every Loophole** 

### ❌ **Problem 1: Caller says "aaykar vibhag" (Hindi for Income Tax)** 

✅ **Fix:** Every org has a `aliases` list including common Hindi/Hinglish names: `"aliases": ["income tax", "aaykar", "aaykar vibhag", "tax wale"]` 

### ❌ **Problem 1.5: "Bank of India" vs "State Bank of India" matching** 

✅ **Fix:** Org resolution uses strict word boundaries (`\b`) and prioritizes exact acronyms over partial matches so "Bank of India" doesn't falsely trigger "SBI".

https://markdownlivepreview.com 

6/9 

9/23/26, 2:34 PM 

Markdown Live Preview 

 

### ❌ **Problem 2: Key sentence broken across two chunks** 

✅ **Fix:** 75-word overlap between chunks. Every sentence appears fully in at least one chunk. 

### ❌ **Problem 3: Two chunks say opposite things** 

✅ **Fix:** Priority ranking: `PROHIBITION > WARNING > PERMISSION > GENERAL` . The more restrictive statement wins. 

### ❌ **Problem 4: Bank updates policy, our data is outdated** 

✅ **Fix:** GitHub Actions runs `refresh_kb.py` monthly. It checks website `Last-Modified` HTTP headers. If a site changed, it opens a GitHub issue asking a human to re-save the page. 

### ❌ **Problem 5: Unknown org — "Karur Vysya Bank" not in KB** 

- ✅ **Fix:** Graceful tiered fallback: 

1. Try KB search (<5ms) → no match 

2. Try Tavily web search (2s) → fallback 

3. Try Static JSON → final fallback 

### ❌ **Problem 6: Render free tier memory limit (512MB)** 

✅ **Fix:** BM25 index loads from `kb_chunks.json` . Index builds in <1 second at startup, lives in RAM using only ~10MB. No heavy vector databases (ChromaDB) allowed. 

### ❌ **Problem 7: Irrelevant Injection (BM25 matches unrelated words)** 

✅ **Fix:** BM25 Minimum Score Threshold. If a user asks "Did SBI wish me happy birthday", BM25 might return a chunk about credit cards just because "SBI" matched. We enforce a strict threshold (e.g., > 1.5 score) before injecting *anything* into Qwen3 to prevent forcing it to hallucinate.

## **11. Monthly Auto-Refresh (GitHub Actions)** 

Because bank websites block scrapers, we cannot auto-download the HTML. Instead, we use a smart header-check: 

```
# .github/workflows/refresh_kb.yml
# Runs on the 1st of every month at midnight
steps:
```

`1. Run scripts/refresh_kb.py` 

`2. Script uses Playwright (headless browser) to fetch the actual <body> text of all 25 URLs` 

`3. Hashes the text (SHA-256) and compares it against the stored hash from last month` 

`4. If a page content changed (bypassing all CDN/WAF header stripping tricks), script exits with Error Code 1` 

`5. GitHub Action catches Error Code 1 and automatically opens a Repo Issue:` 

- `"Action Required: HDFC updated their security page. Please manually re-save."` 

This ensures our Knowledge Base stays fresh, without getting IP-banned by bank firewalls or fooled by Cloudflare CDN caching. 

## **12. What Changes for the User** 

The user experience on the mobile app **stays identical** — same Call Analyzer screen, same verdict display. But behind the scenes: 

https://markdownlivepreview.com 

7/9 

 

|9/23/26, 2:34 PM||Markdown Live Preview|
|---|---|---|
|**What changes**|**Before**|**After**|
|Response time|2–5 seconds (Tavily call)|**<5ms (local KB)**|
|Policy affects Score|❌No (Bug 1)|✅ **Yes**|
|Qwen3 reads rules|❌No (Bug 2)|✅ **Yes (Prompt Injected)**|
|Works offline|❌No|✅Yes (KB is local)|
|Source citation|Sometimes|✅Always|
|Source date shown|❌Never|✅Always ("Policy as of Sep 2024")|
|Coverage|17 orgs|✅25+ orgs|
|Cost|Tavily credits|✅Free forever|
|Hinglish support|❌Limited|✅Alias mapping|



## **13. Implementation Order (5 Phases)** 

We will execute this upgrade over 5 focused days: 

```
Phase 1 (Day 1)  → ✅ COMPLETED! (Plumbing bugs, dynamic weights, 7-layer architecture built)
```

```
Phase 2 (Day 2)  → Expand org_policies.json
                   Add 8 new orgs + Hinglish aliases + 6 scam scripts.
```

```
Phase 3 (Day 3)  → Build the Offline Library
                   Write parse_kb.py, chunk_kb.py, and build_kb.py.
                   Generate the first kb_chunks.json.
```

```
Phase 4 (Day 4)  → Wire Everything Together
                   Write kb_search.py (BM25 engine).
                   Update live_policy_agent.py to use KB first.
                   Inject KB chunks into Qwen3 AND policy_verification.py offline engine.
```

```
Phase 5 (Day 5)  → Testing & Automation
                   Run 20 accuracy test scenarios.
                   Set up GitHub Actions refresh_kb.yml.
                   Deploy to Render/Railway.
```

## **14. Summary** 

We are fixing critical pipeline bugs and replacing an internet-dependent, paid, slow fact-checking system with a **free, offline, instant, and more accurate** one — built from official Indian bank and government documents. 

The system: 

1. **Parses** official fraud warnings from manually-saved HTML pages. 

2. **Chunks** them into 150-word searchable pieces, tagged with policy type. 

3. **Searches** with BM25 (fast, lightweight, accurate). 

4. **Synthesizes** a verdict with Qwen3 AI, handing it the exact official text. 

https://markdownlivepreview.com 

8/9 

9/23/26, 2:34 PM 

Markdown Live Preview 

 

5. **Forces** the score to CRITICAL if a strict bank policy is violated. 

6. **Cites** the source document with date. 

7. **Monitors** bank website updates automatically via GitHub Actions. 

The result: when someone reports a suspicious call from "SBI asking for OTP", the app gives a verdict instantly, successfully updates the score, states _"SBI explicitly states they never ask for OTP"_ , and links directly to `sbi.co.in` (September 2024). 

https://markdownlivepreview.com 

9/9 

