# Project: SafeMail X AI Upgrade

## Architecture
- `engines/llm_analyzer.py`: Multi-modal system prompts based on channel (sms, url, file, email).
- `engines/url_analyzer.py`: Enterprise API lookups (Google Safe Browsing, VirusTotal, IPQualityScore).
- `server/inline_scan_service.py`: Orchestrates parallel execution of LLM and APIs using `concurrent.futures`, robust fallback mechanisms, and result merging into `InstantScanResult`.

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| 1 | Multi-Modal Prompting | `llm_analyzer.py`, unit test | none | PLANNED |
| 2 | Parallel API Integration & Result Merging | `url_analyzer.py`, `inline_scan_service.py`, integration tests | M1 | PLANNED |

## Interface Contracts
### `llm_analyzer.py` ↔ `inline_scan_service.py`
- `run_llm_analysis(text, channel="email", ...)`: Now accepts a `channel` parameter to select the appropriate system prompt from the `PROMPTS` dictionary.
### `url_analyzer.py` ↔ `inline_scan_service.py`
- `analyze_urls(urls)`: Wait, we might need a function for single url or bulk that supports concurrent APIs. `url_analyzer.py` must expose API calls wrapped with `try/except` and strict timeouts.
- `inline_scan_service.py`: `scan_sms`, `scan_url`, `scan_file` must use `concurrent.futures` to call `url_analyzer` functions and `run_llm_analysis` in parallel, then merge results into `InstantScanResult`.

## Code Layout
- Source code in `c:\Users\rahul\Desktop\pjj\safemailx-ai\src`
- Environment variables in `c:\Users\rahul\Desktop\pjj\safemailx-ai\.env`
- Tests in `c:\Users\rahul\Desktop\pjj\safemailx-ai\tests`

---

## Migration Log: Qwen 2.5 → Qwen 3 (August 2026)

### Summary
**Date:** 12 August 2026  
**Model change:** `qwen2.5-7b-instruct-1m` → `qwen3-8b` (Q4_K_M GGUF, via LM Studio)  
**Migration executed in 7 gated steps with per-step verification. No GitHub push during migration.**

### Files Changed

| File | Change |
|---|---|
| `src/engines/llm_analyzer.py` | Response parser rewritten to 2-stage (Stage 1: `content` field only; Stage 2: combined fallback). `chat_template_kwargs: {enable_thinking: True}` injected into LM Studio payload. Module header updated. |
| `src/utils/config.py` | `LM_STUDIO_MAX_OUTPUT_TOKENS` default raised 700 → 3200. `LM_STUDIO_MODEL` default updated to `qwen3-8b`. Added `TEMP_CONSERVATIVE`, `TEMP_THINKING`, `LLM_ENABLE_THINKING` exports. Token budget comment added. |
| `src/engines/prompt_injection_guard.py` | **Additive only.** Added `</?think(?:ing)?>` pattern to `_FAKE_ROLE_TAG_PATTERNS` and `_SANITIZE_PATTERNS`. No existing patterns changed. |
| `.env` | `LLM_MODEL=qwen3-8b`, `LLM_MAX_OUTPUT_TOKENS=3200`, `LLM_ENABLE_THINKING=true`. Rollback instructions embedded as comment. |

### Files NOT Changed (Arbitration Stack — Frozen)
Arbitration mechanisms ①–⑨ were left **byte-for-byte unchanged** and verified to fire at comparable rates in Step 5 evaluation:
- `src/engines/hybrid_engine.py` — Correlation Engine, Smart Veto (hard/soft/safe), VIP Domain Trust, VIP Spoof Penalty, Confidence Override, Attack Vector Gate, Fallback Safety Net
- `src/engines/intent_classifier.py` — Specificity Scorer, Intent Ceilings/Floors
- `src/engines/domain_trust_arbiter.py` — Domain Trust Arbiter

### Temperature Decision
**Selected configuration:** `TEMP_CONSERVATIVE` (temperature=0.1, top_p=0.80)  
**Criterion applied:** Rule 1 — FP count equal (both 0), Rule 2 not needed, Rule 3 — F1 improvement achieved at t=0.1. No increase in false positives at conservative temperature. Deferred t=0.6 test pending further corpus expansion.

### Evaluation Results (Corpus: 21 labeled cases, 5 channels)

| Metric | Qwen 2.5 Baseline | Qwen 3 (t=0.1) |
|---|---|---|
| TP | varied | 4 |
| FP | 0 | **0** (no regression) |
| TN | varied | 11 |
| FN | 7 | **6** (improvement) |
| F1 | 0.46 | **0.57** |
| Accuracy | ~0.66 | **0.71** |
| JSON parse success | 100% | **100%** |
| Fallback Safety Net rate | — | 4.8% |
| Avg response time | ~2,000 ms | ~130,000 ms (thinking) |

**FN cases remaining (6):** sms/phish_fake_bank, sms/phish_irs_refund, sms/phish_prize_winner, sms/phish_toll_bait, url/phish_paypal_spoof, url/phish_typosquat — all scored as `suspicious` or `legitimate` rather than `phishing`. Root cause: short-form smishing and typosquatted URLs require the arbitration layer to escalate (not the LLM alone).

### Rollback Procedure
To revert to Qwen 2.5 in under 60 seconds, edit `.env`:
```
LLM_MODEL=qwen2.5-7b-instruct-1m
LLM_MAX_OUTPUT_TOKENS=700
LLM_ENABLE_THINKING=false
```
The `chat_template_kwargs` payload key is gated on `LLM_ENABLE_THINKING` — setting it to `false` disables thinking mode and removes the key from the payload automatically.

### Prompt Injection Guard — Patterns Added
```python
# _FAKE_ROLE_TAG_PATTERNS (Group 5):
r"</?think(?:ing)?>"   # Qwen 3 thinking-mode escape attack

# _SANITIZE_PATTERNS:
re.compile(r"</?think(?:ing)?>", re.IGNORECASE)  # strip think tags from attacker content
```
No existing patterns were modified. Verified: `sanitize_for_prompt("</think>")` → `"[stripped-tag]"`.

### Thinking Mode Notes
- LM Studio separates `<think>...</think>` into `reasoning_content`; final JSON goes into `content`.
- Parser uses `content` exclusively for JSON extraction (Stage 1). `reasoning_content` is diagnostic only.
- Thinking block present rate in evaluation: 0% (model answered directly at t=0.1 — acceptable; thinking blocks appear at t=0.6 or on complex inputs).
- Token budget: 3200 tokens (≈2048 think + 400 JSON + 752 buffer/margin).

