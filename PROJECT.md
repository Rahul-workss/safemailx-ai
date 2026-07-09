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
