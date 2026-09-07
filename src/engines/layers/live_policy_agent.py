"""
SafeMail X - Live Policy Fact-Checker Agent
============================================
When an org is detected, searches the official website in real-time
to verify if the caller's claimed behavior is legitimate.

Flow:
  1. Resolve official policy URL (pre-mapped or Tavily search)
  2. Fetch + scrape page content
  3. Qwen3 reads the page and answers: Is this behavior allowed?
  4. Return verdict + direct source link

Full fallback chain:
  Tavily -> pre-mapped URL scrape -> static org_policies.json -> "cannot verify"
"""

import hashlib
import json
import logging
import re
import time
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger("LIVE_POLICY_AGENT")

# ── In-memory cache (org_key -> result, expires after 24h) ───────────────────
_CACHE: dict = {}
_CACHE_TTL = 86400  # 24 hours

def _cache_key(org: str, action_type: str) -> str:
    return hashlib.md5(f"{org.lower().strip()}::{action_type.lower().strip()}".encode()).hexdigest()

def _cache_get(key: str) -> Optional[dict]:
    entry = _CACHE.get(key)
    if entry and (time.time() - entry["ts"]) < _CACHE_TTL:
        logger.info("[LIVE_POLICY] Cache hit for key=%s", key[:8])
        return entry["data"]
    return None

def _cache_set(key: str, data: dict):
    _CACHE[key] = {"data": data, "ts": time.time()}


# ── Tavily search ─────────────────────────────────────────────────────────────

def _tavily_search(query: str, official_domain: str = "") -> list[dict]:
    """Search Tavily AI for official policy pages. Returns list of {url, content}."""
    try:
        from utils.config import TAVILY_API_KEY
    except ImportError:
        TAVILY_API_KEY = ""
    try:
        import os
        TAVILY_API_KEY = TAVILY_API_KEY or os.getenv("TAVILY_API_KEY", "")
    except Exception:
        pass

    if not TAVILY_API_KEY:
        logger.info("[LIVE_POLICY] No TAVILY_API_KEY — skipping web search.")
        return []

    search_query = query
    if official_domain:
        search_query = f"site:{official_domain} {query}"

    try:
        from tavily import TavilyClient
        client = TavilyClient(api_key=TAVILY_API_KEY)
        resp = client.search(
            query=search_query,
            search_depth="advanced",
            max_results=3,
            include_raw_content=True,
        )
        results = []
        for r in resp.get("results", []):
            content = (r.get("raw_content") or r.get("content") or "").strip()
            url = r.get("url", "")
            if content and url:
                results.append({"url": url, "content": content[:4000]})
        logger.info("[LIVE_POLICY] Tavily returned %d results.", len(results))
        return results
    except ImportError:
        logger.info("[LIVE_POLICY] tavily-python not installed.")
        return []
    except Exception as e:
        logger.warning("[LIVE_POLICY] Tavily search failed: %s", e)
        return []


def _scrape_url(url: str, timeout: int = 8) -> str:
    """Scrape a URL and return clean text content."""
    try:
        headers = {"User-Agent": "Mozilla/5.0 (SafeMailX Policy Checker/1.0)"}
        resp = requests.get(url, headers=headers, timeout=timeout)
        resp.raise_for_status()

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "lxml")
        except ImportError:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")

        # Remove nav/footer/script
        for tag in soup(["script","style","nav","footer","header","aside","form"]):
            tag.decompose()

        text = soup.get_text(separator="\n")
        # Clean up whitespace
        lines = [l.strip() for l in text.splitlines() if len(l.strip()) > 30]
        return "\n".join(lines)[:4000]
    except Exception as e:
        logger.warning("[LIVE_POLICY] Scrape failed for %s: %s", url, e)
        return ""


def _load_org_policies() -> dict:
    path = Path(__file__).resolve().parents[2] / "data" / "org_policies.json"
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _find_org_entry(org_claimed: str) -> Optional[dict]:
    policies = _load_org_policies()
    org_lower = org_claimed.lower()
    for key, entry in policies.items():
        if entry.get("name","").lower() in org_lower or org_lower in entry.get("name","").lower():
            return entry
        for alias in entry.get("aliases", []):
            if alias.lower() in org_lower or org_lower in alias.lower():
                return entry
    return None


def _qwen3_read_policy(org: str, action_claim: str, page_text: str, source_url: str) -> Optional[dict]:
    """Ask Qwen3 to read the official page and answer the policy question."""
    system = f"""You are a fraud policy fact-checker for SafeMail X.
You are given text from {org}'s OFFICIAL website.
Answer ONLY based on what the page says - do not use outside knowledge.

Return ONLY a JSON object:
{{
  "policy_allows": <true | false | null (if page doesn't address this)>,
  "policy_quote": <exact quote from the page that answers the question, max 200 chars, or null>,
  "confidence": <float 0.0-1.0>,
  "verdict_text": <1 sentence plain English verdict for the user>
}}"""

    user = f"""Official page from {org} (source: {source_url}):

---
{page_text[:3000]}
---

Question: Does {org} call customers to perform the following action over the phone?
Action: "{action_claim}"

Answer ONLY from the page content above. Return the JSON."""

    try:
        from engines.layers.qwen_call_layer import _get_llm_cfg, _parse_json
        cfg = _get_llm_cfg()
        payload = {
            "model": cfg["model"],
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
            "temperature": 0.1,
            "top_p": 0.80,
            "max_tokens": 400,
            "stream": False,
        }
        if cfg["thinking"]:
            payload["chat_template_kwargs"] = {"enable_thinking": True}

        resp = requests.post(cfg["base_url"], json=payload, timeout=45)
        resp.raise_for_status()
        content = (resp.json()["choices"][0]["message"].get("content","") or "").strip()
        parsed = _parse_json(content)
        if parsed and isinstance(parsed, dict):
            return parsed
    except Exception as e:
        logger.warning("[LIVE_POLICY] Qwen3 policy read failed: %s", e)
    return None


def check(org_claimed: str, actions_requested: list, timeout: int = 50) -> dict:
    """
    Main entry point: verify whether org's claimed actions are legitimate
    by searching their official website in real-time.

    Returns:
    {
        "checked": bool,
        "policy_allows": bool | None,
        "verdict_text": str,
        "policy_quote": str | None,
        "source_url": str | None,
        "source_label": str | None,
        "confidence": float,
        "error": str | None,
    }
    """
    _not_checked = {
        "checked": False, "policy_allows": None,
        "verdict_text": "", "policy_quote": None,
        "source_url": None, "source_label": None,
        "confidence": 0.0, "error": None,
    }

    if not org_claimed or not org_claimed.strip():
        return {**_not_checked, "error": "No org name provided"}

    action_claim = ", ".join(actions_requested) if actions_requested else "call customers"
    cache_key = _cache_key(org_claimed, action_claim)

    cached = _cache_get(cache_key)
    if cached:
        return cached

    org_entry = _find_org_entry(org_claimed)
    page_text = ""
    source_url = ""
    source_label = ""

    # Step 1: Try pre-mapped official policy URLs (fastest, most reliable)
    policy_urls = org_entry.get("policy_urls", []) if org_entry else []
    for url in policy_urls[:2]:
        text = _scrape_url(url, timeout=8)
        if len(text) > 200:
            page_text = text
            source_url = url
            # Extract domain as label
            m = re.match(r"https?://(?:www\.)?([^/]+)", url)
            source_label = m.group(1) if m else url
            logger.info("[LIVE_POLICY] Used pre-mapped URL: %s", url)
            break

    # Step 2: Tavily search if no pre-mapped URL worked
    if not page_text:
        official_domain = org_entry.get("official_domain", "") if org_entry else ""
        org_name = org_entry.get("name", org_claimed) if org_entry else org_claimed

        # Build action-aware queries — prioritise fraud awareness pages
        action_lower = action_claim.lower()
        if any(k in action_lower for k in ["otp", "one time", "password", "pin", "cvv"]):
            query = f'"{org_name}" "never ask" OTP password phone call fraud awareness'
        elif any(k in action_lower for k in ["kyc", "know your customer", "verification"]):
            query = f'"{org_name}" KYC phone call fraud awareness "never call"'
        elif any(k in action_lower for k in ["install", "app", "anydesk", "teamviewer", "screen"]):
            query = f'"{org_name}" remote access app phone call scam fraud'
        elif any(k in action_lower for k in ["arrest", "police", "court", "legal", "warrant"]):
            query = f'"digital arrest" scam fraud India official advisory'
        elif any(k in action_lower for k in ["upi", "payment", "transfer", "money"]):
            query = f'"{org_name}" UPI payment phone call fraud scam advisory'
        else:
            query = f'"{org_name}" phone call fraud awareness safety tips official'

        # Try with domain restriction first, then without
        results = _tavily_search(query, official_domain=official_domain)
        if not results:
            results = _tavily_search(query, official_domain="")

        if results:
            best = results[0]
            page_text = best["content"]
            source_url = best["url"]
            m = re.match(r"https?://(?:www\.)?([^/]+)", source_url)

            source_label = m.group(1) if m else source_url

    # Step 3: No content found — return graceful fallback
    if not page_text:
        result = {
            **_not_checked,
            "verdict_text": f"Could not find official policy page for {org_claimed}. "
                            "Call the organization's official number to verify.",
            "error": "no_content_found",
        }
        _cache_set(cache_key, result)
        return result

    # Step 4: Ask Qwen3 to read the policy page
    qwen_result = _qwen3_read_policy(org_claimed, action_claim, page_text, source_url)

    if qwen_result:
        result = {
            "checked": True,
            "policy_allows": qwen_result.get("policy_allows"),
            "verdict_text": qwen_result.get("verdict_text", ""),
            "policy_quote": qwen_result.get("policy_quote"),
            "source_url": source_url,
            "source_label": source_label,
            "confidence": float(qwen_result.get("confidence", 0.75)),
            "error": None,
        }
    else:
        # Qwen3 failed but we have the page — return page source at least
        result = {
            "checked": True,
            "policy_allows": None,
            "verdict_text": f"Found {org_claimed}'s official page but could not extract a clear policy statement. View the source to verify.",
            "policy_quote": None,
            "source_url": source_url,
            "source_label": source_label,
            "confidence": 0.40,
            "error": "qwen_read_failed",
        }

    _cache_set(cache_key, result)
    logger.info(
        "[LIVE_POLICY] %s | allows=%s | conf=%.2f | src=%s",
        org_claimed, result["policy_allows"], result["confidence"], source_label
    )
    return result
