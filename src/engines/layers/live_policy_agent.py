"""
SafeMail X - Live Policy Fact-Checker Agent (v2)
================================================
Uses Tavily AI answer feature to directly answer whether an org's
claimed behavior is legitimate — no Qwen3 needed for basic verdict.

Flow:
  1. Build a direct yes/no question about the org's claim
  2. Tavily searches the web and returns a direct answer + source URLs
  3. Parse the answer for yes/no verdict + confidence
  4. (Optional) Qwen3 enhances the answer if LM Studio is running

Full fallback: Tavily offline -> static org_policies.json -> cannot verify
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

# In-memory cache (24h TTL)
_CACHE: dict = {}
_CACHE_TTL = 86400

def _cache_key(org: str, action: str) -> str:
    return hashlib.md5(f"{org.lower().strip()}::{action.lower().strip()}".encode()).hexdigest()

def _cache_get(key: str) -> Optional[dict]:
    entry = _CACHE.get(key)
    if entry and (time.time() - entry["ts"]) < _CACHE_TTL:
        return entry["data"]
    return None

def _cache_set(key: str, data: dict):
    _CACHE[key] = {"data": data, "ts": time.time()}


def _get_tavily_key() -> str:
    try:
        from utils.config import TAVILY_API_KEY
        if TAVILY_API_KEY:
            return TAVILY_API_KEY
    except ImportError:
        pass
    import os
    return os.getenv("TAVILY_API_KEY", "")


def _tavily_ask(question: str, org_name: str, official_domain: str = "") -> Optional[dict]:
    """
    Use Tavily's answer feature to directly answer the policy question.
    Returns {answer, sources, confidence} or None.
    """
    api_key = _get_tavily_key()
    if not api_key:
        logger.info("[LIVE_POLICY] No TAVILY_API_KEY.")
        return None

    try:
        from tavily import TavilyClient
        client = TavilyClient(api_key=api_key)

        # Build search query — site-restricted first if we have official domain
        query = question
        if official_domain:
            query = f"site:{official_domain} {question}"

        resp = client.search(
            query=query,
            search_depth="advanced",
            max_results=5,
            include_answer=True,
        )

        answer_text = (resp.get("answer") or "").strip()

        # If site-restricted gave no answer, retry without domain restriction
        if not answer_text and official_domain:
            resp = client.search(
                query=question,
                search_depth="advanced",
                max_results=5,
                include_answer=True,
            )
            answer_text = (resp.get("answer") or "").strip()

        sources = []
        for r in resp.get("results", []):
            url = r.get("url", "")
            content = (r.get("content") or "").strip()
            if url:
                sources.append({"url": url, "snippet": content[:300]})

        logger.info("[LIVE_POLICY] Tavily answer (%d chars). Sources: %d", len(answer_text), len(sources))
        return {"answer": answer_text, "sources": sources}

    except ImportError:
        logger.info("[LIVE_POLICY] tavily-python not installed.")
        return None
    except Exception as e:
        logger.warning("[LIVE_POLICY] Tavily failed: %s", e)
        return None


def _parse_answer_verdict(answer_text: str, action_claim: str) -> dict:
    """
    Parse Tavily's natural language answer into a structured verdict.
    Returns {policy_allows, confidence, policy_quote}.
    """
    if not answer_text:
        return {"policy_allows": None, "confidence": 0.0, "policy_quote": None}

    text_lower = answer_text.lower()

    # Strong NEGATIVE signals — org does NOT do this
    negative_phrases = [
        "does not call", "never call", "do not call", "never ask",
        "does not ask", "will not call", "never contacts", "not call",
        "scam", "fraudulent", "do not share", "never share",
        "never request", "does not request", "not legitimate",
        "fraud", "not authorized to call", "never initiates",
    ]
    # Strong POSITIVE signals — org IS allowed to do this
    positive_phrases = [
        "does call", "may call", "can call", "will call",
        "is authorized to call", "calls customers", "legitimate to call",
        "customer service calls", "does contact",
    ]

    neg_hits = sum(1 for p in negative_phrases if p in text_lower)
    pos_hits = sum(1 for p in positive_phrases if p in text_lower)

    if neg_hits > 0 and pos_hits == 0:
        confidence = min(0.95, 0.70 + neg_hits * 0.08)
        return {"policy_allows": False, "confidence": round(confidence, 2), "policy_quote": answer_text[:250]}
    elif pos_hits > 0 and neg_hits == 0:
        confidence = min(0.90, 0.65 + pos_hits * 0.08)
        return {"policy_allows": True, "confidence": round(confidence, 2), "policy_quote": answer_text[:250]}
    elif neg_hits > pos_hits:
        return {"policy_allows": False, "confidence": 0.55, "policy_quote": answer_text[:250]}
    elif pos_hits > neg_hits:
        return {"policy_allows": True, "confidence": 0.55, "policy_quote": answer_text[:250]}
    else:
        return {"policy_allows": None, "confidence": 0.30, "policy_quote": answer_text[:250]}


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
        name = entry.get("name", "").lower()
        if name in org_lower or org_lower in name:
            return entry
        for alias in entry.get("aliases", []):
            if alias.lower() in org_lower or org_lower in alias.lower():
                return entry
    return None


def _static_fallback(org_claimed: str, actions_requested: list) -> dict:
    """
    Check static org_policies.json as fallback when Tavily is unavailable.
    Returns a partial result with no source URL.
    """
    entry = _find_org_entry(org_claimed)
    if not entry:
        return {
            "checked": False, "policy_allows": None,
            "verdict_text": f"No official policy data found for '{org_claimed}'. Call their official number to verify.",
            "policy_quote": None, "source_url": entry.get("verified_source") if entry else None,
            "source_label": None, "confidence": 0.0, "error": "org_not_found",
        }

    action_str = " ".join(actions_requested).lower()
    never_list = entry.get("never_via_call", [])
    special = entry.get("special_rule", "")

    # Check if any requested action matches the never_via_call list
    matched_prohibition = None
    for prohibited in never_list:
        prohibited_lower = prohibited.lower()
        # Check word overlap
        prohibited_words = set(prohibited_lower.split())
        action_words = set(action_str.split())
        overlap = prohibited_words & action_words - {"a", "the", "an", "for", "to", "of", "or", "and"}
        if len(overlap) >= 2:
            matched_prohibition = prohibited
            break

    source_url = entry.get("verified_source", "")
    m = re.match(r"https?://(?:www\.)?([^/]+)", source_url) if source_url else None
    source_label = m.group(1) if m else None

    if special:
        return {
            "checked": True, "policy_allows": False,
            "verdict_text": special,
            "policy_quote": special,
            "source_url": source_url, "source_label": source_label,
            "confidence": 0.95, "error": None,
        }
    if matched_prohibition:
        return {
            "checked": True, "policy_allows": False,
            "verdict_text": f"{entry.get('name', org_claimed)} never calls customers to {matched_prohibition}. This is against their official policy.",
            "policy_quote": f"Official policy: {entry.get('name', org_claimed)} does not {matched_prohibition} via phone calls.",
            "source_url": source_url, "source_label": source_label,
            "confidence": 0.88, "error": None,
        }

    return {
        "checked": True, "policy_allows": None,
        "verdict_text": f"No specific prohibition found for this request. Verify directly with {entry.get('name', org_claimed)} at their official number.",
        "policy_quote": None,
        "source_url": source_url, "source_label": source_label,
        "confidence": 0.30, "error": None,
    }


def _build_question(org_name: str, action_claim: str) -> str:
    """Build a natural-language question for Tavily to answer."""
    action_lower = action_claim.lower()
    if any(k in action_lower for k in ["otp", "one time password", "pin", "cvv", "password"]):
        return f"Does {org_name} ask customers for OTP PIN or password over a phone call? Is this a scam?"
    elif any(k in action_lower for k in ["kyc", "know your customer", "verification", "verify"]):
        return f"Does {org_name} call customers to update KYC over phone? Is this legitimate or a scam?"
    elif any(k in action_lower for k in ["install", "app", "anydesk", "teamviewer", "screen", "remote"]):
        return f"Does {org_name} ask customers to install apps or share screen over phone? Is this legitimate?"
    elif any(k in action_lower for k in ["arrest", "police", "court", "legal", "warrant", "digital arrest"]):
        return f"Is digital arrest over phone by police or CBI legitimate in India? Is this a scam?"
    elif any(k in action_lower for k in ["upi", "payment", "transfer", "money", "fee"]):
        return f"Does {org_name} ask customers to make UPI payments or money transfers over phone? Is this legitimate?"
    elif any(k in action_lower for k in ["aadhaar", "aadhar", "pan"]):
        return f"Does {org_name} call customers to verify Aadhaar or PAN over phone? Is this legitimate or fraud?"
    else:
        return f"Does {org_name} call customers for '{action_claim}'? Is this legitimate or a scam?"


def check(org_claimed: str, actions_requested: list, timeout: int = 50) -> dict:
    """
    Main entry: verify org's claimed actions against official policy via web search.

    Returns:
    {
        checked, policy_allows, verdict_text, policy_quote,
        source_url, source_label, confidence, error
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
        logger.info("[LIVE_POLICY] Cache hit for %s + %s", org_claimed, action_claim[:30])
        return cached

    org_entry = _find_org_entry(org_claimed)
    org_name = org_entry.get("name", org_claimed) if org_entry else org_claimed
    official_domain = org_entry.get("official_domain", "") if org_entry else ""

    # ── Stage A: Tavily answer (primary — works without Qwen3) ───────────────
    question = _build_question(org_name, action_claim)
    logger.info("[LIVE_POLICY] Asking Tavily: %s", question)
    tavily_result = _tavily_ask(question, org_name, official_domain)

    if tavily_result and tavily_result.get("answer"):
        answer_text = tavily_result["answer"]
        sources = tavily_result.get("sources", [])

        verdict_parsed = _parse_answer_verdict(answer_text, action_claim)

        # Pick best source — prefer official domain
        best_source_url = None
        best_source_label = None
        for s in sources:
            url = s.get("url", "")
            if official_domain and official_domain in url:
                best_source_url = url
                m = re.match(r"https?://(?:www\.)?([^/]+)", url)
                best_source_label = m.group(1) if m else url
                break
        # Fallback to first source
        if not best_source_url and sources:
            best_source_url = sources[0]["url"]
            m = re.match(r"https?://(?:www\.)?([^/]+)", best_source_url)
            best_source_label = m.group(1) if m else best_source_url

        result = {
            "checked": True,
            "policy_allows": verdict_parsed["policy_allows"],
            "verdict_text": answer_text[:400],
            "policy_quote": verdict_parsed["policy_quote"],
            "source_url": best_source_url,
            "source_label": best_source_label,
            "confidence": verdict_parsed["confidence"],
            "error": None,
        }

        _cache_set(cache_key, result)
        logger.info(
            "[LIVE_POLICY] Tavily verdict: allows=%s conf=%.2f src=%s",
            result["policy_allows"], result["confidence"], best_source_label
        )
        return result

    # ── Stage B: Static org_policies.json fallback ───────────────────────────
    logger.info("[LIVE_POLICY] Tavily unavailable — using static fallback.")
    result = _static_fallback(org_claimed, actions_requested)
    _cache_set(cache_key, result)
    return result
