import base64
import email
import hashlib
import ipaddress
import json
import logging
import re
import socket
import uuid
from email.utils import parseaddr
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup

from engines.analyzers.docx_analyzer import analyze_docx
from engines.analyzers.pdf_analyzer import analyze_pdf
from engines.hybrid_engine import hybrid_detect
from engines.llm_analyzer import run_llm_analysis
from engines.url_analyzer import (
    check_bloom_filter,
    check_offline_prefix,
    get_entropy_metrics,
    get_rdap_age_days,
    get_typosquatting_metrics,
)
from server.schemas import InstantScanResult, QuickScanArtifacts, QuickScanSignal, Verdict
from server.uploads import IMAGE_EXTENSIONS, extract_upload_text
from utils.config import (
    IPQUALITYSCORE_API_KEY,
    SAFE_BROWSING_API_KEY,
    VIRUSTOTAL_API_KEY,
    is_configured_secret,
)
from utils.content_processor import clean_extracted_text
from utils.email_parser import _html_text_and_images, _is_cta_text, parse_security_headers
from utils.url_extractor import SHORT_URL_DOMAINS, extract_urls


logger = logging.getLogger("INSTANT_SCAN_ENGINE")

URL_TOKEN_RE = re.compile(
    r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:/[^\s<>'\"]*)?)(?:[^\s<>'\"]*)?)"
)
PHONE_RE = re.compile(r"\+?\d[\d\s().-]{7,}\d")

SMS_OTP_MARKERS = ("otp", "one-time password", "verification code", "auth code", "security code", "login code")
SMS_DELIVERY_MARKERS = ("delivery", "package", "parcel", "track", "tracking", "courier", "usps", "fedex", "ups", "dhl", "toll")
SMS_REWARD_MARKERS = ("claim", "reward", "prize", "gift", "won", "winner", "bonus", "offer", "free")
SMS_PRESSURE_MARKERS = ("urgent", "immediately", "act now", "expires", "final notice", "last chance", "locked", "suspended")
SMS_ACTION_MARKERS = ("click", "tap", "verify", "pay", "claim", "track", "update", "login", "open")
URL_BAIT_MARKERS = ("login", "signin", "verify", "password", "secure", "account", "update", "billing", "invoice", "wallet", "payment")

KNOWN_BRANDS = {
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in"},
    "bank": {"chase.com", "bankofamerica.com", "capitalone.com", "wellsfargo.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "google": {"google.com", "gmail.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com"},
    "netflix": {"netflix.com"},
    "paypal": {"paypal.com"},
    "ups": {"ups.com"},
    "usps": {"usps.com"},
}

FILE_PRIVACY_NOTICE = (
    "This scan may query Google Safe Browsing, VirusTotal, IPQualityScore, and local threat feeds when configured. "
    "Only extracted URLs, domains, and file hashes may be checked externally; raw file bytes are not sent to third-party providers."
)
URL_PRIVACY_NOTICE = (
    "This scan may query Google Safe Browsing, VirusTotal, IPQualityScore, and local threat feeds when configured. "
    "Submitted URLs may also be fetched in a controlled no-login mode to resolve redirects and inspect lightweight HTML."
)
SMS_PRIVACY_NOTICE = (
    "This scan may query Google Safe Browsing, VirusTotal, IPQualityScore, and local threat feeds when configured. "
    "If the message contains links, those URLs and domains may be checked externally."
)


def _base_domain(host: str) -> str:
    parts = (host or "").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (host or "")


def _is_reserved_test_domain(host: str) -> bool:
    base = _base_domain(host)
    return base in {"example.com", "example.org", "example.net"} or host.endswith(
        (".test", ".invalid", ".localhost")
    )


def _candidate_to_url(token: str) -> str | None:
    token = token.strip(" \t\r\n<>[](){}\"'.,;:!?")
    if not token or "@" in token:
        return None
    if token.lower().startswith("http://") or token.lower().startswith("https://"):
        url = token
    elif token.lower().startswith("www."):
        url = f"https://{token}"
    elif "." in token:
        url = f"https://{token}"
    else:
        return None

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return urlunparse(parsed._replace(scheme=parsed.scheme.lower(), netloc=parsed.netloc.lower(), fragment=""))


def _extract_urls_from_text(text: str) -> list[dict[str, Any]]:
    records = {record["normalized_url"]: record for record in extract_urls(text or "")}
    for match in URL_TOKEN_RE.finditer(text or ""):
        normalized = _candidate_to_url(match.group(1))
        if not normalized or normalized in records:
            continue
        parsed = urlparse(normalized)
        domain = (parsed.hostname or "").lower()
        records[normalized] = {
            "raw_url": match.group(1),
            "normalized_url": normalized,
            "domain": domain,
            "is_ip": False,
            "is_short": domain in SHORT_URL_DOMAINS or any(domain.endswith("." + short) for short in SHORT_URL_DOMAINS),
            "flags": [],
            "safebrowsing_hit": False,
        }
    return list(records.values())


def _extract_brand_claims(text: str) -> list[str]:
    text_lower = (text or "").lower()
    claims = []
    for brand in KNOWN_BRANDS:
        if re.search(rf"\b{re.escape(brand)}\b", text_lower):
            claims.append(brand)
    return claims


def _extract_phone_numbers(text: str) -> list[str]:
    seen = []
    for match in PHONE_RE.findall(text or ""):
        cleaned = re.sub(r"\s+", " ", match).strip()
        if cleaned not in seen:
            seen.append(cleaned)
    return seen


def _classify_sender(sender: str | None) -> str:
    value = (sender or "").strip()
    if not value:
        return "unknown"
    if re.fullmatch(r"\+?\d[\d\s().-]{5,}\d", value):
        return "phone_number"
    if re.fullmatch(r"\d{3,8}", value):
        return "shortcode"
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9 _-]{2,15}", value):
        return "alphanumeric"
    return "unknown"


def _severity_for_weight(weight: int) -> str:
    if weight >= 35:
        return "critical"
    if weight >= 20:
        return "high"
    if weight >= 10:
        return "medium"
    return "low"


def _make_signal(name: str, description: str, weight: int, confidence: float) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "weight": weight,
        "severity": _severity_for_weight(weight),
        "confidence": max(0.05, min(confidence, 0.99)),
    }


def _signal_models(signals: list[dict[str, Any]]) -> list[QuickScanSignal]:
    ordered = sorted(signals, key=lambda item: (-item["weight"], -item["confidence"], item["name"]))
    return [
        QuickScanSignal(
            name=item["name"],
            description=item["description"],
            severity=item["severity"],
            confidence=round(item["confidence"], 2),
        )
        for item in ordered[:8]
    ]


def _normalize_confidence(score: int, degraded: bool, evidence_quality: str) -> float:
    base = 0.62
    if score >= 85:
        base = 0.95
    elif score >= 70:
        base = 0.88
    elif score >= 55:
        base = 0.8
    elif score >= 35:
        base = 0.72
    if evidence_quality == "low":
        base -= 0.08
    elif evidence_quality == "high":
        base += 0.03
    if degraded:
        base -= 0.12
    return round(max(0.35, min(base, 0.98)), 2)


def _recommended_action(verdict: Verdict, channel: str, category: str | None) -> str:
    if verdict == "phishing":
        if channel == "file":
            return "Do not open or forward this file. Keep it quarantined and delete it unless your security team needs a sample."
        if channel == "url":
            return "Do not open this link. If it came from a message, block the sender and report the URL as malicious."
        return "Do not click, reply, or share codes. Block the sender and report the message as smishing."
    if verdict == "suspicious":
        if channel == "url":
            return "Treat this link cautiously. Verify the destination through a trusted source before opening it."
        if channel == "file":
            return "Open this file only if you can confirm the sender and business context through a separate trusted channel."
        return "Do not act on the message until you verify the sender, link destination, or transaction context independently."
    if category == "transactional":
        return "This appears low risk, but still verify unexpected account activity or deliveries through the official app."
    return "No clear malicious evidence was found. Continue only if the context matches what you expected."


def _risk_to_verdict(score: int) -> Verdict:
    if score >= 80:
        return "phishing"
    if score >= 45:
        return "suspicious"
    return "legitimate"


def _provider_mode(external_checks_used: list[str]) -> str:
    return "hybrid_cloud" if any(
        provider in external_checks_used
        for provider in ("google_safe_browsing", "virustotal_url", "virustotal_file_hash", "ipqualityscore")
    ) else "local_only"


@lru_cache(maxsize=512)
def _safe_browsing_lookup(url: str) -> tuple[bool, str | None]:
    if not is_configured_secret(SAFE_BROWSING_API_KEY):
        return False, None
    try:
        response = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}",
            timeout=2.5,
            json={
                "client": {"clientId": "safemailx-ai", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            },
        )
        response.raise_for_status()
        matches = response.json().get("matches", [])
        if matches:
            return True, matches[0].get("threatType", "match")
    except Exception as exc:
        raise RuntimeError(str(exc)) from exc
    return False, None


@lru_cache(maxsize=512)
def _virustotal_url_lookup(url: str) -> tuple[int, int]:
    if not is_configured_secret(VIRUSTOTAL_API_KEY):
        return 0, 0
    url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").strip("=")
    response = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers={"x-apikey": VIRUSTOTAL_API_KEY},
        timeout=2.5,
    )
    response.raise_for_status()
    stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    return malicious, suspicious


@lru_cache(maxsize=512)
def _ipqs_url_lookup(url: str) -> dict[str, Any]:
    if not is_configured_secret(IPQUALITYSCORE_API_KEY):
        return {}
    response = requests.get(
        f"https://www.ipqualityscore.com/api/json/url/{IPQUALITYSCORE_API_KEY}/{requests.utils.quote(url, safe='')}",
        timeout=2.5,
    )
    response.raise_for_status()
    return response.json()


@lru_cache(maxsize=512)
def _virustotal_hash_lookup(sha256_hash: str) -> int:
    if not is_configured_secret(VIRUSTOTAL_API_KEY):
        return 0
    response = requests.get(
        f"https://www.virustotal.com/api/v3/files/{sha256_hash}",
        headers={"x-apikey": VIRUSTOTAL_API_KEY},
        timeout=2.5,
    )
    if response.status_code == 404:
        return 0
    response.raise_for_status()
    stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return int(stats.get("malicious", 0))


def _is_private_target(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        return any(
            (
                ip.is_private,
                ip.is_loopback,
                ip.is_link_local,
                ip.is_multicast,
                ip.is_reserved,
                ip.is_unspecified,
            )
        )
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False

    for info in infos:
        resolved = info[4][0]
        try:
            ip = ipaddress.ip_address(resolved)
            if any(
                (
                    ip.is_private,
                    ip.is_loopback,
                    ip.is_link_local,
                    ip.is_multicast,
                    ip.is_reserved,
                    ip.is_unspecified,
                )
            ):
                return True
        except ValueError:
            continue
    return False


def _controlled_fetch(url: str) -> dict[str, Any]:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host:
        return {"blocked": True, "reason": "missing_host", "redirect_chain": []}
    if _is_private_target(host):
        return {"blocked": True, "reason": "private_target_blocked", "redirect_chain": []}
    if _is_reserved_test_domain(host):
        return {"blocked": True, "reason": "test_domain_skipped", "redirect_chain": [url]}

    headers = {"User-Agent": "SafeMailX/1.0", "Accept": "text/html,application/xhtml+xml"}
    redirect_chain: list[str] = []
    current_url = url
    title = None
    forms = 0
    content_snippet = ""
    for _ in range(5):
        response = requests.get(
            current_url,
            timeout=(2.5, 3.5),
            allow_redirects=False,
            stream=True,
            headers=headers,
        )
        redirect_chain.append(current_url)
        if 300 <= response.status_code < 400 and response.headers.get("Location"):
            next_url = urljoin(current_url, response.headers["Location"])
            next_host = urlparse(next_url).hostname or ""
            response.close()
            if next_host and _is_private_target(next_host):
                return {
                    "blocked": True,
                    "reason": "redirect_to_private_target",
                    "redirect_chain": redirect_chain + [next_url],
                }
            current_url = next_url
            continue

        content_type = response.headers.get("Content-Type", "").lower()
        if "text/html" in content_type:
            body = response.text[:200000]
            soup = BeautifulSoup(body, "html.parser")
            title = (soup.title.string or "").strip() if soup.title and soup.title.string else None
            forms = len(soup.find_all("form"))
            content_snippet = clean_extracted_text(soup.get_text(" ", strip=True))[:4000]
        response.close()
        return {
            "blocked": False,
            "redirect_chain": redirect_chain,
            "final_url": current_url,
            "title": title,
            "forms": forms,
            "content_snippet": content_snippet,
        }

    return {"blocked": False, "redirect_chain": redirect_chain, "final_url": current_url, "title": title, "forms": forms, "content_snippet": content_snippet}


def _llm_assessment(channel: str, text: str, features: dict[str, Any], subject: str = "", sender: str = "") -> dict[str, Any] | None:
    if not text.strip():
        return None
    try:
        return run_llm_analysis(
            channel=channel,
            email_text=text[:12000],
            subject=subject[:240],
            sender=sender[:240],
            security_summary=json.dumps(features, ensure_ascii=True)[:1800],
        )
    except Exception as exc:
        logger.debug("Quick scan LLM unavailable: %s", exc)
        return None


def _build_artifacts(artifacts: dict[str, Any]) -> QuickScanArtifacts:
    return QuickScanArtifacts(**artifacts)


def _build_result(
    *,
    channel: str,
    score: int,
    signals: list[dict[str, Any]],
    artifacts: dict[str, Any],
    summary: str,
    recommended_action: str,
    category: str | None,
    llm_reasoning: str | None,
    degraded: bool,
    degraded_reasons: list[str],
    evidence_quality: str,
    external_checks_used: list[str],
    external_checks_failed: list[str],
    privacy_notice: str,
    structural_score: float | None = None,
    reputation_score: float | None = None,
    llm_score_value: float | None = None,
) -> InstantScanResult:
    verdict = _risk_to_verdict(score)
    return InstantScanResult(
        scan_id=str(uuid.uuid4()),
        channel=channel,
        verdict=verdict,
        risk_score=float(max(0, min(score, 100))),
        confidence=_normalize_confidence(score, degraded, evidence_quality),
        summary=summary,
        top_signals=_signal_models(signals),
        artifacts=_build_artifacts(artifacts),
        recommended_action=recommended_action,
        degraded=degraded,
        saved_to_history=False,
        llm_reasoning=llm_reasoning,
        evidence_quality=evidence_quality,
        analysis_mode=_provider_mode(external_checks_used),
        external_checks_used=list(dict.fromkeys(external_checks_used)),
        external_checks_failed=list(dict.fromkeys(external_checks_failed)),
        degraded_reasons=list(dict.fromkeys(degraded_reasons)),
        privacy_notice=privacy_notice,
        scan_category=category,
        structural_score=structural_score,
        reputation_score=reputation_score,
        llm_score=llm_score_value,
    )


def _extract_eml_content(file_bytes: bytes) -> dict[str, Any]:
    msg = email.message_from_bytes(file_bytes)
    body_parts: list[str] = []
    links: list[dict[str, Any]] = []
    attachment_names: list[str] = []

    for part in msg.walk():
        content_type = part.get_content_type()
        filename = part.get_filename()
        if filename:
            attachment_names.append(filename)
        payload = part.get_payload(decode=True) or b""
        if content_type == "text/plain":
            body_parts.append(payload.decode(errors="ignore"))
        elif content_type == "text/html":
            html = payload.decode(errors="ignore")
            html_text, _images, html_links = _html_text_and_images(html)
            body_parts.append(html_text)
            links.extend(html_links)

    headers = [{"name": key, "value": value} for key, value in msg.items()]
    sender = msg.get("From", "unknown_file_sender")
    subject = msg.get("Subject", "Uploaded email file")

    if not body_parts:
        body_parts.append(file_bytes.decode(errors="ignore"))

    extracted = clean_extracted_text("\n".join(body_parts))
    return {
        "subject": subject,
        "sender": sender,
        "body": extracted,
        "security_headers": parse_security_headers(headers),
        "url_details": links,
        "attachment_names": attachment_names,
    }


def _extract_html_content(file_bytes: bytes) -> dict[str, Any]:
    html = file_bytes.decode(errors="ignore")
    html_text, _images, html_links = _html_text_and_images(html)
    return {
        "subject": "Uploaded HTML file",
        "sender": "html_file",
        "body": clean_extracted_text(html_text),
        "security_headers": {},
        "url_details": html_links,
        "attachment_names": [],
    }


class SmartVetoOrchestrator:
    def _inspect_url(self, url: str, *, context_brands: list[str] | None = None, source_sender: str | None = None) -> tuple[int, list[dict[str, Any]], dict[str, Any], list[str], list[str], list[str], str, float, float, float | None]:
        normalized = _candidate_to_url(url) or url
        parsed = urlparse(normalized)
        host = (parsed.hostname or "").lower()
        base = _base_domain(host)
        signals: list[dict[str, Any]] = []
        external_checks_used: list[str] = []
        external_checks_failed: list[str] = []
        degraded_reasons: list[str] = []
        reputation_hits: list[str] = []
        redirect_chain: list[str] = []
        final_url = normalized
        final_domain = host
        landing_page_title = None
        fetch_snippet = ""
        score = 0

        if base and check_bloom_filter(normalized):
            signals.append(_make_signal("trusted_domain_whitelist", "Domain matches the local high-trust whitelist.", -15, 0.7))
            score -= 15
            external_checks_used.append("tranco_whitelist")

        if check_offline_prefix(normalized):
            signals.append(_make_signal("offline_prefix_feed", "URL matched a locally synchronized malicious prefix feed.", 100, 0.99))
            reputation_hits.append("offline_prefix_feed")
            score = max(score, 100)
            external_checks_used.append("offline_prefix_feed")

        if parsed.scheme == "http":
            signals.append(_make_signal("plaintext_http", "The URL uses plain HTTP instead of HTTPS.", 8, 0.72))
            score += 8
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
            signals.append(_make_signal("ip_host", "The URL points directly to an IP address.", 20, 0.9))
            score += 20
        if base in SHORT_URL_DOMAINS or any(host.endswith("." + short) for short in SHORT_URL_DOMAINS):
            signals.append(_make_signal("shortener", "The URL uses a shortening service that hides the final destination.", 12, 0.82))
            score += 12
        if host.startswith("xn--"):
            signals.append(_make_signal("punycode_host", "The hostname uses punycode and needs extra scrutiny.", 20, 0.8))
            score += 20

        age_days = None
        try:
            age_days = get_rdap_age_days(normalized)
        except Exception as exc:
            degraded_reasons.append("rdap_lookup_failed")
            logger.debug("RDAP lookup failed: %s", exc)
        if age_days is not None:
            if age_days < 14:
                signals.append(_make_signal("new_domain", f"Domain was registered only {age_days} day(s) ago.", 18, 0.82))
                score += 18
            elif age_days < 45:
                signals.append(_make_signal("young_domain", f"Domain is only {age_days} day(s) old.", 10, 0.7))
                score += 10

        try:
            entropy = get_entropy_metrics(normalized)
        except Exception:
            entropy = 0.0
        if entropy > 4.0:
            signals.append(_make_signal("high_entropy_path", "The path structure looks randomly generated or obfuscated.", 14, 0.76))
            score += 14

        typosquat_hits = get_typosquatting_metrics(normalized)
        if typosquat_hits:
            signals.append(_make_signal("typosquatting", "The domain closely resembles a high-value brand domain.", 35, 0.94))
            score += 35

        path_lower = f"{parsed.path} {parsed.query}".lower()
        bait_hits = [token for token in URL_BAIT_MARKERS if token in path_lower]
        if bait_hits:
            signals.append(_make_signal("credential_bait_path", "The URL path contains login, billing, or verification bait language.", 12, 0.72))
            score += 12

        brand_claims = context_brands or []
        sender_domain = _base_domain(((source_sender or "").split("@")[-1]).lower()) if source_sender and "@" in source_sender else ""
        claimed_brand_mismatch = False
        for brand in brand_claims:
            brand_domains = KNOWN_BRANDS.get(brand, set())
            if brand_domains and base not in brand_domains:
                claimed_brand_mismatch = True
                signals.append(_make_signal("brand_mismatch", f"The URL does not match the claimed {brand.title()} destination.", 28, 0.9))
                score += 28
                break
        if sender_domain and sender_domain != base and sender_domain and base:
            signals.append(_make_signal("sender_domain_mismatch", "The link domain does not match the sender domain.", 20, 0.82))
            score += 20

        if host and not _is_reserved_test_domain(host):
            try:
                malicious, threat = _safe_browsing_lookup(normalized)
                external_checks_used.append("google_safe_browsing")
                if malicious:
                    signals.append(_make_signal("safe_browsing_match", f"Google Safe Browsing flagged the URL as {threat or 'malicious'}.", 100, 0.99))
                    reputation_hits.append("google_safe_browsing")
                    score = max(score, 100)
            except Exception:
                external_checks_failed.append("google_safe_browsing")
                degraded_reasons.append("safe_browsing_failed")

            try:
                malicious, suspicious = _virustotal_url_lookup(normalized)
                external_checks_used.append("virustotal_url")
                if malicious > 0:
                    signals.append(_make_signal("virustotal_malicious", f"VirusTotal reports {malicious} malicious engine hit(s).", 55, 0.92))
                    reputation_hits.append(f"virustotal:{malicious}")
                    score += min(55, 20 + malicious * 3)
                elif suspicious > 0:
                    signals.append(_make_signal("virustotal_suspicious", f"VirusTotal reports {suspicious} suspicious engine hit(s).", 18, 0.72))
                    reputation_hits.append(f"virustotal_suspicious:{suspicious}")
                    score += min(18, 8 + suspicious * 2)
            except Exception:
                external_checks_failed.append("virustotal_url")
                degraded_reasons.append("virustotal_url_failed")

            try:
                ipqs = _ipqs_url_lookup(normalized)
                if ipqs:
                    external_checks_used.append("ipqualityscore")
                    if ipqs.get("unsafe") or (ipqs.get("risk_score") or 0) >= 85:
                        signals.append(_make_signal("ipqs_high_risk", "IPQualityScore marked the URL as unsafe.", 35, 0.86))
                        reputation_hits.append("ipqualityscore")
                        score += 35
                    elif (ipqs.get("risk_score") or 0) >= 65:
                        signals.append(_make_signal("ipqs_medium_risk", "IPQualityScore reported elevated fraud risk.", 16, 0.68))
                        score += 16
            except Exception:
                external_checks_failed.append("ipqualityscore")
                degraded_reasons.append("ipqualityscore_failed")

            try:
                fetch_result = _controlled_fetch(normalized)
                external_checks_used.append("controlled_fetch")
                redirect_chain = fetch_result.get("redirect_chain", [])
                if fetch_result.get("blocked"):
                    reason = fetch_result.get("reason", "fetch_blocked")
                    degraded_reasons.append(reason)
                    if reason == "private_target_blocked":
                        signals.append(_make_signal("private_target_blocked", "The URL points to a private or local network target and was not fetched.", 16, 0.8))
                        score += 16
                else:
                    final_url = fetch_result.get("final_url") or final_url
                    final_domain = (urlparse(final_url).hostname or "").lower() if final_url else final_domain
                    landing_page_title = fetch_result.get("title")
                    fetch_snippet = fetch_result.get("content_snippet", "")
                    forms = int(fetch_result.get("forms", 0) or 0)
                    if final_domain and final_domain != base:
                        signals.append(_make_signal("redirect_domain_change", "The URL redirects to a different final domain.", 22, 0.88))
                        score += 22
                        if brand_claims and all(final_domain not in KNOWN_BRANDS.get(brand, set()) for brand in brand_claims):
                            signals.append(_make_signal("offbrand_redirect", "The final redirect target is off-brand for the claimed service.", 30, 0.92))
                            score += 30
                    if forms > 0:
                        signals.append(_make_signal("landing_page_form", "The destination page contains HTML forms that could collect credentials or payment details.", 10, 0.65))
                        score += 10
            except Exception:
                external_checks_failed.append("controlled_fetch")
                degraded_reasons.append("controlled_fetch_failed")

        evidence_quality = "high" if final_url and redirect_chain else "medium"
        if external_checks_failed and not external_checks_used:
            evidence_quality = "low"
        elif claimed_brand_mismatch and not redirect_chain:
            evidence_quality = "medium"

        feature_summary = {
            "host": host,
            "base_domain": base,
            "age_days": age_days,
            "entropy": round(entropy, 3),
            "typosquat_hits": typosquat_hits,
            "redirect_chain": redirect_chain,
            "final_domain": final_domain,
            "landing_page_title": landing_page_title,
            "brand_claims": brand_claims,
            "reputation_hits": reputation_hits,
        }
        llm_result = None
        if 25 <= score <= 75 or (not signals and fetch_snippet):
            llm_input = "\n".join(part for part in [normalized, landing_page_title or "", fetch_snippet] if part)
            llm_result = _llm_assessment("url", llm_input, feature_summary, subject=normalized, sender=source_sender or "url")
            if llm_result:
                threat_probability = float(llm_result.get("llm_score", 0.0))
                if threat_probability >= 0.82:
                    signals.append(_make_signal("llm_url_deception", "The semantic model found strong credential-theft or impersonation cues.", 22, 0.76))
                    score += 22
                elif threat_probability >= 0.62:
                    signals.append(_make_signal("llm_url_suspicion", "The semantic model found moderate deceptive web-lure cues.", 12, 0.62))
                    score += 12
                elif threat_probability <= 0.18 and score < 35:
                    score -= 8

        artifacts = {
            "urls": [normalized],
            "domains": [domain for domain in [host, final_domain] if domain],
            "submitted_url": url,
            "normalized_url": normalized,
            "final_url": final_url,
            "final_domain": final_domain,
            "redirect_chain": redirect_chain,
            "landing_page_title": landing_page_title,
            "reputation_hits": reputation_hits,
            "parser_quality": evidence_quality,
            "detected_type": "text/url",
            "extraction_method": "structured_url_pipeline",
        }
        llm_reasoning = llm_result.get("reasoning") if llm_result else None
        category = "phishing_link" if score >= 80 else "suspicious_link" if score >= 45 else "clean_link"
        llm_prob = float(llm_result.get("llm_score", 0.0)) if llm_result else None
        rep_score = float(min(100, sum(s["severity"] for s in signals if any(k in s["name"] for k in ("safe_browsing", "virustotal", "ipqs", "offline_prefix"))))) if reputation_hits else 0.0
        struct_score = float(min(100, max(0, score - (rep_score or 0) - ((llm_prob or 0) * 22))))
        return max(0, min(score, 100)), signals, artifacts, external_checks_used, external_checks_failed, degraded_reasons, llm_reasoning, struct_score, rep_score, llm_prob

    def process_url_scan(self, url: str, scan_mode: str = "balanced") -> InstantScanResult:
        score, signals, artifacts, external_checks_used, external_checks_failed, degraded_reasons, llm_reasoning, struct_score, rep_score, llm_prob = self._inspect_url(url)
        degraded = bool(external_checks_failed)
        evidence_quality = artifacts.get("parser_quality") or "medium"
        verdict = _risk_to_verdict(score)
        summary = "No strong phishing evidence was found in the submitted URL."
        if verdict == "phishing":
            summary = "This URL shows strong phishing or malicious-site indicators based on domain, redirect, and reputation evidence."
        elif verdict == "suspicious":
            summary = "This URL shows mixed or incomplete risk evidence and should be treated cautiously."
        return _build_result(
            channel="url",
            score=score,
            signals=signals,
            artifacts=artifacts,
            summary=summary,
            recommended_action=_recommended_action(verdict, "url", None),
            category="url_scan",
            llm_reasoning=llm_reasoning,
            degraded=degraded,
            degraded_reasons=degraded_reasons,
            evidence_quality=evidence_quality,
            external_checks_used=external_checks_used,
            external_checks_failed=external_checks_failed,
            privacy_notice=URL_PRIVACY_NOTICE,
            structural_score=round(struct_score, 2),
            reputation_score=round(rep_score, 2),
            llm_score_value=round(llm_prob, 4) if llm_prob is not None else None,
        )

    def process_sms_scan(self, text: str, sender: str | None = None, scan_mode: str = "balanced") -> InstantScanResult:
        cleaned = clean_extracted_text(text)
        sender_type = _classify_sender(sender)
        urls = _extract_urls_from_text(cleaned)
        brand_claims = _extract_brand_claims(cleaned)
        phone_numbers = _extract_phone_numbers(cleaned)
        lowered = cleaned.lower()
        urgency_markers = [token for token in SMS_PRESSURE_MARKERS if token in lowered]
        intent_markers = [token for token in SMS_ACTION_MARKERS if token in lowered]

        signals: list[dict[str, Any]] = []
        external_checks_used: list[str] = []
        external_checks_failed: list[str] = []
        degraded_reasons: list[str] = []
        llm_reasoning = None
        score = 0
        category = "transactional"

        if urls:
            max_url_score = 0
            merged_domains: list[str] = []
            reputation_hits: list[str] = []
            redirect_chain: list[str] = []
            final_url = None
            for record in urls[:3]:
                url_score, url_signals, url_artifacts, used, failed, degraded_items, url_llm_reasoning, _us, _ur, _ul = self._inspect_url(
                    record["normalized_url"],
                    context_brands=brand_claims,
                    source_sender=sender,
                )
                max_url_score = max(max_url_score, url_score)
                merged_domains.extend(url_artifacts.get("domains", []))
                reputation_hits.extend(url_artifacts.get("reputation_hits", []))
                if not final_url:
                    final_url = url_artifacts.get("final_url")
                    redirect_chain = url_artifacts.get("redirect_chain", [])
                external_checks_used.extend(used)
                external_checks_failed.extend(failed)
                degraded_reasons.extend(degraded_items)
                llm_reasoning = llm_reasoning or url_llm_reasoning
            if max_url_score >= 80:
                signals.append(_make_signal("malicious_link_in_sms", "At least one SMS link was scored as malicious by the URL scanner.", 40, 0.94))
                score += 40
                category = "smishing_link"
            elif max_url_score >= 45:
                signals.append(_make_signal("suspicious_link_in_sms", "At least one SMS link was scored as suspicious by the URL scanner.", 22, 0.82))
                score += 22
                category = "verification_lure"
        else:
            merged_domains = []
            reputation_hits = []
            redirect_chain = []
            final_url = None

        has_otp = any(marker in lowered for marker in SMS_OTP_MARKERS)
        has_delivery = any(marker in lowered for marker in SMS_DELIVERY_MARKERS)
        has_reward = any(marker in lowered for marker in SMS_REWARD_MARKERS)
        has_pressure = bool(urgency_markers)

        if has_delivery and urls:
            signals.append(_make_signal("delivery_lure", "The SMS uses package or toll language combined with a link.", 18, 0.78))
            score += 18
            category = "delivery_fraud"
        if has_reward and urls:
            signals.append(_make_signal("reward_lure", "The SMS promises a reward or offer and pushes the user toward a link.", 18, 0.76))
            score += 18
            category = "reward_lure"
        if has_otp and urls:
            signals.append(_make_signal("credential_lure", "The SMS references account verification or OTPs while also pushing a link.", 20, 0.84))
            score += 20
            category = "account_takeover_lure"
        if has_pressure and not urls and (has_otp or has_delivery or has_reward):
            signals.append(_make_signal("pressure_without_context", "The SMS uses urgency and a scam pattern without enough legitimate detail.", 10, 0.66))
            score += 10
            category = "verification_lure"

        if sender_type == "alphanumeric" and brand_claims:
            normalized_sender = (sender or "").lower().replace(" ", "")
            if not any(brand in normalized_sender for brand in brand_claims):
                signals.append(_make_signal("sender_brand_mismatch", "The visible sender ID does not match the claimed brand in the message.", 14, 0.72))
                score += 14

        if has_otp and not urls and not has_pressure:
            signals.append(_make_signal("otp_structure", "The message resembles a normal transactional OTP notice and does not contain a risky link.", -18, 0.78))
            score -= 18
            category = "transactional"

        llm_result = None
        if 20 <= score <= 70 or (not urls and (has_delivery or has_reward or has_pressure)):
            llm_features = {
                "sender": sender,
                "sender_type": sender_type,
                "brand_claims": brand_claims,
                "urls": [item["normalized_url"] for item in urls],
                "urgency_markers": urgency_markers,
                "intent_markers": intent_markers,
            }
            llm_result = _llm_assessment("sms", cleaned, llm_features, sender=sender or "sms")
            if llm_result:
                llm_score = float(llm_result.get("llm_score", 0.0))
                category = llm_result.get("intent") or category
                llm_reasoning = llm_result.get("reasoning")
                if llm_score >= 0.82:
                    signals.append(_make_signal("llm_smishing_confirmed", "The semantic model found strong smishing or fraud patterns.", 18, 0.74))
                    score += 18
                elif llm_score >= 0.62:
                    signals.append(_make_signal("llm_smishing_suspected", "The semantic model found moderate smishing patterns.", 10, 0.62))
                    score += 10
                elif llm_score <= 0.18 and score < 35:
                    score -= 8

        score = max(0, min(score, 100))
        degraded = bool(external_checks_failed)
        evidence_quality = "high" if urls else "medium"
        if degraded and not urls:
            evidence_quality = "low"
        verdict = _risk_to_verdict(score)
        if verdict == "phishing":
            summary = "This message shows strong smishing indicators such as risky links, deceptive lures, or sender-to-brand inconsistencies."
        elif verdict == "suspicious":
            summary = "This message contains scam-like patterns or incomplete evidence and should not be trusted without independent verification."
        else:
            summary = "This message looks low risk based on its structure and available link evidence."

        artifacts = {
            "urls": [item["normalized_url"] for item in urls],
            "domains": list(dict.fromkeys(merged_domains)),
            "phone_numbers": phone_numbers,
            "sender_id": sender,
            "sender_type": sender_type,
            "brand_claims": brand_claims,
            "urgency_markers": urgency_markers,
            "intent_markers": intent_markers,
            "final_url": final_url,
            "redirect_chain": redirect_chain,
            "reputation_hits": list(dict.fromkeys(reputation_hits)),
            "detected_type": "text/sms",
            "extraction_method": "structured_sms_pipeline",
            "parser_quality": evidence_quality,
        }
        sms_rep_score = float(min(100, len(reputation_hits) * 40)) if reputation_hits else 0.0
        sms_llm_prob = float(llm_result.get("llm_score", 0.0)) if llm_result else None
        sms_struct_score = float(min(100, max(0, score - sms_rep_score - ((sms_llm_prob or 0) * 22))))
        return _build_result(
            channel="sms",
            score=score,
            signals=signals,
            artifacts=artifacts,
            summary=summary,
            recommended_action=_recommended_action(verdict, "sms", category),
            category=category,
            llm_reasoning=llm_reasoning,
            degraded=degraded,
            degraded_reasons=degraded_reasons,
            evidence_quality=evidence_quality,
            external_checks_used=external_checks_used,
            external_checks_failed=external_checks_failed,
            privacy_notice=SMS_PRIVACY_NOTICE,
            structural_score=round(sms_struct_score, 2),
            reputation_score=round(sms_rep_score, 2),
            llm_score_value=round(sms_llm_prob, 4) if sms_llm_prob is not None else None,
        )

    def process_file_scan(self, filename: str, content_type: str | None, file_bytes: bytes, scan_mode: str = "balanced") -> InstantScanResult:
        suffix = Path(filename or "upload.bin").suffix.lower()
        display_type = content_type or "application/octet-stream"
        extracted_text = ""
        extraction_notes: list[str] = []
        url_details: list[dict[str, Any]] = []
        attachment_names: list[str] = []
        attachment_score = 0.0
        signals: list[dict[str, Any]] = []
        external_checks_used: list[str] = []
        external_checks_failed: list[str] = []
        degraded_reasons: list[str] = []
        llm_reasoning = None
        scan_category = "file_review"
        subject = f"File Scan: {filename}"
        sender = "file_scanner"
        security_headers: dict[str, Any] = {}
        auth_context = "file_upload"
        sender_domain = ""
        parser_quality = "medium"
        social_engineering_risk = 0
        document_malware_risk = 0

        sha256_hash = hashlib.sha256(file_bytes).hexdigest()
        if suffix in {".eml"}:
            eml = _extract_eml_content(file_bytes)
            subject = eml["subject"]
            sender = eml["sender"]
            extracted_text = eml["body"]
            security_headers = eml["security_headers"]
            url_details = eml["url_details"] or []
            attachment_names = eml["attachment_names"]
            auth_context = "original_headers"
            sender_domain = _base_domain(parseaddr(sender)[1].split("@")[-1].lower()) if "@" in parseaddr(sender)[1] else ""
            parser_quality = "high"
            extraction_notes.append("mime_parser")
        elif suffix in {".html", ".htm"}:
            html = _extract_html_content(file_bytes)
            subject = html["subject"]
            sender = html["sender"]
            extracted_text = html["body"]
            url_details = html["url_details"] or []
            parser_quality = "high"
            extraction_notes.append("dom_parser")
        else:
            extracted_text, extraction_notes = extract_upload_text(filename, file_bytes)
            parser_quality = "medium" if extracted_text else "low"

        if suffix in {".pdf"}:
            pdf_result = analyze_pdf(file_bytes, filename)
            document_malware_risk = int(round(float(pdf_result.get("threat_score", 0.0)) * 100))
            for indicator in pdf_result.get("indicators", []):
                signals.append(_make_signal("pdf_static_indicator", indicator.replace("_", " "), 12 if "suspicious" in indicator else 22, 0.72))
            extraction_notes.append("pdf_static_analysis")
        elif suffix in {".docx", ".doc", ".docm", ".xlsx", ".xls", ".pptx", ".ppt", ".pptm"}:
            office_result = analyze_docx(file_bytes, filename)
            document_malware_risk = int(round(float(office_result.get("threat_score", 0.0)) * 100))
            for indicator in office_result.get("indicators", []):
                weight = 30 if "weaponized_vba" in indicator or "dde" in indicator else 16
                signals.append(_make_signal("office_static_indicator", indicator.replace("_", " "), weight, 0.78))
            extraction_notes.append("office_static_analysis")
        elif suffix in IMAGE_EXTENSIONS:
            extraction_notes.append("image_ocr")
            if not extracted_text.strip():
                parser_quality = "low"

        if not url_details:
            url_details = _extract_urls_from_text(extracted_text)

        if not _is_reserved_test_domain("example.com"):
            try:
                malicious_engines = _virustotal_hash_lookup(sha256_hash)
                external_checks_used.append("virustotal_file_hash")
                if malicious_engines > 0:
                    document_malware_risk = max(document_malware_risk, min(100, 40 + malicious_engines * 4))
                    signals.append(_make_signal("virustotal_file_hash", f"VirusTotal reports {malicious_engines} malicious engine hit(s) for this file hash.", 45, 0.9))
            except Exception:
                external_checks_failed.append("virustotal_file_hash")
                degraded_reasons.append("virustotal_file_hash_failed")

        url_flags: list[str] = []
        url_artifact_domains: list[str] = []
        redirect_chain: list[str] = []
        reputation_hits: list[str] = []
        for record in url_details[:3]:
            url_score, url_signals, url_artifacts, used, failed, degraded_items, url_llm_reasoning, _fs, _fr, _fl = self._inspect_url(
                record.get("href") or record.get("normalized_url") or record.get("raw_url") or "",
                context_brands=_extract_brand_claims(extracted_text),
                source_sender=sender,
            )
            llm_reasoning = llm_reasoning or url_llm_reasoning
            url_artifact_domains.extend(url_artifacts.get("domains", []))
            redirect_chain = redirect_chain or url_artifacts.get("redirect_chain", [])
            reputation_hits.extend(url_artifacts.get("reputation_hits", []))
            external_checks_used.extend(used)
            external_checks_failed.extend(failed)
            degraded_reasons.extend(degraded_items)
            if url_score >= 80:
                signals.append(_make_signal("malicious_link_in_file", "The file contains a link that scored as malicious.", 35, 0.9))
                social_engineering_risk = max(social_engineering_risk, 70)
            elif url_score >= 45:
                signals.append(_make_signal("suspicious_link_in_file", "The file contains a link that scored as suspicious.", 20, 0.78))
                social_engineering_risk = max(social_engineering_risk, 45)
            record.setdefault("flags", [])
            if url_score >= 80:
                record["flags"].append("high_risk_url")
                url_flags.append("embedded_high_risk_url")
            elif url_score >= 45:
                record["flags"].append("suspicious_url")
                url_flags.append("embedded_suspicious_url")

        hybrid = None
        if extracted_text.strip():
            hybrid = hybrid_detect(
                subject,
                extracted_text,
                sender,
                attachment_score=(document_malware_risk / 100.0) if document_malware_risk else None,
                url_flags=url_flags,
                security_headers=security_headers,
                auth_context=auth_context,
                url_details=url_details,
                source_type="file",
                link_evidence_mode="raw_href" if any(item.get("href") for item in url_details) else "visible_url" if url_details else "none_visible",
            )
            social_engineering_risk = max(social_engineering_risk, int(round(float(hybrid.get("final_score", 0.0)) * 100)))
            llm_reasoning = llm_reasoning or ((hybrid.get("llm_reasons") or [""])[0] or None)
            scan_category = ((hybrid.get("llm_analysis") or {}).get("intent") or scan_category)
            for reason in hybrid.get("rule_reasons", [])[:5]:
                signals.append(_make_signal("semantic_rule", reason.replace("_", " "), 12, 0.68))
            if hybrid.get("llm_score") and float(hybrid["llm_score"]) >= 0.72:
                signals.append(_make_signal("llm_document_lure", "The semantic model found deceptive or malicious lure language in the file content.", 18, 0.72))
        elif parser_quality == "low":
            degraded_reasons.append("low_parser_quality")

        if suffix in IMAGE_EXTENSIONS and not url_details and any(token in extracted_text.lower() for token in ("claim", "verify", "redeem", "limited time", "login")):
            social_engineering_risk = max(social_engineering_risk, 52)
            signals.append(_make_signal("ocr_lure_without_link", "The image contains lure language, but the actual destination is not visible.", 18, 0.74))
            scan_category = "ocr_lure"

        final_score = max(document_malware_risk, social_engineering_risk)
        if document_malware_risk >= 80:
            summary = "The file shows strong static-malware or weaponized-document indicators."
            scan_category = "malware_delivery"
        elif social_engineering_risk >= 80:
            summary = "The file content or embedded links show strong phishing or social-engineering evidence."
        elif final_score >= 45:
            summary = "The file contains suspicious content, risky links, or limited parser confidence and should be reviewed carefully."
        else:
            summary = "No strong malicious evidence was found in the file based on its text, links, and static metadata."

        degraded = bool(external_checks_failed) or parser_quality == "low"
        if degraded and final_score < 45:
            final_score = max(final_score, 35)
        verdict = _risk_to_verdict(final_score)
        artifacts = {
            "urls": [item.get("href") or item.get("normalized_url") for item in url_details if item.get("href") or item.get("normalized_url")],
            "extracted_urls": [item.get("href") or item.get("normalized_url") for item in url_details if item.get("href") or item.get("normalized_url")],
            "domains": list(dict.fromkeys(url_artifact_domains or [item.get("domain") for item in url_details if item.get("domain")])),
            "filename": filename,
            "detected_type": display_type,
            "detected_file_type": suffix.lstrip(".") or display_type,
            "extraction_method": ", ".join(extraction_notes) if extraction_notes else "basic_text_extraction",
            "parser_quality": parser_quality,
            "reputation_hits": list(dict.fromkeys(reputation_hits)),
            "redirect_chain": redirect_chain,
            "attachment_names": attachment_names,
            "document_malware_risk": round(document_malware_risk / 100.0, 2),
            "social_engineering_risk": round(social_engineering_risk / 100.0, 2),
            "embedded_active_content": [signal["description"] for signal in signals if "static_indicator" in signal["name"]],
        }
        file_rep_score = float(min(100, len(reputation_hits) * 40)) if reputation_hits else 0.0
        file_llm_prob = float(hybrid.get("llm_score", 0.0)) if hybrid and hybrid.get("llm_score") else None
        file_struct_score = float(min(100, max(0, final_score - file_rep_score - ((file_llm_prob or 0) * 22))))
        return _build_result(
            channel="file",
            score=max(0, min(final_score, 100)),
            signals=signals,
            artifacts=artifacts,
            summary=summary,
            recommended_action=_recommended_action(verdict, "file", scan_category),
            category=scan_category,
            llm_reasoning=llm_reasoning,
            degraded=degraded,
            degraded_reasons=degraded_reasons,
            evidence_quality=parser_quality,
            external_checks_used=external_checks_used,
            external_checks_failed=external_checks_failed,
            privacy_notice=FILE_PRIVACY_NOTICE,
            structural_score=round(file_struct_score, 2),
            reputation_score=round(file_rep_score, 2),
            llm_score_value=round(file_llm_prob, 4) if file_llm_prob is not None else None,
        )
