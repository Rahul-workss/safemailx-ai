import ipaddress
import re
from urllib.parse import urlparse, urlunparse


SHORT_URL_DOMAINS = {
    "bit.ly", "tinyurl.com", "tiny.cc", "t.co", "ow.ly", "is.gd",
    "rebrand.ly", "t.ly", "qrco.de", "goo.su", "bit.do", "migre.me",
    "6url.ru", "shorturl.at", "soo.gd", "shorte.st", "lnkd.in",
}

URL_CANDIDATE_RE = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
TRAILING_JUNK = ".,;:!?)]}>\"'"


def _clean_candidate(candidate: str) -> str:
    cleaned = candidate.strip()
    while cleaned and cleaned[-1] in TRAILING_JUNK:
        cleaned = cleaned[:-1]
    return cleaned


def _is_ip_domain(domain: str) -> bool:
    try:
        ipaddress.ip_address(domain.strip("[]"))
        return True
    except ValueError:
        return False


def _normalize_url(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return None
    normalized = parsed._replace(
        scheme=parsed.scheme.lower(),
        netloc=parsed.netloc.lower(),
        fragment="",
    )
    return urlunparse(normalized)


def extract_urls(text: str) -> list[dict]:
    """Extract sanitized, normalized, unique URL records preserving order."""
    seen = set()
    records = []

    for match in URL_CANDIDATE_RE.finditer(text or ""):
        raw = _clean_candidate(match.group(0))
        normalized = _normalize_url(raw)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)

        parsed = urlparse(normalized)
        domain = parsed.hostname.lower() if parsed.hostname else ""
        is_ip = _is_ip_domain(domain)
        is_short = domain in SHORT_URL_DOMAINS or any(
            domain.endswith("." + short) for short in SHORT_URL_DOMAINS
        )
        flags = []
        if is_ip:
            flags.append("ip_based_url")
        if is_short:
            flags.append("shortened_url")

        records.append({
            "raw_url": raw,
            "normalized_url": normalized,
            "domain": domain,
            "is_ip": is_ip,
            "is_short": is_short,
            "flags": flags,
            "safebrowsing_hit": False,
        })

    return records
