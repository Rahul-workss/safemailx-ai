import math
import ipaddress
import requests
import socket
import sqlite3
import datetime
import urllib.parse
from urllib.parse import urlparse
import logging
from typing import List, Dict, Optional, Tuple
import os

logger = logging.getLogger("URL_ANALYZER")
WHOIS_AVAILABLE = True

try:
    from pybloom_live import BloomFilter
    BLOOM_AVAILABLE = True
except ImportError:
    BLOOM_AVAILABLE = False
    logger.warning("pybloom_live not installed. Whitelist Bloom Filter will be mocked.")

try:
    from confusable_homoglyphs import confusables
    IDN_AVAILABLE = True
except ImportError:
    IDN_AVAILABLE = False
    logger.warning("confusable_homoglyphs not installed. IDN checks disabled.")

def _base_domain(host: str) -> str:
    parts = (host or "").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (host or "")

# ==========================================
# STAGE 1: Pre-Computation (Whitelist & Hash)
# ==========================================

from engines.offline_sync import check_url_prefix, check_url_against_offline_db

# Feature 3: Offline safe-browsing config
try:
    from utils.config import FEATURE_OFFLINE_SAFEBROWSING_ENABLED
except ImportError:
    FEATURE_OFFLINE_SAFEBROWSING_ENABLED = False

# Initialize Tranco Bloom Filter
_TRANCO_BLOOM = None
if BLOOM_AVAILABLE:
    _TRANCO_BLOOM = BloomFilter(capacity=1000000, error_rate=0.001)
    # Attempt to load from offline csv if it exists
    csv_path = os.path.join(os.path.dirname(__file__), "tranco.csv")
    if os.path.exists(csv_path):
        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                for line in f:
                    domain = line.strip()
                    if domain: _TRANCO_BLOOM.add(domain)
            logger.info("Successfully loaded Tranco top sites into Bloom Filter.")
        except Exception as e:
            logger.error(f"Failed to load tranco.csv into Bloom Filter: {e}")
    else:
        # Add some top domains for testing
        _TRANCO_BLOOM.add("google.com")
        _TRANCO_BLOOM.add("microsoft.com")
        _TRANCO_BLOOM.add("apple.com")
        _TRANCO_BLOOM.add("github.com")

def check_bloom_filter(url: str) -> bool:
    """Check if the domain is in the highly-optimized Tranco top 1M Bloom filter."""
    if not BLOOM_AVAILABLE or not _TRANCO_BLOOM:
        # Fallback to hardcoded list if bloom filter library failed
        parsed = urlparse(url)
        host = (parsed.hostname or parsed.netloc).lower()
        base = _base_domain(host)
        return base in {"google.com", "microsoft.com", "apple.com", "github.com"}
        
    parsed = urlparse(url)
    host = (parsed.hostname or parsed.netloc).lower()
    base = _base_domain(host)
    
    return base in _TRANCO_BLOOM

def check_offline_prefix(url: str) -> bool:
    """
    Check against local SQLite 32-bit SHA-256 hash prefixes.
    Feature 3: now uses full-URL hash (not domain-only) for better accuracy.
    Legacy callers that already use this function get the improved behavior.
    """
    if FEATURE_OFFLINE_SAFEBROWSING_ENABLED:
        # Full URL hash check (Feature 3 — more accurate)
        return check_url_against_offline_db(url)
    # Fallback: legacy domain-only check (pre-Feature 3 behavior)
    return check_url_prefix(url)


# ==========================================
# STAGE 3: Machine Learning & Lexical Forensics
# ==========================================

# Initialize SQLite RDAP Cache
RDAP_DB_PATH = os.path.join(os.path.dirname(__file__), "rdap_cache.db")
def init_rdap_db():
    conn = sqlite3.connect(RDAP_DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS domain_age (domain TEXT PRIMARY KEY, age_days INTEGER)''')
    conn.commit()
    conn.close()

init_rdap_db()

def get_rdap_age_days(url: str) -> Optional[int]:
    """
    Asynchronously queries RDAP JSON for domain age, or uses local SQLite cache.
    Replaces legacy WHOIS on Port 43.
    """
    parsed = urlparse(url)
    host = (parsed.hostname or parsed.netloc).lower()
    base = _base_domain(host)
    
    if not base:
        return None

    # Check local SQLite cache first
    conn = sqlite3.connect(RDAP_DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT age_days FROM domain_age WHERE domain = ?', (base,))
    result = cursor.fetchone()
    if result:
        conn.close()
        return result[0]

    try:
        # We query the RDAP bootstrap 
        rdap_url = f"https://rdap.org/domain/{base}"
        res = requests.get(rdap_url, timeout=2.0)
        if res.status_code == 200:
            data = res.json()
            events = data.get("events", [])
            for event in events:
                if event.get("eventAction") == "registration":
                    date_str = event.get("eventDate")
                    if date_str:
                        # e.g. "1997-09-15T04:00:00Z"
                        dt = datetime.datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                        age = (datetime.datetime.now(datetime.timezone.utc) - dt).days
                        cursor.execute('INSERT OR IGNORE INTO domain_age (domain, age_days) VALUES (?, ?)', (base, age))
                        conn.commit()
                        conn.close()
                        return age
    except Exception as e:
        logger.debug(f"RDAP lookup failed for {base}: {e}")
    
    conn.close()
    return None

def get_entropy_metrics(url: str) -> float:
    """Calculate Shannon entropy of the URL path to detect DGAs."""
    parsed = urlparse(url)
    path = parsed.path
    if not path or path == "/":
        return 0.0
        
    # Shannon entropy calculation
    prob = [float(path.count(c)) / len(path) for c in dict.fromkeys(list(path))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

TARGET_BRANDS = ["paypal.com", "microsoft.com", "apple.com", "amazon.com", "google.com", "netflix.com"]


def is_safe_external_url(url: str) -> bool:
    """Allow only HTTP(S) destinations that do not resolve to local networks."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        host = parsed.hostname.rstrip(".")
        try:
            addresses = {item[4][0] for item in socket.getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)}
        except socket.gaierror:
            # A domain that cannot currently resolve cannot be fetched by the
            # HTTP client either. Keep lexical analysis available for it.
            return True
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
                return False
        return True
    except (ValueError, TypeError):
        return False

def get_typosquatting_metrics(url: str) -> List[str]:
    """Check for IDN Homographs and Levenshtein distance against high-value targets."""
    hits = []
    parsed = urlparse(url)
    host = (parsed.hostname or parsed.netloc).lower()
    base = _base_domain(host)
    
    if not base:
        return hits

    # 1. IDN Homograph check
    if IDN_AVAILABLE:
        if confusables.is_mixed_script(base) or confusables.is_dangerous(base):
            hits.append(f"idn_homograph_attack:{base}")
            
    # 2. Levenshtein / Bitsquatting check
    for target in TARGET_BRANDS:
        if base == target:
            continue # Exact match is fine (it should be caught by Bloom Filter anyway)
        dist = _levenshtein(base, target)
        if dist > 0 and dist <= 2:
            hits.append(f"typosquatting:{base}->{target}")
            
    return hits

def analyze_urls(urls, sender_domain: str | None = None):
    logger.warning("Legacy analyze_urls called. Use SmartVetoOrchestrator instead.")
    suspicious: list[str] = []
    normalized_sender = _base_domain((sender_domain or "").lower())

    for item in urls:
        if isinstance(item, str):
            url_value = item
            detail = {"raw_url": item}
        else:
            detail = item
            url_value = (
                detail.get("href")
                or detail.get("raw_url")
                or detail.get("normalized_url")
                or detail.get("url")
                or ""
            )

        if not url_value:
            continue

        if check_offline_prefix(url_value):
            suspicious.append("offline_prefix_hard_fail")
        if get_typosquatting_metrics(url_value):
            suspicious.append("typosquatting_detected")

        parsed = urlparse(url_value)
        host = (parsed.hostname or "").lower()
        base = _base_domain(host)
        detail.setdefault("domain", host or base)

        if detail.get("is_cta"):
            suspicious.append("cta_link_present")

        final_url, resolved_domain = _resolve_final_url(url_value)
        if final_url:
            detail["resolved_url"] = final_url
        if resolved_domain:
            detail["resolved_domain"] = resolved_domain
            resolved_base = _base_domain(resolved_domain)
            if detail.get("is_cta") and normalized_sender and resolved_base != normalized_sender:
                suspicious.append(f"cta_resolved_domain_mismatch:{resolved_domain}")

        href_domain = (detail.get("href_domain") or host).lower()
        href_base = _base_domain(href_domain)
        if detail.get("is_cta") and normalized_sender and href_base and href_base != normalized_sender:
            suspicious.append(f"cta_sender_domain_mismatch:{href_domain}")

    return list(dict.fromkeys(suspicious))

def _resolve_final_url(url: str) -> tuple[str | None, str | None]:
    try:
        if not is_safe_external_url(url):
            return None, None
        response = requests.get(url, timeout=2.0, allow_redirects=True, stream=True)
        final_url = response.url
        response.close()
        if not final_url: return None, None
        if not is_safe_external_url(final_url):
            return None, None
        parsed = urlparse(final_url)
        return final_url, (parsed.hostname or "").lower()
    except Exception:
        return None, None
