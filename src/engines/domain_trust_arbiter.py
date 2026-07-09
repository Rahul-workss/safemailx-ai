import re
import time
import whois
import threading
import logging
import concurrent.futures
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Cache for whois results to prevent redundant network calls
# format: { domain: (timestamp, domain_age_days) }
_WHOIS_CACHE: Dict[str, tuple[float, Optional[int]]] = {}
_CACHE_TTL = 3600 * 24  # 24 hours

# =====================================================================
# PLATINUM DOMAINS (Expanded from legacy VIP_DOMAINS)
# These domains automatically get maximum trust if authenticated.
# =====================================================================
PLATINUM_DOMAINS = {
    # Tech / Core Platforms
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "github.com", "gitlab.com", "bitbucket.org",
    
    # Social / Media
    "youtube.com", "facebook.com", "instagram.com", "meta.com",
    "linkedin.com", "twitter.com", "x.com", "netflix.com", "spotify.com",
    "pinterest.com", "reddit.com", "tiktok.com",
    
    # Cloud / Infrastructure / Security
    "aws.amazon.com", "cloudflare.com", "heroku.com", "digitalocean.com",
    "okta.com", "auth0.com", "crowdstrike.com", "paloaltonetworks.com",
    
    # E-Commerce / Payments
    "amazon.in", "paypal.com", "stripe.com", "razorpay.com", "square.com",
    "flipkart.com", "myntra.com", "swiggy.in", "zomato.com", "blinkit.com",
    "paytm.com", "phonepe.com", "gpay.app", "cred.club", "shopify.com",
    
    # SaaS / Productivity / B2B
    "slack.com", "atlassian.net", "atlassian.com", "salesforce.com",
    "hubspot.com", "zoom.us", "dropbox.com", "box.com", "notion.so",
    "asana.com", "trello.com", "figma.com", "canva.com", "miro.com",
    "zendesk.com", "intercom.com", "docusign.com", "calendly.com",
    
    # EdTech / Hacker / Developer Communities (Crucial for target audience)
    "hack2skill.com", "hackerearth.com", "hackerrank.com", "leetcode.com",
    "devfolio.co", "unstop.com", "coursera.org", "udemy.com",
    "edx.org", "pluralsight.com", "freecodecamp.org", "codecademy.com"
}

# =====================================================================
# FREEMAIL PROVIDERS
# These domains are free to register and heavily abused by phishers.
# Even with SPF/DKIM, they should not gain high trust tiers.
# =====================================================================
FREEMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "icloud.com", "mail.com", "proton.me", "protonmail.com",
    "yandex.com", "zoho.com", "gmx.com"
}


@dataclass
class DomainTrustResult:
    trust_tier: str
    trust_score: float
    domain_age_days: Optional[int]
    signals_fired: List[str] = field(default_factory=list)


def _get_domain_age_days(domain: str) -> Optional[int]:
    """Fetch WHOIS creation date with 2-second timeout and caching."""
    if not domain or domain == "unknown_origin":
        return None
        
    now = time.time()
    if domain in _WHOIS_CACHE:
        timestamp, age = _WHOIS_CACHE[domain]
        if now - timestamp < _CACHE_TTL:
            return age

    def fetch_whois():
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if not creation_date:
                return None
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            delta = (time.time() - creation_date.timestamp())
            return int(delta / (3600 * 24))
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {domain}: {e}")
            return None

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(fetch_whois)
            age_days = future.result(timeout=2.0)
            _WHOIS_CACHE[domain] = (now, age_days)
            return age_days
    except concurrent.futures.TimeoutError:
        logger.warning(f"WHOIS timeout for {domain} (2s limit exceeded)")
        return None
    except Exception as e:
        logger.warning(f"WHOIS error for {domain}: {e}")
        return None


def check_domain_trust(
    sender_domain: str,
    sender_full: str,
    spf_pass: bool,
    dkim_pass: bool,
    dmarc_pass: bool,
    received_headers: List[Dict[str, str]],
    url_details: List[Dict[str, Any]],
    security_headers: Dict[str, Any] = None,
    auth_context: str = "original_headers"
) -> DomainTrustResult:
    """
    Analyzes domain trust signals to categorize the sender into a trust tier.
    This neutralizes false positives caused by urgency keywords from legitimate senders.
    """
    signals = []
    score = 0.0
    
    # Ensure sender domain is clean
    sender_domain = sender_domain.lower().strip()
    
    # -----------------------------------------------------------------
    # INSTANT SIGNALS (Zero Network I/O)
    # -----------------------------------------------------------------
    
    # Security Auth (Crucial for trust)
    auth_context = security_headers.get("auth_context", "original_headers") if security_headers else "original_headers"
    
    if spf_pass and dkim_pass:
        score += 30
        signals.append("P4: SPF/DKIM Passed (+30)")
    elif spf_pass or dkim_pass:
        score += 10
        signals.append("P5: Partial Auth (+10)")
    else:
        if auth_context in ["forwarder_only", "unknown"]:
            signals.append("N0: Auth Data Unavailable (Forwarded) (0)")
        else:
            score -= 20
            signals.append("N1: No Auth (-20)")
        
    if dmarc_pass:
        score += 15
        signals.append("P6: DMARC Passed (+15)")

    # Sender Name Analysis
    if re.search(r"support|billing|admin|team|noreply|no-reply", sender_full.lower()):
        # Extract username using regex safely
        username_match = re.search(r"([a-zA-Z0-9._%+-]+)@", sender_full)
        if username_match:
            username = username_match.group(1).lower()
            if "no-reply" in username or "noreply" in username:
                if spf_pass and dkim_pass:
                    score += 10
                    signals.append("P14: Authenticated no-reply (+10)")
                elif auth_context in ["forwarder_only", "unknown"]:
                    signals.append("N0: Auth Data Unavailable for no-reply (0)")
                else:
                    score -= 15
                    signals.append("N8: Unauthenticated no-reply (-15)")

    # ESP Trust (Checking if sent via trusted bulk senders like SendGrid/Mailgun)
    trusted_esps = ["sendgrid.net", "mailgun.org", "mandrillapp.com", "amazonses.com", "mcsv.net"]
    is_trusted_esp = False
    for hop in received_headers:
        by_host = hop.get("by", "").lower()
        if any(esp in by_host for esp in trusted_esps):
            is_trusted_esp = True
            break
            
    if is_trusted_esp and (spf_pass or dkim_pass):
        score += 20
        signals.append("P16: Reputable ESP routing (+20)")

    # URL Consistency Check
    # If the email contains URLs that point back to the sender's domain, it builds trust
    if url_details:
        sender_urls = 0
        total_urls = len(url_details)
        for url_dict in url_details:
            try:
                parsed_url = urlparse(url_dict.get("url", ""))
                if sender_domain in parsed_url.netloc.lower():
                    sender_urls += 1
            except Exception:
                pass
                
        if sender_urls > 0 and (sender_urls / total_urls) > 0.5:
            score += 15
            signals.append("P19: Internal Domain Link Consistency (+15)")
            
    # Subdomain check
    if sender_domain.count(".") > 2:
        score -= 10
        signals.append("N9: Deep Subdomain (-10)")

    # FREEMAIL PENALTY
    if sender_domain in FREEMAIL_PROVIDERS:
        score -= 20
        signals.append("N10: Freemail Provider Penalty (-20)")

    # PLATINUM CHECK
    if sender_domain in PLATINUM_DOMAINS and sender_domain not in FREEMAIL_PROVIDERS:
        if spf_pass and dkim_pass:
            score += 50
            signals.append("P2: VIP Domain (+50)")
        elif auth_context in ["forwarder_only", "unknown"]:
            score += 30
            signals.append("P2_FWD: VIP Domain (Forwarded, Auth Stripped) (+30)")

    # -----------------------------------------------------------------
    # FAST I/O SIGNALS (Domain Age via WHOIS)
    # -----------------------------------------------------------------
    # Only fetch WHOIS if we don't already have overwhelming evidence
    age_days = None
    if sender_domain and sender_domain != "unknown_origin":
        age_days = _get_domain_age_days(sender_domain)
        
        if age_days is not None:
            if age_days > 180:
                score += 20
                signals.append(f"P9: Domain Age {age_days}d (+20)")
            elif age_days > 30:
                score += 5
                signals.append(f"P10: Domain Age {age_days}d (+5)")
            elif age_days < 14:
                score -= 30
                signals.append(f"N5: Very New Domain {age_days}d (-30)")

    # -----------------------------------------------------------------
    # TIER CLASSIFICATION
    # -----------------------------------------------------------------
    tier = "SUSPICIOUS"
    if sender_domain in PLATINUM_DOMAINS and spf_pass and dkim_pass and sender_domain not in FREEMAIL_PROVIDERS:
        tier = "PLATINUM"
    elif sender_domain in FREEMAIL_PROVIDERS:
        tier = "BRONZE" if score >= 20 else "SUSPICIOUS"
    elif score >= 60:
        tier = "GOLD"
    elif score >= 40:
        tier = "SILVER"
    elif score >= 20:
        tier = "BRONZE"
    elif not spf_pass and not dkim_pass and score <= 0:
        tier = "SUSPICIOUS"
    else:
        tier = "UNVERIFIED"

    return DomainTrustResult(
        trust_tier=tier,
        trust_score=score,
        domain_age_days=age_days,
        signals_fired=signals
    )
