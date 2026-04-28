import requests
import os
import sys
import io
import threading
import contextlib
from datetime import datetime
from urllib.parse import urlparse

try:
    import whois as _whois_lib
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

# Set your API Key here, or as an environment variable
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY", "AIzaSyBypl1Q-bIIV8d6V46IGEWiZ89bJ_lpZQo")

# Maximum seconds to wait for a WHOIS response.
# python-whois has no built-in timeout; slow/firewalled networks
# (e.g. ISPs that block port 43) cause it to hang indefinitely.
WHOIS_TIMEOUT_SECONDS = 3


def _whois_with_timeout(domain: str, timeout: int = WHOIS_TIMEOUT_SECONDS):
    """
    Run whois.whois() in a daemon thread and return the result within
    `timeout` seconds. Returns None if it times out or fails.
    """
    result = [None]
    error  = [None]

    def _do_whois():
        try:
            # Suppress python-whois internal socket error messages
            # (it prints directly to stdout/stderr on timeout)
            devnull = io.StringIO()
            with contextlib.redirect_stdout(devnull), contextlib.redirect_stderr(devnull):
                result[0] = _whois_lib.whois(domain)
        except Exception as e:
            error[0] = e

    t = threading.Thread(target=_do_whois, daemon=True)
    t.start()
    t.join(timeout)

    if t.is_alive():
        # Thread is still blocked on the socket — give up gracefully
        print(f"[URL_ANALYZER] WHOIS timed out for '{domain}' after {timeout}s — skipping")
        return None

    if error[0]:
        return None

    return result[0]


def analyze_urls(urls):
    """
    Analyzes a list of URLs locally (for speed) and checks them against
    Google Safe Browsing in a single batched API call.
    """
    suspicious = []

    # -----------------------------------
    # 1. FAST LOCAL HEURISTICS (INSTANT)
    # -----------------------------------
    for url in urls:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            if "bit.ly" in domain or "tinyurl" in domain:
                suspicious.append("shortened_url")
            elif WHOIS_AVAILABLE:
                w = _whois_with_timeout(domain)
                if w is not None:
                    try:
                        creation_date = w.creation_date
                        if isinstance(creation_date, list):
                            creation_date = creation_date[0]
                        if creation_date:
                            age_days = (datetime.now() - creation_date).days
                            if age_days < 14:
                                suspicious.append(f"domain_age_newly_registered:{domain}")
                    except Exception:
                        pass

            # Check if domain is just an IP address (no letters)
            if domain.replace(".", "").isdigit():
                suspicious.append("ip_based_url")

        except Exception:
            pass

    # -----------------------------------
    # 2. LIVE GOOGLE SAFE BROWSING CHECK
    # -----------------------------------
    if not urls or SAFE_BROWSING_API_KEY == "YOUR_API_KEY_HERE":
        return suspicious

    # Build the massive JSON payload for the API
    # We batch every url so it only costs 1 HTTP request!
    threat_entries = [{"url": u} for u in set(urls)]

    payload = {
        "client": {
            "clientId": "safemailx-extension",
            "clientVersion": "1.1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": threat_entries
        }
    }

    try:
        # Strict timeout of 1.5s ensures the extension NEVER feels slow
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
        
        response = requests.post(api_url, json=payload, timeout=1.5)
        
        if response.status_code == 200:
            data = response.json()
            matches = data.get("matches", [])
            
            for match in matches:
                matched_url = match.get("threat", {}).get("url", "unknown")
                threat_type = match.get("threatType", "MALICIOUS")
                suspicious.append(f"SafeBrowsing_Match:{threat_type}")
                print(f"[ALERT] Safe Browsing caught: {matched_url} as {threat_type}")
                
    except requests.exceptions.Timeout:
        print("[WARNING] Safe Browsing API timed out. Proceeding with local results to maintain speed.")
    except Exception as e:
        print(f"[ERROR] Safe Browsing integration failed: {str(e)}")

    # Return unique reasons only
    return list(set(suspicious))