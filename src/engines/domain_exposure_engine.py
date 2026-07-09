import re
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests


def _clean_domain(value: str) -> str:
    raw = (value or "").strip().lower()
    if "://" in raw:
        raw = urlparse(raw).hostname or raw
    raw = raw.strip("/ ")
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", raw):
        raise ValueError("Domain must be a hostname such as example.com")
    return raw


def _nslookup(domain: str, record_type: str) -> str:
    try:
        result = subprocess.run(
            ["nslookup", "-type=" + record_type, domain],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except Exception:
        return ""
    return (result.stdout or "") + "\n" + (result.stderr or "")


def _tls_expiry_days(domain: str) -> int | None:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        not_after = cert.get("notAfter")
        if not not_after:
            return None
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return (expires - datetime.now(timezone.utc)).days
    except Exception:
        return None


def analyze_domain_exposure(domain: str) -> dict:
    hostname = _clean_domain(domain)
    signals: list[str] = []
    checks: dict[str, str | int | None] = {"domain": hostname}

    try:
        socket.getaddrinfo(hostname, 443)
        checks["dns_resolution"] = "ok"
    except Exception:
        checks["dns_resolution"] = "failed"
        signals.append("dns_resolution_failed")

    mx_output = _nslookup(hostname, "mx").lower()
    checks["mx_record"] = "present" if "mail exchanger" in mx_output or "mx preference" in mx_output else "missing_or_unknown"
    if checks["mx_record"] == "missing_or_unknown":
        signals.append("mx_missing_or_unconfirmed")

    txt_output = _nslookup(hostname, "txt").lower()
    checks["spf"] = "present" if "v=spf1" in txt_output else "missing_or_unknown"
    if checks["spf"] == "missing_or_unknown":
        signals.append("spf_missing")

    dmarc_output = _nslookup("_dmarc." + hostname, "txt").lower()
    checks["dmarc"] = "present" if "v=dmarc1" in dmarc_output else "missing_or_unknown"
    if checks["dmarc"] == "missing_or_unknown":
        signals.append("dmarc_missing")

    expiry_days = _tls_expiry_days(hostname)
    checks["tls_expires_in_days"] = expiry_days
    if expiry_days is None:
        signals.append("tls_unavailable_or_unreadable")
    elif expiry_days < 14:
        signals.append("tls_certificate_expiring_soon")

    try:
        response = requests.get(f"https://{hostname}", timeout=4, allow_redirects=True)
        headers = {k.lower(): v for k, v in response.headers.items()}
        checks["https_status"] = response.status_code
        for header, signal in [
            ("strict-transport-security", "hsts_missing"),
            ("content-security-policy", "content_security_policy_missing"),
            ("x-frame-options", "clickjacking_header_missing"),
        ]:
            if header not in headers:
                signals.append(signal)
        server = headers.get("server", "")
        checks["server_header"] = server[:80] if server else None
        if server:
            signals.append("server_banner_exposed")
    except Exception:
        checks["https_status"] = "unreachable"
        signals.append("https_unreachable")

    risk_score = min(1.0, 0.18 * len(set(signals)))
    if "dns_resolution_failed" in signals or "https_unreachable" in signals:
        risk_score = max(risk_score, 0.55)

    return {
        "domain": hostname,
        "risk_score": round(risk_score, 3),
        "signals": sorted(set(signals)),
        "checks": checks,
    }
