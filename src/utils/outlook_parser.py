"""Parse a raw MIME email (bytes) from Microsoft Graph into the same dict
shape that utils.email_parser.parse_email() produces for Gmail messages.

Returns:
    {
        "subject": str,
        "sender": str,
        "body": str,          # plain-text body (HTML stripped if needed)
        "images": list[str],  # cid: or inline image URLs extracted from HTML
        "links": list[str],   # all href URLs found in the message
        "attachments": list,  # list of dicts {filename, content_type, size_bytes}
        "security_headers": dict,  # SPF/DKIM/DMARC/Authentication-Results parsed
    }
"""
from __future__ import annotations

import email
import email.policy
import logging
import re
from email.message import EmailMessage
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("outlook_parser")


# ── Minimal HTML → plain-text converter ──────────────────────────────────────

class _TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self._parts: list[str] = []
        self._links: list[dict[str, Any]] = []
        self._images: list[str] = []
        self._current_href: str | None = None
        self._current_anchor: list[str] = []

    def handle_data(self, data: str) -> None:
        stripped = data.strip()
        if stripped:
            self._parts.append(stripped)
            if self._current_href:
                self._current_anchor.append(stripped)

    def handle_starttag(self, tag: str, attrs: list) -> None:
        attr_dict = dict(attrs)
        if tag == "a" and "href" in attr_dict:
            href = attr_dict["href"].strip()
            if href and not href.startswith(("javascript:", "#", "mailto:")):
                self._current_href = href
                self._current_anchor = []
        if tag == "img" and "src" in attr_dict:
            self._images.append(attr_dict["src"].strip())

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._current_href:
            anchor_text = " ".join(self._current_anchor).strip()
            parsed_domain = (urlparse(self._current_href).hostname or "").lower()
            self._links.append({
                "anchor_text": anchor_text,
                "href": self._current_href,
                "href_domain": parsed_domain,
                "link_source": "raw_href",
                "is_cta": False,
            })
            self._current_href = None
            self._current_anchor = []

    @property
    def text(self) -> str:
        return "\n".join(self._parts)


def _html_to_text(html: str) -> tuple[str, list[dict[str, Any]], list[str]]:
    """Return (plain_text, links, images) from an HTML fragment."""
    parser = _TextExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass
    return parser.text, parser._links, parser._images


# ── Security header parsing ───────────────────────────────────────────────────

def _parse_security_headers(msg: EmailMessage) -> dict[str, Any]:
    """Extract SPF, DKIM, DMARC, Reply-To mismatch, Message-ID mismatch,
    TLS, and X-Mailer — mirroring Gmail's parse_security_headers() coverage
    so the LLM receives identical forensic context for both providers."""
    result: dict[str, Any] = {}

    # ── SPF / DKIM / DMARC from Authentication-Results ──────────────────────
    auth_results = msg.get("Authentication-Results", "")
    if auth_results:
        result["authentication_results"] = auth_results[:2000]
        for proto in ("spf", "dkim", "dmarc"):
            m = re.search(rf"{proto}=(\S+)", auth_results, re.IGNORECASE)
            if m:
                result[proto] = m.group(1).lower().rstrip(";")

    received_spf = msg.get("Received-SPF", "")
    if received_spf and "spf" not in result:
        result["received_spf"] = received_spf[:500]
        m = re.match(r"\s*(\w+)", received_spf)
        if m:
            result["spf"] = m.group(1).lower()

    dkim_sig = msg.get("DKIM-Signature", "")
    if dkim_sig:
        result["dkim_signature_present"] = True

    # ── TLS detection from Received headers ─────────────────────────────────
    received_headers = msg.get_all("Received") or []
    tls_found = False
    tls_version = None
    for rcv in received_headers:
        if "tls" in rcv.lower() or "esmtps" in rcv.lower():
            tls_found = True
            m_tls = re.search(r"(TLSv[\d.]+)", rcv, re.IGNORECASE)
            if m_tls:
                tls_version = m_tls.group(1)
            break
    result["tls"] = tls_found
    if tls_version:
        result["tls_version"] = tls_version

    # ── Reply-To mismatch (classic sender-spoofing signal) ───────────────────
    from_addr = msg.get("From", "")
    reply_to = msg.get("Reply-To", None)
    from_domain = ""
    m_from = re.search(r"@([\w.-]+)", from_addr)
    if m_from:
        from_domain = m_from.group(1).lower()

    result["reply_to"] = reply_to
    reply_to_mismatch = False
    if reply_to:
        m_rt = re.search(r"@([\w.-]+)", reply_to)
        if m_rt and m_rt.group(1).lower() != from_domain:
            reply_to_mismatch = True
    result["reply_to_mismatch"] = reply_to_mismatch

    # ── Message-ID domain mismatch ───────────────────────────────────────────
    message_id = msg.get("Message-ID", "")
    msg_id_domain = None
    msg_id_mismatch = False
    m_mid = re.search(r"@([\w.-]+)", message_id)
    if m_mid:
        msg_id_domain = m_mid.group(1).lower()
        if from_domain and msg_id_domain != from_domain:
            msg_id_mismatch = True
    result["message_id_domain"] = msg_id_domain
    result["message_id_mismatch"] = msg_id_mismatch

    # ── X-Mailer ─────────────────────────────────────────────────────────────
    x_mailer = msg.get("X-Mailer", None)
    if x_mailer:
        result["x_mailer"] = x_mailer

    result["from_raw"] = from_addr

    return result


# ── Main parser ───────────────────────────────────────────────────────────────

def parse_mime_message(raw: bytes) -> dict[str, Any]:
    """Parse a raw MIME email (from Graph /$value) into SafeMail X scan dict."""
    try:
        msg: EmailMessage = email.message_from_bytes(raw, policy=email.policy.default)  # type: ignore[assignment]
    except Exception as exc:
        logger.error("Failed to parse MIME message: %s", exc)
        return {
            "subject": "(parse error)",
            "sender": "",
            "body": "",
            "images": [],
            "links": [],
            "attachments": [],
            "security_headers": {},
        }

    subject = str(msg.get("Subject", "")).strip()
    sender = str(msg.get("From", "")).strip()

    body = ""
    links: list[str] = []
    images: list[str] = []
    attachments: list[dict] = []

    # Walk MIME parts
    for part in msg.walk():
        content_type = part.get_content_type()
        disposition = str(part.get("Content-Disposition", "")).lower()

        # Attachment
        if "attachment" in disposition or part.get_filename():
            filename = part.get_filename() or "unnamed"
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": filename,
                "content_type": content_type,
                "size_bytes": len(payload),
            })
            continue

        if content_type == "text/plain" and not body:
            try:
                body = part.get_content() or ""
            except Exception:
                body = (part.get_payload(decode=True) or b"").decode("utf-8", errors="replace")

        elif content_type == "text/html":
            try:
                html = part.get_content() or ""
            except Exception:
                html = (part.get_payload(decode=True) or b"").decode("utf-8", errors="replace")
            text, html_links, html_images = _html_to_text(html)
            if not body:
                body = text
            links.extend(html_links)
            images.extend(html_images)

    security_headers = _parse_security_headers(msg)  # type: ignore[arg-type]

    return {
        "subject": subject,
        "sender": sender,
        "body": body,
        "images": images,
        "links": links,
        "attachments": attachments,
        "security_headers": security_headers,
    }
