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
    """Extract SPF, DKIM, DMARC, and Authentication-Results info."""
    result: dict[str, Any] = {}

    auth_results = msg.get("Authentication-Results", "")
    if auth_results:
        result["authentication_results"] = auth_results[:2000]
        # Quick pass/fail extraction
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
