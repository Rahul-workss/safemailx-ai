import re
import base64
from bs4 import BeautifulSoup
from urllib.parse import urlparse


def _decode_gmail_body(data):
    if not data:
        return ""
    pad = len(data) % 4
    if pad:
        data += "=" * (4 - pad)
    return base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")


def _append_unique(items, value):
    if value and value not in items:
        items.append(value)


CTA_TOKENS = (
    "claim", "offer", "unlock", "verify", "continue", "redeem",
    "activate", "upgrade", "view now", "apply now", "get started",
    "shop now", "open offer",
)


def _extract_domain(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _is_cta_text(text: str) -> bool:
    normalized = re.sub(r"\s+", " ", (text or "").strip().lower())
    return any(token in normalized for token in CTA_TOKENS)


def _looks_hidden(tag):
    if tag.name in {"script", "style", "head", "title", "meta", "link", "noscript"}:
        return True

    if tag.has_attr("hidden") or tag.get("aria-hidden") == "true":
        return True

    classes = " ".join(tag.get("class", [])).lower()
    if any(token in classes for token in ("preheader", "preview", "hidden")):
        return True

    style = re.sub(r"\s+", "", tag.get("style", "").lower())
    hidden_markers = (
        "display:none",
        "visibility:hidden",
        "opacity:0",
        "font-size:0",
        "font-size:0px",
        "max-height:0",
        "max-height:0px",
        "width:0",
        "width:0px",
        "height:0",
        "height:0px",
        "mso-hide:all",
    )
    return any(marker in style for marker in hidden_markers)


def _html_text_and_images(html):
    soup = BeautifulSoup(html, "html.parser")

    for tag in list(soup.find_all(_looks_hidden)):
        tag.decompose()

    image_sources = []
    for img in soup.find_all("img"):
        src = (img.get("src") or "").strip()
        if src.startswith(("http://", "https://", "data:image/")):
            _append_unique(image_sources, src)

    links = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith(("http://", "https://")):
            anchor_text = re.sub(r"\s+", " ", a.get_text(" ", strip=True)).strip()
            link_record = {
                "anchor_text": anchor_text,
                "href": href,
                "href_domain": _extract_domain(href),
                "is_cta": _is_cta_text(anchor_text),
                "link_source": "raw_href",
            }
            if link_record not in links:
                links.append(link_record)

            replacement = f"{anchor_text} -> {href}" if anchor_text else href
            a.replace_with(replacement)

    extracted_text = soup.get_text(separator="\n", strip=True)

    if links:
        extracted_text += "\n" + "\n".join(
            f"{link['anchor_text']} -> {link['href']}" if link.get("anchor_text") else link["href"]
            for link in links
        )

    return extracted_text, image_sources, links


# MIME types treated as scannable file attachments
def parse_security_headers(headers: list) -> dict:
    """
    Parses the raw Gmail header list and extracts every security-relevant
    field into a clean structured dict for forensic reporting.
    """
    raw = {h["name"].lower(): h["value"] for h in headers}

    # ── SPF / DKIM / DMARC from Authentication-Results ──────────────────────
    auth_results = raw.get("authentication-results", "")

    def _extract_auth(field):
        m = re.search(rf"{field}=(\w+)", auth_results, re.IGNORECASE)
        return m.group(1).lower() if m else "none"

    spf   = _extract_auth("spf")
    dkim  = _extract_auth("dkim")
    dmarc = _extract_auth("dmarc")

    # ── TLS detection from Received headers ─────────────────────────────────
    received_headers = [h["value"] for h in headers if h["name"].lower() == "received"]
    tls_found    = False
    tls_version  = None
    for rcv in received_headers:
        if "tls" in rcv.lower() or "esmtps" in rcv.lower():
            tls_found = True
            m = re.search(r"(TLSv[\d.]+)", rcv, re.IGNORECASE)
            if m:
                tls_version = m.group(1)
            break

    # ── Reply-To mismatch ───────────────────────────────────────────────────
    from_addr  = raw.get("from", "")
    reply_to   = raw.get("reply-to", None)
    from_domain = ""
    m = re.search(r"@([\w.-]+)", from_addr)
    if m:
        from_domain = m.group(1).lower()

    reply_to_mismatch = False
    if reply_to:
        m2 = re.search(r"@([\w.-]+)", reply_to)
        if m2 and m2.group(1).lower() != from_domain:
            reply_to_mismatch = True

    # ── X-Mailer ────────────────────────────────────────────────────────────
    x_mailer = raw.get("x-mailer", None)

    # ── Message-ID domain mismatch ──────────────────────────────────────────
    message_id = raw.get("message-id", "")
    msg_id_domain = None
    msg_id_mismatch = False
    m3 = re.search(r"@([\w.-]+)", message_id)
    if m3:
        msg_id_domain = m3.group(1).lower()
        if from_domain and msg_id_domain != from_domain:
            msg_id_mismatch = True

    return {
        "spf":                 spf,
        "dkim":                dkim,
        "dmarc":               dmarc,
        "tls":                 tls_found,
        "tls_version":         tls_version,
        "reply_to":            reply_to,
        "reply_to_mismatch":   reply_to_mismatch,
        "x_mailer":            x_mailer,
        "message_id_domain":   msg_id_domain,
        "message_id_mismatch": msg_id_mismatch,
        "received_chain":      received_headers,
        "from_raw":            from_addr,
        "from_domain":         from_domain,
    }


_FILE_ATTACHMENT_MIME_TYPES = {
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",   # .docx
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",         # .xlsx
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",  # .pptx
    "application/msword",        # legacy .doc
    "application/vnd.ms-excel",  # legacy .xls
    "application/vnd.ms-powerpoint",  # legacy .ppt
    "application/octet-stream",  # catch-all binary — inspected by extension
}


def _extract_parts(service, message_id, parts, body_list, images_list, attachments_list, links_list):
    """
    Recursively scans nested MIME parts to pull text/plain strings,
    detects/downloads image attachments into base64 data URIs, and
    downloads file attachments (PDF, DOCX, XLSX, PPTX) as raw bytes.
    """
    for part in parts:
        mime_type = part.get("mimeType", "")
        filename_hdr = part.get("filename") or ""

        if filename_hdr and not mime_type.startswith("image/") and not mime_type.startswith("multipart/"):
            body_data = part.get("body", {})
            data_raw = None
            if "attachmentId" in body_data:
                att_id = body_data["attachmentId"]
                print(f"[PARSER] Found file attachment '{filename_hdr}' ({mime_type}). Downloading...")
                try:
                    att = service.users().messages().attachments().get(
                        userId='me', messageId=message_id, id=att_id
                    ).execute()
                    data_raw = att.get("data", "")
                except Exception as e:
                    print(f"[ERROR] Failed downloading file attachment '{filename_hdr}': {e}")
            elif "data" in body_data:
                data_raw = body_data["data"]

            if data_raw:
                standard_b64 = data_raw.replace("-", "+").replace("_", "/")
                pad = len(standard_b64) % 4
                if pad:
                    standard_b64 += "=" * (4 - pad)
                attachments_list.append({
                    "filename": filename_hdr,
                    "bytes":    base64.b64decode(standard_b64),
                })
            continue
        
        if mime_type == "text/plain":
            data = part.get("body", {}).get("data")
            if data:
                decoded = _decode_gmail_body(data)
                body_list.append(decoded)
                
        elif mime_type == "text/html":
            data = part.get("body", {}).get("data")
            if data:
                decoded = _decode_gmail_body(data)
                html_text, html_images, html_links = _html_text_and_images(decoded)
                body_list.append(html_text)
                for src in html_images:
                    _append_unique(images_list, src)
                for link in html_links:
                    if link not in links_list:
                        links_list.append(link)
                
        elif mime_type.startswith("multipart/"):
            nested_parts = part.get("parts", [])
            _extract_parts(service, message_id, nested_parts, body_list, images_list, attachments_list, links_list)
            
        elif mime_type.startswith("image/"):
            body_data = part.get("body", {})
            
            data_raw = None
            if "attachmentId" in body_data:
                # Gmail strips large file data. We must make a separate API call to get it.
                att_id = body_data["attachmentId"]
                print(f"[PARSER] Found {mime_type} attachment. Downloading payload from Google...")
                try:
                    att = service.users().messages().attachments().get(
                        userId='me', messageId=message_id, id=att_id
                    ).execute()
                    data_raw = att.get("data", "")
                except Exception as e:
                    print(f"[ERROR] Failed downloading attachment data: {e}")
            elif "data" in body_data:
                # Small inline objects have the data baked right in
                data_raw = body_data["data"]
                print(f"[PARSER] Found inline {mime_type} image.")

            if data_raw:
                # Gmail returns URL-Safe Base64 ('-' and '_'). 
                # Our frontend / image_downloader expects standard Base64 ('+' and '/').
                standard_b64 = data_raw.replace("-", "+").replace("_", "/")
                
                # Fix any missing padding
                pad = len(standard_b64) % 4
                if pad:
                    standard_b64 += "=" * (4 - pad)
                    
                # Format exactly like a typical browser data URI
                images_list.append(f"data:{mime_type};base64,{standard_b64}")

        elif mime_type in _FILE_ATTACHMENT_MIME_TYPES or mime_type.startswith("application/"):
            # ── File Attachment (PDF / DOCX / XLSX / PPTX) ──────────────────
            body_data    = part.get("body", {})
            filename_hdr = part.get("filename") or "unknown_attachment"

            data_raw = None
            if "attachmentId" in body_data:
                att_id = body_data["attachmentId"]
                print(f"[PARSER] Found file attachment '{filename_hdr}' ({mime_type}). Downloading...")
                try:
                    att = service.users().messages().attachments().get(
                        userId='me', messageId=message_id, id=att_id
                    ).execute()
                    data_raw = att.get("data", "")
                except Exception as e:
                    print(f"[ERROR] Failed downloading file attachment '{filename_hdr}': {e}")
            elif "data" in body_data:
                data_raw = body_data["data"]
                print(f"[PARSER] Found inline file attachment '{filename_hdr}'.")

            if data_raw:
                import base64 as _b64
                # Gmail returns URL-safe base64 — convert to standard, fix padding
                standard_b64 = data_raw.replace("-", "+").replace("_", "/")
                pad = len(standard_b64) % 4
                if pad:
                    standard_b64 += "=" * (4 - pad)
                raw_bytes = _b64.b64decode(standard_b64)
                attachments_list.append({
                    "filename": filename_hdr,
                    "bytes":    raw_bytes,
                })


def parse_email(service, message_id, message):
    headers = message["payload"]["headers"]
    subject = next((h["value"] for h in headers if h["name"] == "Subject"), "No Subject")
    sender = next((h["value"] for h in headers if h["name"] == "From"), "Unknown")
    
    body_list       = []
    images_list     = []
    attachments_list = []
    links_list = []
    
    if "parts" in message["payload"]:
        _extract_parts(service, message_id, message["payload"]["parts"], body_list, images_list, attachments_list, links_list)
    else:
        # Single payload email (no attachments or nesting)
        mime_type = message["payload"].get("mimeType", "")
        if mime_type == "text/plain" or mime_type == "text/html":
            data = message["payload"].get("body", {}).get("data")
            if data:
                decoded = _decode_gmail_body(data)
                if mime_type == "text/html":
                    html_text, html_images, html_links = _html_text_and_images(decoded)
                    body_list.append(html_text)
                    for src in html_images:
                        _append_unique(images_list, src)
                    for link in html_links:
                        if link not in links_list:
                            links_list.append(link)
                else:
                    body_list.append(decoded)
                
    if attachments_list:
        print(f"[PARSER] Extracted {len(attachments_list)} file attachment(s): "
              f"{[a['filename'] for a in attachments_list]}")

    security_headers = parse_security_headers(headers)

    return {
        "subject":          subject,
        "sender":           sender,
        "body":             "\n".join(body_list),
        "images":           images_list,
        "links":            links_list,
        "attachments":      attachments_list,
        "security_headers": security_headers,
    }
