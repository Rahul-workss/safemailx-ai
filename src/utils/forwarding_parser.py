import re

from utils.email_parser import parse_security_headers


FORWARDED_MARKERS = [
    r"---------- Forwarded message ---------",
    r"Begin forwarded message:",
    r"Original Message",
]


def extract_forwarded_payload(text: str) -> str:
    """Return the forwarded payload if a common forward marker is present."""
    if not text:
        return ""

    for marker in FORWARDED_MARKERS:
        match = re.search(marker, text, re.IGNORECASE)
        if match:
            return text[match.start():]

    from_match = re.search(r"(?im)^\s*(?:From|De|Von):\s+.+", text)
    if from_match:
        return text[from_match.start():]

    return text


def extract_original_sender(text: str) -> str:
    """Extract the original sender address from a forwarded header block."""
    if not text:
        return "unknown_origin"

    match = re.search(
        r"(?im)^\s*(?:From|De|Von):\s*.*?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        text,
    )
    return match.group(1).lower() if match else "unknown_origin"


def extract_original_headers(text: str) -> tuple[dict, str]:
    """
    Parse original headers when a forwarded payload includes raw headers.
    Returns (headers, auth_context). Most Gmail forwards only expose display
    headers, so this commonly returns forwarder_only.
    """
    if not text:
        return {}, "unknown"

    header_lines = []
    in_headers = False
    for line in text.splitlines():
        if re.match(r"(?i)^\s*(from|to|date|subject|reply-to|message-id|authentication-results|received):", line):
            in_headers = True
            header_lines.append(line.strip())
            continue
        if in_headers:
            if not line.strip():
                break
            if line.startswith((" ", "\t")) and header_lines:
                header_lines[-1] += " " + line.strip()
            elif re.match(r"^[A-Za-z0-9-]+:", line):
                header_lines.append(line.strip())
            else:
                break

    parsed_headers = []
    for line in header_lines:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        parsed_headers.append({"name": name.strip(), "value": value.strip()})

    has_auth = any(h["name"].lower() == "authentication-results" for h in parsed_headers)
    has_received = any(h["name"].lower() == "received" for h in parsed_headers)
    if has_auth or has_received:
        return parse_security_headers(parsed_headers), "original_headers"
    if parsed_headers:
        return {}, "forwarder_only"
    return {}, "unknown"
