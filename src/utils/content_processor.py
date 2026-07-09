import re
import unicodedata

from bs4 import BeautifulSoup

from .ocr_engine import extract_text_from_image
from .config import debug_log


_INVISIBLE_TRANSLATION = str.maketrans({
    "\u00ad": "",
    "\u034f": "",
    "\u061c": "",
    "\u180e": "",
    "\u200b": "",
    "\u200c": "",
    "\u200d": "",
    "\u200e": "",
    "\u200f": "",
    "\u202a": "",
    "\u202b": "",
    "\u202c": "",
    "\u202d": "",
    "\u202e": "",
    "\u2060": "",
    "\u2061": "",
    "\u2062": "",
    "\u2063": "",
    "\u2064": "",
    "\u2066": "",
    "\u2067": "",
    "\u2068": "",
    "\u2069": "",
    "\ufeff": "",
})


def _line_has_signal(line):
    return bool(re.search(r"[A-Za-z0-9]", line))


def _html_to_text_preserving_links(text_str: str) -> str:
    soup = BeautifulSoup(text_str, "html.parser")
    for tag in soup(["script", "style", "head", "title", "meta", "link", "noscript"]):
        tag.decompose()

    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        anchor_text = re.sub(r"\s+", " ", a.get_text(" ", strip=True)).strip()
        if href.startswith(("http://", "https://")):
            replacement = f"{anchor_text} -> {href}" if anchor_text else href
            a.replace_with(replacement)

    return soup.get_text(separator="\n", strip=True)


def clean_extracted_text(text):
    """
    Remove invisible email padding and normalize spacing while preserving
    meaningful line breaks for terminal evidence and LLM analysis.
    """
    if not text:
        return ""

    # Defense-in-depth: If the text is raw HTML (e.g. wrapped in text/plain MIME part),
    # strip all HTML tags, scripts, and styles using BeautifulSoup first.
    text_str = str(text)
    if "<html" in text_str.lower() or "<!doctype" in text_str.lower() or "<body>" in text_str.lower() or "<p>" in text_str.lower():
        try:
            text_str = _html_to_text_preserving_links(text_str)
        except Exception:
            pass

    normalized = unicodedata.normalize("NFKC", text_str)
    normalized = normalized.translate(_INVISIBLE_TRANSLATION)
    normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")
    normalized = normalized.replace("\xa0", " ")

    cleaned_lines = []
    blank_seen = False

    for raw_line in normalized.split("\n"):
        line = re.sub(r"[\t\f\v]+", " ", raw_line)
        line = re.sub(r"[ ]{2,}", " ", line).strip()

        # Marketing emails often pad previews with lines made only of spacing
        # or invisible remnants. Keep one blank line, drop the rest.
        if not line:
            if cleaned_lines and not blank_seen:
                cleaned_lines.append("")
                blank_seen = True
            continue

        if not _line_has_signal(line) and len(line) > 20:
            continue

        cleaned_lines.append(line)
        blank_seen = False

    return "\n".join(cleaned_lines).strip()


def clean_terminal_evidence_text(text):
    """
    Build a human-readable terminal view of extracted email text.
    Keeps the useful body copy and hides tracking URLs/image placeholders.
    """
    cleaned = clean_extracted_text(text)
    if not cleaned:
        return ""

    marker = "---------- Forwarded message ---------"
    first_marker = cleaned.find(marker)
    if first_marker != -1:
        second_marker = cleaned.find(marker, first_marker + len(marker))
        if second_marker != -1:
            cleaned = cleaned[:second_marker].strip()

    display_lines = []
    blank_seen = False
    skipping_image_label = False

    for raw_line in cleaned.splitlines():
        line = raw_line.strip()

        if skipping_image_label:
            if "]" in line:
                skipping_image_label = False
            continue

        if line.lower().startswith("[image"):
            if "]" not in line:
                skipping_image_label = True
            continue

        if re.match(r"^<?https?://", line, re.IGNORECASE):
            continue

        if re.match(r"^<https?://.*>$", line, re.IGNORECASE):
            continue

        line = re.sub(r"\*([^*]+)\*", r"\1", line)
        line = line.replace("\\u0026", "&")

        if not line:
            if display_lines and not blank_seen:
                display_lines.append("")
                blank_seen = True
            continue

        display_lines.append(line)
        blank_seen = False

    return "\n".join(display_lines).strip()


def collect_ocr_texts(image_paths=None):
    """Run OCR over image paths and return cleaned non-empty OCR results."""
    ocr_texts = []

    if not image_paths:
        return ocr_texts

    for img in image_paths:
        debug_log(f"[OCR DEBUG] Running OCR on image: {img}")
        ocr_text = clean_extracted_text(extract_text_from_image(img))
        debug_log(f"[OCR DEBUG] OCR text for {img}:\n{ocr_text}")

        if ocr_text:
            ocr_texts.append(ocr_text)

    return ocr_texts


def build_full_email_text(email_body, image_paths=None):
    """
    Combine email body text with OCR extracted text.
    Verbose text dumps are gated behind SAFEMAILX_DEBUG=true.
    """

    combined_parts = [clean_extracted_text(email_body)]
    combined_parts.extend(collect_ocr_texts(image_paths))
    combined_text = clean_extracted_text("\n\n".join(part for part in combined_parts if part))

    debug_log(f"[CONTENT DEBUG] Final analysis text:\n{combined_text}")

    return combined_text
