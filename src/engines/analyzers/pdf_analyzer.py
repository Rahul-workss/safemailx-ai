# ============================================================
# SafeMail-X — PDF Static Analyzer
# ============================================================
# Uses PyMuPDF (fitz) to inspect PDF bytes WITHOUT executing them.
# Returns a threat_score (0.0–1.0) and a list of detected indicators.
# ============================================================

import io
import re

try:
    import fitz  # PyMuPDF
    PYMUPDF_AVAILABLE = True
except ImportError:
    PYMUPDF_AVAILABLE = False


# ── Suspicious keyword list scanned against extracted text ──

SUSPICIOUS_KEYWORDS = [
    "verify your account",
    "confirm your identity",
    "click here immediately",
    "your account will be suspended",
    "enter your password",
    "update your payment",
    "login to continue",
    "unauthorized access",
    "security alert",
    "reset your password",
    "wire transfer",
    "invoice attached",
    "urgent action required",
]

# ── Threat weights ──────────────────────────────────────────

WEIGHTS = {
    "embedded_javascript":    0.45,
    "auto_open_action":       0.40,
    "high_url_count":         0.20,
    "suspicious_keywords":    0.15,
    "encrypted_no_password":  0.10,
}


def analyze_pdf(file_bytes: bytes, filename: str = "unknown.pdf") -> dict:
    """
    Statically inspect a PDF's internal structure and extracted text.

    Args:
        file_bytes: Raw bytes of the PDF file.
        filename:   Original filename (used in log messages only).

    Returns:
        {
            "filename":     str,
            "file_type":    "pdf",
            "threat_score": float,   # 0.0 – 1.0
            "indicators":   [str],
        }
    """
    indicators = []
    score = 0.0

    if not PYMUPDF_AVAILABLE:
        print(f"[PDF_ANALYZER] PyMuPDF not available — skipping {filename}")
        return {
            "filename":     filename,
            "file_type":    "pdf",
            "threat_score": 0.0,
            "indicators":   ["pymupdf_not_installed"],
        }

    try:
        pdf = fitz.open(stream=io.BytesIO(file_bytes), filetype="pdf")
    except Exception as e:
        print(f"[PDF_ANALYZER] Failed to open {filename}: {e}")
        return {
            "filename":     filename,
            "file_type":    "pdf",
            "threat_score": 0.0,
            "indicators":   ["corrupt_or_unreadable"],
        }

    # ── 0. Anti-Obfuscation Raw Byte Scan ───────────────────
    try:
        raw_pdf_str = file_bytes.decode('latin-1').lower()
        if "/acroform" in raw_pdf_str and ("/js" in raw_pdf_str or "/javascript" in raw_pdf_str):
            indicators.append("acroform_javascript_obfuscation")
            score += 0.6
        if raw_pdf_str.count("/objstm") > 5:
            indicators.append("high_object_stream_density_suspicious")
            score += 0.2
        # Hex encoded /JavaScript trick (e.g. /J#61vaScript)
        if re.search(r"/[a-z0-9_]*#[0-9a-f]{2}", raw_pdf_str):
            indicators.append("hex_encoded_object_obfuscation")
            score += 0.8
    except Exception as e:
        print(f"[PDF_ANALYZER] Raw obfuscation scan error: {e}")

    # ── 1. Embedded JavaScript ──────────────────────────────
    try:
        xref_count = pdf.xref_length()
        for xref in range(1, xref_count):
            try:
                obj_str = pdf.xref_object(xref)
                if "/JS" in obj_str or "/JavaScript" in obj_str:
                    indicators.append("embedded_javascript")
                    score += WEIGHTS["embedded_javascript"]
                    break  # one hit is enough
            except Exception:
                continue
    except Exception as e:
        print(f"[PDF_ANALYZER] xref scan error in {filename}: {e}")

    # ── 2. Auto-open / auto-launch actions ──────────────────
    try:
        trailer_raw = str(pdf.pdf_trailer())
        if any(kw in trailer_raw for kw in ("/OpenAction", "/AA", "/Launch")):
            indicators.append("auto_open_action")
            score += WEIGHTS["auto_open_action"]
    except Exception as e:
        print(f"[PDF_ANALYZER] Trailer scan error in {filename}: {e}")

    # ── 3. External URL count ────────────────────────────────
    try:
        url_set = set()
        for page in pdf:
            for link in page.get_links():
                uri = link.get("uri", "")
                if uri.startswith("http"):
                    url_set.add(uri)
        if len(url_set) > 5:
            indicators.append(f"high_url_count:{len(url_set)}")
            score += WEIGHTS["high_url_count"]
    except Exception as e:
        print(f"[PDF_ANALYZER] Link scan error in {filename}: {e}")

    # ── 4. Suspicious keywords in extracted text ─────────────
    try:
        full_text = ""
        for page in pdf:
            full_text += page.get_text()
        text_lower = full_text.lower()
        kw_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in text_lower]
        if kw_hits:
            indicators.append(f"suspicious_keywords:{len(kw_hits)}_matches")
            score += WEIGHTS["suspicious_keywords"]
    except Exception as e:
        print(f"[PDF_ANALYZER] Text extraction error in {filename}: {e}")

    # ── 5. Encrypted with no user-password required ──────────
    try:
        if pdf.is_encrypted and pdf.authenticate("") == 1:
            indicators.append("encrypted_no_password")
            score += WEIGHTS["encrypted_no_password"]
    except Exception as e:
        print(f"[PDF_ANALYZER] Encryption check error in {filename}: {e}")

    pdf.close()

    # Cap score at 1.0
    score = round(min(score, 1.0), 3)

    print(f"[PDF_ANALYZER] {filename} -> score={score}, indicators={indicators}")

    return {
        "filename":     filename,
        "file_type":    "pdf",
        "threat_score": score,
        "indicators":   indicators,
    }
