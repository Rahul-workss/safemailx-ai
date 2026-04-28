# ============================================================
# SafeMail-X — DOCX / XLSX / PPTX Static Analyzer
# ============================================================
# Office Open XML files (.docx, .xlsx, .pptx) are ZIP archives.
# We inspect their internal structure without executing them.
# Falls back to python-docx for richer text extraction on DOCX.
# ============================================================

import io
import re
import zipfile

try:
    import docx as python_docx
    PYTHON_DOCX_AVAILABLE = True
except ImportError:
    PYTHON_DOCX_AVAILABLE = False


try:
    from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML
    OLETOOLS_AVAILABLE = True
except ImportError:
    OLETOOLS_AVAILABLE = False

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
    "enable macros",
    "enable content",
    "enable editing",
]

# ── Threat weights ──────────────────────────────────────────

WEIGHTS = {
    "vba_macro":              0.55,
    "dde_field":              0.40,
    "external_rels":          0.30,
    "suspicious_keywords":    0.15,
    "high_link_density":      0.10,
}

# ── External relationship target pattern ────────────────────
# Matches targets that point outside the ZIP (http/https/ftp/unc)
EXT_REL_PATTERN = re.compile(
    r'Target\s*=\s*"(https?://|ftp://|\\\\)',
    re.IGNORECASE
)

# ── DDE field pattern ────────────────────────────────────────
DDE_PATTERN = re.compile(
    r"(DDEAUTO|DDE\b|AUTOOPEN|AUTO_OPEN|Document_Open)",
    re.IGNORECASE
)


def _read_zip_text(zf: zipfile.ZipFile, name: str) -> str:
    """Safely read a text file from the ZIP, return empty string on error."""
    try:
        return zf.read(name).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def analyze_docx(file_bytes: bytes, filename: str = "unknown.docx") -> dict:
    """
    Statically inspect an Office Open XML file's internal structure and text.

    Args:
        file_bytes: Raw bytes of the file.
        filename:   Original filename (used for logs and output).

    Returns:
        {
            "filename":     str,
            "file_type":    "docx" | "xlsx" | "pptx" | "office",
            "threat_score": float,
            "indicators":   [str],
        }
    """
    indicators = []
    score = 0.0

    # Derive clean type label from extension
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else "office"
    DOCX_EXTENSIONS = {'.docx', '.doc', '.xlsx', '.xls', '.pptx', '.ppt', '.docm', '.xlsm', '.pptm'}
    file_type = ext if f".{ext}" in DOCX_EXTENSIONS else "office"

    # Verify it is a valid ZIP
    if not zipfile.is_zipfile(io.BytesIO(file_bytes)):
        print(f"[DOCX_ANALYZER] {filename} is not a valid ZIP/Office file")
        return {
            "filename":     filename,
            "file_type":    file_type,
            "threat_score": 0.0,
            "indicators":   ["invalid_zip_structure"],
        }

    try:
        zf = zipfile.ZipFile(io.BytesIO(file_bytes))
    except Exception as e:
        print(f"[DOCX_ANALYZER] Failed to open {filename}: {e}")
        return {
            "filename":     filename,
            "file_type":    file_type,
            "threat_score": 0.0,
            "indicators":   ["corrupt_or_unreadable"],
        }

    namelist = zf.namelist()

    # ── 1. VBA Macro check ───────────────────────────────────
    vba_bin_found = any("vbaProject.bin" in n or "vbaproject.bin" in n.lower() for n in namelist)
    if vba_bin_found:
        if OLETOOLS_AVAILABLE:
            try:
                vbaparser = VBA_Parser(filename, data=file_bytes)
                if vbaparser.detect_vba_macros():
                    results = vbaparser.analyze_macros()
                    weaponized = False
                    for kw_type, keyword, description in results:
                        if kw_type in ('Suspicious', 'AutoExec', 'IOC'):
                            indicators.append(f"weaponized_vba:{keyword}")
                            weaponized = True
                            score += 0.8  # Critical penalty for payload execution code
                    
                    if not weaponized:
                        indicators.append("benign_vba_macro")
                        score += 0.2
            except Exception as e:
                print(f"[DOCX_ANALYZER] oletools failed to parse: {e}")
                indicators.append("vba_macro_detected")
                score += WEIGHTS["vba_macro"]
        else:
            indicators.append("vba_macro_detected")
            score += WEIGHTS["vba_macro"]

    # ── 2. DDE / auto-run field codes ────────────────────────
    # Check word/document.xml (DOCX) or xl/workbook.xml (XLSX)
    doc_xml_candidates = [
        "word/document.xml",
        "xl/workbook.xml",
        "ppt/presentation.xml",
        "word/settings.xml",
    ]
    for candidate in doc_xml_candidates:
        if candidate in namelist:
            content = _read_zip_text(zf, candidate)
            if DDE_PATTERN.search(content):
                indicators.append("dde_autorun_field")
                score += WEIGHTS["dde_field"]
                break

    # ── 3. External relationship targets ─────────────────────
    rels_files = [n for n in namelist if "_rels" in n and n.endswith(".rels")]
    ext_rel_found = False
    for rels_file in rels_files:
        content = _read_zip_text(zf, rels_file)
        if EXT_REL_PATTERN.search(content):
            ext_rel_found = True
            break
    if ext_rel_found:
        indicators.append("external_relationship_target")
        score += WEIGHTS["external_rels"]

    # ── 4. Suspicious keywords in document text ───────────────
    full_text = ""
    if file_type == "docx" and PYTHON_DOCX_AVAILABLE:
        try:
            doc = python_docx.Document(io.BytesIO(file_bytes))
            full_text = "\n".join(p.text for p in doc.paragraphs)
        except Exception:
            pass  # Fall through to XML extraction

    if not full_text:
        # Fallback: extract raw text from XML parts
        xml_text_parts = []
        for name in namelist:
            if name.endswith(".xml"):
                raw = _read_zip_text(zf, name)
                # Strip XML tags
                plain = re.sub(r"<[^>]+>", " ", raw)
                xml_text_parts.append(plain)
        full_text = " ".join(xml_text_parts)

    text_lower = full_text.lower()
    kw_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in text_lower]
    if kw_hits:
        indicators.append(f"suspicious_keywords:{len(kw_hits)}_matches")
        score += WEIGHTS["suspicious_keywords"]

    # ── 5. High hyperlink density ─────────────────────────────
    all_rels_text = " ".join(
        _read_zip_text(zf, n) for n in rels_files
    )
    http_links = re.findall(r'Target\s*=\s*"https?://[^"]+', all_rels_text, re.IGNORECASE)
    if len(http_links) > 10:
        indicators.append(f"high_link_density:{len(http_links)}_links")
        score += WEIGHTS["high_link_density"]

    zf.close()

    # Cap score at 1.0
    score = round(min(score, 1.0), 3)

    print(f"[DOCX_ANALYZER] {filename} -> score={score}, indicators={indicators}")

    return {
        "filename":     filename,
        "file_type":    file_type,
        "threat_score": score,
        "indicators":   indicators,
    }
