# ============================================================
# SafeMail-X — Attachment Analysis Orchestrator
# ============================================================
# Receives a list of { "filename": str, "bytes": bytes } dicts
# from the email parser, routes each to the correct sub-analyzer,
# and aggregates the results into a single threat summary.
# ============================================================

from engines.analyzers.pdf_analyzer  import analyze_pdf
from engines.analyzers.docx_analyzer import analyze_docx


# ── MIME / extension routing ────────────────────────────────

PDF_EXTENSIONS   = {".pdf"}
DOCX_EXTENSIONS  = {".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt",
                    ".docm", ".xlsm", ".pptm"}  # macro-enabled variants

import hashlib
import requests

from utils.config import VIRUSTOTAL_API_KEY, is_configured_secret


HIGH_RISK_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".com", ".ps1"}
SCRIPT_EXTENSIONS = {".js", ".vbs", ".jse", ".wsf", ".hta"}
CONTAINER_EXTENSIONS = {".zip", ".rar", ".7z"}
CONTENT_EXTENSIONS = {".html", ".htm", ".eml"}

def _check_magic_bytes(file_bytes: bytes, ext: str):
    """Inspects raw hex header to catch RTLO or extension spoofing (e.g. .exe renamed to .pdf)."""
    if len(file_bytes) < 4: return False, "empty"
    header = file_bytes[:4]
    
    is_pdf = header.startswith(b"%PDF")
    is_zip = header.startswith(b"PK\x03\x04")
    is_exe = header.startswith(b"MZ")
    
    if ext in PDF_EXTENSIONS:
        if is_exe: return True, "executable_spoofing"
        if not is_pdf: return True, "corrupt_or_mismatched_pdf"
    elif ext in DOCX_EXTENSIONS:
        if is_exe: return True, "executable_spoofing"
        if not is_zip: return True, "corrupt_or_mismatched_office_zip"
        
    return False, "valid"

def _check_virustotal_hash(file_bytes: bytes) -> tuple:
    """Calculates SHA-256 entirely in RAM and checks VirusTotal reputation."""
    if not is_configured_secret(VIRUSTOTAL_API_KEY):
        return None, []
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    try:
        url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        r = requests.get(url, headers=headers, timeout=2.0)
        if r.status_code == 200:
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            if malicious > 0:
                return 1.0, [f"virustotal_malicious:{malicious}_engines_flagged"]
    except Exception as e:
        print(f"[VT ERROR] {e}")
    return None, []

def _get_extension(filename: str) -> str:
    """Return lowercase file extension including the dot, e.g. '.pdf'"""
    if "." in filename:
        return "." + filename.rsplit(".", 1)[-1].lower()
    return ""


def analyze_attachments(attachments: list) -> dict:
    """
    Analyze a list of email attachments using static inspection.
    """
    findings = []

    for item in attachments:
        filename  = item.get("filename", "unknown")
        raw_bytes = item.get("bytes", b"")
        ext       = _get_extension(filename)

        if not raw_bytes:
            print(f"[ATTACHMENT] Skipping {filename} — no bytes received")
            continue

        # 1. Zero-Knowledge Hash Reputation
        vt_score, vt_inds = _check_virustotal_hash(raw_bytes)
        if vt_score == 1.0:
            print(f"[ATTACHMENT] VirusTotal caught known malware hash for {filename}!")
            findings.append({
                "filename": filename,
                "file_type": ext.replace(".", ""),
                "threat_score": 1.0,
                "indicators": vt_inds
            })
            continue

        if ext in HIGH_RISK_EXTENSIONS:
            findings.append({
                "filename": filename,
                "file_type": ext.replace(".", "") or "executable",
                "threat_score": 0.95,
                "indicators": [f"high_risk_executable_attachment:{ext}"]
            })
            continue

        if ext in SCRIPT_EXTENSIONS:
            findings.append({
                "filename": filename,
                "file_type": ext.replace(".", "") or "script",
                "threat_score": 0.85,
                "indicators": [f"script_attachment:{ext}"]
            })
            continue

        if ext in CONTENT_EXTENSIONS:
            findings.append({
                "filename": filename,
                "file_type": ext.replace(".", "") or "content",
                "threat_score": 0.55,
                "indicators": [f"active_content_or_forwarded_mail_attachment:{ext}"]
            })
            continue

        if ext in CONTAINER_EXTENSIONS:
            findings.append({
                "filename": filename,
                "file_type": ext.replace(".", "") or "archive",
                "threat_score": 0.45,
                "indicators": [f"archive_attachment_requires_manual_review:{ext}"]
            })
            continue

        # 2. True Signature Magic Byte Validation
        is_spoofed, true_type = _check_magic_bytes(raw_bytes, ext)
        if is_spoofed:
            print(f"[ATTACHMENT] Magic Byte Spoofing detected in {filename} -> {true_type}")
            findings.append({
                "filename": filename,
                "file_type": ext.replace(".", ""),
                "threat_score": 1.0 if "executable" in true_type else 0.5,
                "indicators": [f"magic_byte_mismatch:{true_type}"]
            })
            continue

        if ext in PDF_EXTENSIONS:
            result = analyze_pdf(raw_bytes, filename)
            findings.append(result)

        elif ext in DOCX_EXTENSIONS:
            result = analyze_docx(raw_bytes, filename)
            findings.append(result)

        else:
            # Unknown type — log and skip (don't crash the pipeline)
            print(f"[ATTACHMENT] Unsupported type '{ext}' for '{filename}' — skipping")

    if not findings:
        return {
            "attachment_score":    None,
            "attachment_findings": [],
        }

    # Aggregate score = max individual threat score
    # Rationale: one malicious attachment is enough to flag the email
    aggregate_score = max(f["threat_score"] for f in findings)

    print(f"[ATTACHMENT] Aggregate attachment score: {aggregate_score} across {len(findings)} file(s)")

    return {
        "attachment_score":    round(aggregate_score, 3),
        "attachment_findings": findings,
    }
