import logging
import os
import bs4
import email

logger = logging.getLogger("FILE_ANALYZER")

try:
    from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML
    OLETOOLS_AVAILABLE = True
except ImportError:
    OLETOOLS_AVAILABLE = False
    logger.warning("oletools not installed. Macro extraction disabled.")

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("yara-python not installed. YARA scanning disabled.")

# Load YARA rules from directory
_YARA_RULES = None
if YARA_AVAILABLE:
    try:
        rules_dir = os.path.join(os.path.dirname(__file__), "yara_rules")
        rule_files = {}
        if os.path.exists(rules_dir):
            for f in os.listdir(rules_dir):
                if f.endswith('.yar'):
                    rule_files[f] = os.path.join(rules_dir, f)
            
            if rule_files:
                _YARA_RULES = yara.compile(filepaths=rule_files)
                logger.info(f"Successfully loaded {len(rule_files)} YARA rule files.")
    except Exception as e:
        logger.error(f"Failed to compile YARA rules: {e}")


def extract_and_analyze_attachments(filename: str, file_bytes: bytes) -> dict:
    """
    Stage 2: Static Binary Analysis
    Extracts text, checks for macros using oletools, and scans raw bytes with YARA.
    """
    metrics = {
        "has_macros": False,
        "suspicious_macros": False,
        "yara_hits": [],
        "extracted_text": "",
        "extracted_urls": []
    }

    # 1. YARA Static Scan (Raw Bytes)
    if YARA_AVAILABLE and _YARA_RULES:
        try:
            matches = _YARA_RULES.match(data=file_bytes)
            if matches:
                metrics["yara_hits"] = [m.rule for m in matches]
        except Exception as e:
            logger.debug(f"YARA scan failed: {e}")

    # 2. Document Macro Extraction (oletools)
    if OLETOOLS_AVAILABLE:
        try:
            vbaparser = VBA_Parser(filename, data=file_bytes)
            if vbaparser.detect_vba_macros():
                metrics["has_macros"] = True
                results = vbaparser.analyze_macros()
                for kw_type, keyword, description in results:
                    # Flag AutoExec or Suspicious keywords
                    if kw_type in ('AutoExec', 'Suspicious', 'IOC'):
                        metrics["suspicious_macros"] = True
                        break
            vbaparser.close()
        except Exception as e:
            logger.debug(f"oletools analysis failed: {e}")

    # 3. Text & URL Extraction for SLM (Stage 4)
    text = ""
    urls = []
    
    if filename.lower().endswith('.eml'):
        try:
            msg = email.message_from_bytes(file_bytes)
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    text += part.get_payload(decode=True).decode(errors='ignore')
                elif part.get_content_type() == 'text/html':
                    soup = bs4.BeautifulSoup(part.get_payload(decode=True), 'html.parser')
                    text += soup.get_text(separator=' ')
                    urls.extend([a['href'] for a in soup.find_all('a', href=True)])
        except Exception:
            pass
    elif filename.lower().endswith(('.html', '.htm')):
        try:
            soup = bs4.BeautifulSoup(file_bytes, 'html.parser')
            text = soup.get_text(separator=' ')
            urls.extend([a['href'] for a in soup.find_all('a', href=True)])
        except Exception:
            pass
    else:
        # Fallback simplistic extraction for strings
        try:
            text = file_bytes.decode('utf-8', errors='ignore')
        except Exception:
            pass

    metrics["extracted_text"] = text.strip()
    metrics["extracted_urls"] = list(set(urls))

    return metrics
