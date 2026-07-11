# ============================================================
# SafeMail X — QR Code / Quishing Analyzer
# Feature: QR-Code Phishing (Quishing) Detection
# Controlled by: FEATURE_QR_DETECTION_ENABLED env var
# ============================================================
# QR codes are increasingly used by attackers to hide malicious
# URLs from text-based scanners. This module decodes QR codes
# from images using two independent decoders (OpenCV + pyzbar)
# and merges the results. Decoded URLs are fed into the existing
# url_analyzer pipeline — no second scoring path is created.
# ============================================================

import logging
import os
from typing import Optional

logger = logging.getLogger("QR_ANALYZER")

# --- OpenCV QR decoder (already a project dependency) ---
try:
    import cv2
    import numpy as np
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False
    logger.warning("[QR] opencv-python not available. OpenCV QR decoder disabled.")

# --- pyzbar decoder (supplementary — catches codes OpenCV misses) ---
try:
    from pyzbar.pyzbar import decode as zbar_decode
    from PIL import Image as PilImage
    ZBAR_AVAILABLE = True
except ImportError:
    ZBAR_AVAILABLE = False
    logger.debug("[QR] pyzbar not installed. Using OpenCV decoder only.")


def decode_qr_codes(image_path: str) -> list[str]:
    """
    Decode all QR codes found in an image file.

    Uses both OpenCV QRCodeDetector and pyzbar (if available) and
    de-duplicates results — each decoder catches codes the other misses
    (low-contrast, rotated, or damaged codes are handled differently
    by each library).

    Returns a list of decoded payload strings. Never raises — returns
    an empty list on any failure so callers stay safe.
    """
    found: set[str] = set()

    if not os.path.isfile(image_path):
        return []

    # -- OpenCV path --
    if CV2_AVAILABLE:
        try:
            img = cv2.imread(image_path)
            if img is not None:
                detector = cv2.QRCodeDetector()
                retval, decoded_info, _points, _straight = detector.detectAndDecodeMulti(img)
                if retval and decoded_info:
                    for text in decoded_info:
                        if text and text.strip():
                            found.add(text.strip())
        except Exception as exc:
            logger.debug("[QR] OpenCV decode error on %s: %s", image_path, exc)

    # -- pyzbar path (fallback / supplement) --
    if ZBAR_AVAILABLE:
        try:
            pil_img = PilImage.open(image_path)
            results = zbar_decode(pil_img)
            for r in results:
                payload = r.data.decode("utf-8", errors="ignore").strip()
                if payload:
                    found.add(payload)
        except Exception as exc:
            logger.debug("[QR] pyzbar decode error on %s: %s", image_path, exc)

    return list(found)


def analyze_qr_payload(image_path: str) -> dict:
    """
    Analyze an image file for embedded QR codes and return a
    structured finding dict for the hybrid engine to consume.

    Return schema (always present, never raises):
      qr_codes_found   int   — total QR codes decoded (URL or non-URL)
      qr_decoded_payloads list[str] — all decoded strings
      qr_urls          list[str] — subset that are http/https URLs
      has_qr_url       bool  — True if at least one URL was found
    """
    try:
        decoded = decode_qr_codes(image_path)
    except Exception as exc:
        logger.warning("[QR] analyze_qr_payload failed for %s: %s", image_path, exc)
        decoded = []

    urls = [
        d for d in decoded
        if d.lower().startswith("http://") or d.lower().startswith("https://")
    ]

    return {
        "qr_codes_found": len(decoded),
        "qr_decoded_payloads": decoded,
        "qr_urls": urls,
        "has_qr_url": len(urls) > 0,
    }


def analyze_qr_from_bytes(image_bytes: bytes, suffix: str = ".png") -> dict:
    """
    Convenience wrapper that writes bytes to a temp file, decodes QR
    codes, then cleans up. Used by attachment_analyzer when there is
    no existing file path (only raw bytes are available).

    Returns the same schema as analyze_qr_payload().
    Never raises.
    """
    import tempfile
    tmp_path: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(image_bytes)
            tmp_path = tmp.name
        return analyze_qr_payload(tmp_path)
    except Exception as exc:
        logger.warning("[QR] analyze_qr_from_bytes error: %s", exc)
        return {
            "qr_codes_found": 0,
            "qr_decoded_payloads": [],
            "qr_urls": [],
            "has_qr_url": False,
        }
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
