# ============================================================
# SafeMail X — QR Code / Quishing Analyzer
# Feature: QR-Code Phishing (Quishing) Detection
# Controlled by: FEATURE_QR_DETECTION_ENABLED env var
# ============================================================
# QR codes are increasingly used by attackers to hide malicious
# URLs from text-based scanners. This module decodes QR codes
# from images using THREE independent decoders:
#
#   1. zxing-cpp   (BEST for dense QR — Aadhaar PVC Version 35-40)
#   2. pyzbar      (good general-purpose fallback)
#   3. OpenCV      (basic but fast)
#
# Decoder chain: try raw image with all 3 → if none succeed,
# apply preprocessing (threshold/CLAHE/upscale) and retry.
#
# Aadhaar PVC card QR fix:
#   PVC cards use BYTE-mode QR encoding. ZBar/OpenCV return raw
#   binary bytes (not ASCII decimal digits like paper Aadhaar).
#   _normalize_qr_bytes() detects this and converts:
#     binary bytes → int.from_bytes(big) → str(n) → decimal string
# ============================================================

import logging
import os
from typing import Optional

logger = logging.getLogger("QR_ANALYZER")

# --- zxing-cpp decoder (BEST for dense QR codes) ---
try:
    import zxingcpp
    ZXING_AVAILABLE = True
except ImportError:
    ZXING_AVAILABLE = False
    logger.warning("[QR] zxing-cpp not available. Dense QR decoding may fail.")

# --- OpenCV QR decoder ---
try:
    import cv2
    import numpy as np
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False
    logger.warning("[QR] opencv-python not available. OpenCV QR decoder disabled.")

# --- pyzbar decoder (supplementary) ---
try:
    from pyzbar.pyzbar import decode as zbar_decode
    from PIL import Image as PilImage
    ZBAR_AVAILABLE = True
except ImportError:
    ZBAR_AVAILABLE = False
    logger.debug("[QR] pyzbar not installed.")


def _normalize_qr_bytes(raw: bytes, qr_type: str = "QRCODE") -> str:
    """
    Normalize raw QR payload bytes into a consistent string.

    QR encoding modes:
      NUMERIC (paper/e-Aadhaar): bytes are ASCII digit chars → UTF-8 decode OK
      BYTE    (PVC Aadhaar):     bytes are raw gzip binary  → must convert to decimal
      TEXT    (URLs/UPI):        bytes are ASCII             → UTF-8 decode OK
    """
    if not raw:
        return ""

    # Try UTF-8 first — works for text, URLs, UPI, and NUMERIC-mode Aadhaar
    try:
        decoded = raw.decode("utf-8")
        return decoded.strip()
    except UnicodeDecodeError:
        pass

    # Binary payload (PVC Aadhaar BYTE mode)
    # Convert raw bytes → big-endian int → decimal string
    # This gives the same format as NUMERIC mode output
    try:
        n = int.from_bytes(raw, byteorder="big")
        decimal_str = str(n)
        if len(decimal_str) >= 50:
            logger.debug(
                "[QR] BYTE-mode binary → decimal (%d digits) — likely Aadhaar PVC",
                len(decimal_str),
            )
        return decimal_str
    except Exception as exc:
        logger.debug("[QR] Binary→decimal failed: %s", exc)
        return raw.decode("utf-8", errors="replace").strip()


def _try_zxing(img_bgr) -> set[str]:
    """Decode using zxing-cpp (best for dense/Version-40 QR like Aadhaar PVC).

    zxing-cpp distinguishes between content types:
      ContentType.Text   → .text is the decoded string (URLs, UPI, NUMERIC Aadhaar)
      ContentType.Binary → .bytes is raw compressed data (PVC Aadhaar BYTE-mode)
    """
    found: set[str] = set()
    if not ZXING_AVAILABLE or img_bgr is None:
        return found
    try:
        results = zxingcpp.read_barcodes(img_bgr)
        for r in results:
            # Check if this is binary content (PVC Aadhaar BYTE-mode QR)
            is_binary = (
                hasattr(r, 'content_type') and
                r.content_type == zxingcpp.ContentType.Binary
            )

            if is_binary:
                # For BYTE-mode: .bytes has the raw compressed data
                # Convert to decimal string (same as NUMERIC mode output)
                raw = r.bytes
                if raw:
                    normalized = _normalize_qr_bytes(bytes(raw))
                    if normalized:
                        found.add(normalized)
                        logger.debug("[QR] zxing-cpp decoded BINARY QR (%d bytes)", len(raw))
            else:
                # For text content: .text is the decoded string
                text = r.text
                if text and text.strip():
                    found.add(text.strip())

    except Exception as exc:
        logger.debug("[QR] zxing-cpp decode error: %s", exc)
    return found


def _try_opencv(img_bgr) -> set[str]:
    """Decode using OpenCV QRCodeDetector."""
    found: set[str] = set()
    if not CV2_AVAILABLE or img_bgr is None:
        return found
    try:
        detector = cv2.QRCodeDetector()
        retval, decoded_info, _pts, _straight = detector.detectAndDecodeMulti(img_bgr)
        if retval and decoded_info:
            for text in decoded_info:
                if text and text.strip():
                    found.add(text.strip())
    except Exception as exc:
        logger.debug("[QR] OpenCV decode error: %s", exc)
    return found


def _try_pyzbar(img_bgr) -> set[str]:
    """Decode using pyzbar/ZBar."""
    found: set[str] = set()
    if not ZBAR_AVAILABLE or img_bgr is None:
        return found
    try:
        if CV2_AVAILABLE:
            rgb = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2RGB)
            pil_img = PilImage.fromarray(rgb)
        else:
            pil_img = PilImage.fromarray(img_bgr)
        results = zbar_decode(pil_img)
        for r in results:
            payload = _normalize_qr_bytes(r.data, r.type)
            if payload:
                found.add(payload)
    except Exception as exc:
        logger.debug("[QR] pyzbar decode error: %s", exc)
    return found


def _try_all_decoders(img_bgr) -> set[str]:
    """Try all three decoders on a single image. Returns union of results."""
    found: set[str] = set()

    # 1. zxing-cpp (highest success rate for dense QR)
    found.update(_try_zxing(img_bgr))
    if found:
        return found

    # 2. pyzbar (good general-purpose)
    found.update(_try_pyzbar(img_bgr))
    if found:
        return found

    # 3. OpenCV (basic fallback)
    found.update(_try_opencv(img_bgr))

    return found


def _preprocess_strategies(gray):
    """
    Generate preprocessed images targeting different failure modes.
    Each is a BGR image ready for _try_all_decoders().
    """
    if not CV2_AVAILABLE:
        return []

    strategies = []
    h, w = gray.shape[:2]

    # 1. Adaptive Gaussian threshold (handles uneven lighting / PVC glare)
    adapt = cv2.adaptiveThreshold(
        gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
    )
    strategies.append(cv2.cvtColor(adapt, cv2.COLOR_GRAY2BGR))

    # 2. CLAHE + Otsu (boosts low-contrast prints)
    clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
    enhanced = clahe.apply(gray)
    _, otsu_clahe = cv2.threshold(enhanced, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    strategies.append(cv2.cvtColor(otsu_clahe, cv2.COLOR_GRAY2BGR))

    # 3. Bilateral filter + Otsu (smooths noise, preserves edges)
    bilateral = cv2.bilateralFilter(gray, 9, 75, 75)
    _, otsu_bi = cv2.threshold(bilateral, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    strategies.append(cv2.cvtColor(otsu_bi, cv2.COLOR_GRAY2BGR))

    # 4. Sharpen + adaptive threshold (slightly blurry captures)
    kernel_sharpen = np.array([[-1, -1, -1], [-1, 9, -1], [-1, -1, -1]])
    sharpened = cv2.filter2D(gray, -1, kernel_sharpen)
    adapt_sharp = cv2.adaptiveThreshold(
        sharpened, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
    )
    strategies.append(cv2.cvtColor(adapt_sharp, cv2.COLOR_GRAY2BGR))

    # 5. 2× upscale + adaptive (QR is small in frame)
    up2 = cv2.resize(gray, (w * 2, h * 2), interpolation=cv2.INTER_CUBIC)
    adapt_up2 = cv2.adaptiveThreshold(
        up2, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
    )
    strategies.append(cv2.cvtColor(adapt_up2, cv2.COLOR_GRAY2BGR))

    # 6. 2× upscale raw (no thresholding — let the decoder use its own binarizer)
    up2_raw = cv2.resize(gray, (w * 2, h * 2), interpolation=cv2.INTER_CUBIC)
    strategies.append(cv2.cvtColor(up2_raw, cv2.COLOR_GRAY2BGR))

    # 7. Median blur + adaptive threshold (removes Moiré from screen captures)
    # When scanning a QR displayed on a laptop/phone screen, the pixel grid
    # creates interference patterns. Median blur suppresses this.
    median = cv2.medianBlur(gray, 3)
    adapt_median = cv2.adaptiveThreshold(
        median, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
    )
    strategies.append(cv2.cvtColor(adapt_median, cv2.COLOR_GRAY2BGR))

    return strategies


def decode_qr_codes(image_path: str) -> list[str]:
    """
    Decode all QR codes found in an image file.

    Uses three independent decoders (zxing-cpp, pyzbar, OpenCV) with
    multi-strategy preprocessing for challenging real-world conditions
    (PVC card glare, low contrast, small QR, blurry captures).

    Returns a list of decoded payload strings. Never raises.
    """
    found: set[str] = set()

    if not os.path.isfile(image_path):
        return []

    # ── Cap image size to prevent OOM on Render free tier (512MB RAM) ────────
    # Phone cameras take 12-48MP photos. 3x upscale on a 48MP image =
    # 432MP = ~1.3GB BGR → instant OOM crash → HTTP 502.
    # Cap to 2000px longest edge before any processing.
    MAX_DIM = 2000

    def _cap_size(img_bgr):
        h, w = img_bgr.shape[:2]
        if max(h, w) <= MAX_DIM:
            return img_bgr
        scale = MAX_DIM / max(h, w)
        new_w, new_h = int(w * scale), int(h * scale)
        return cv2.resize(img_bgr, (new_w, new_h), interpolation=cv2.INTER_AREA)

    # ── Phase 1: Raw image — try all decoders ────────────────────────────────
    if CV2_AVAILABLE:
        try:
            img = cv2.imread(image_path)
            if img is not None:
                found.update(_try_all_decoders(img))
        except Exception as exc:
            logger.debug("[QR] Raw decode error: %s", exc)

    # pyzbar directly from PIL (if OpenCV not available)
    if not found and ZBAR_AVAILABLE and not CV2_AVAILABLE:
        try:
            pil_img = PilImage.open(image_path)
            for r in zbar_decode(pil_img):
                payload = _normalize_qr_bytes(r.data, r.type)
                if payload:
                    found.add(payload)
        except Exception as exc:
            logger.debug("[QR] PIL+pyzbar error: %s", exc)

    if found:
        logger.debug("[QR] Decoded from raw image: %d payloads", len(found))
        return list(found)

    # ── Phase 2: Preprocessing pipeline (only if raw failed) ─────────────────
    # Cap image size BEFORE preprocessing to keep memory safe
    if CV2_AVAILABLE:
        try:
            img = cv2.imread(image_path)
            if img is not None:
                img = _cap_size(img)
                gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                for i, processed in enumerate(_preprocess_strategies(gray)):
                    results = _try_all_decoders(processed)
                    if results:
                        logger.info("[QR] Decoded with strategy #%d: %d payloads", i, len(results))
                        found.update(results)
                        break  # Stop at first success
        except Exception as exc:
            logger.debug("[QR] Preprocessing error: %s", exc)

    if found:
        return list(found)

    logger.debug("[QR] No QR codes found in %s after all strategies", image_path)
    return []


def analyze_qr_payload(image_path: str) -> dict:
    """
    Analyze an image for QR codes. Returns structured findings.

    Return schema:
      qr_codes_found       int
      qr_decoded_payloads   list[str]
      qr_urls              list[str]
      has_qr_url           bool
    """
    try:
        decoded = decode_qr_codes(image_path)
    except Exception as exc:
        logger.warning("[QR] analyze_qr_payload failed: %s", exc)
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
    Convenience wrapper: writes bytes to temp file, decodes, cleans up.
    Returns same schema as analyze_qr_payload(). Never raises.
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
