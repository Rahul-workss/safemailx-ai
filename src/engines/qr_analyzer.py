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
#
# Preprocessing pipeline (for dense/PVC-card QR codes):
#   Raw image → grayscale → multiple strategies in parallel →
#   each tried with OpenCV + pyzbar → first success wins
#   Strategies: raw | adaptive threshold | CLAHE+Otsu |
#               bilateral filter+Otsu | upscale 2x | upscale 3x
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


def _try_decode_image(img_bgr) -> list[str]:
    """
    Try OpenCV + pyzbar on a single (already-preprocessed) BGR image.
    Returns list of decoded payload strings (may be empty).
    """
    found: set[str] = set()

    if CV2_AVAILABLE and img_bgr is not None:
        try:
            detector = cv2.QRCodeDetector()
            retval, decoded_info, _pts, _straight = detector.detectAndDecodeMulti(img_bgr)
            if retval and decoded_info:
                for text in decoded_info:
                    if text and text.strip():
                        found.add(text.strip())
        except Exception as exc:
            logger.debug("[QR] OpenCV decode attempt failed: %s", exc)

    if ZBAR_AVAILABLE and img_bgr is not None:
        try:
            # pyzbar expects a PIL image or numpy array
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
            logger.debug("[QR] pyzbar decode attempt failed: %s", exc)

    return list(found)


def _normalize_qr_bytes(raw: bytes, qr_type: str = "QRCODE") -> str:
    """
    Normalize raw pyzbar bytes into a consistent string payload.

    QR encoding modes produce different raw bytes:
    ─────────────────────────────────────────────
    NUMERIC mode  (paper/digital Aadhaar e-Aadhaar):
        ZBar returns the decimal digits as ASCII bytes → b"12345..."
        → Decode as UTF-8 → plain decimal string
        → Our aadhaar_decoder consumes this directly

    BYTE mode  (PVC Aadhaar card):
        ZBar returns the raw compressed binary data directly (not ASCII).
        → .decode("utf-8", errors="ignore") would silently drop bytes
          causing the detector to miss the Aadhaar pattern or send garbage
        → Must convert big-endian bytes → Python int → decimal string
          (identical to NUMERIC mode output, so aadhaar_decoder works)

    Other QR types (URLs, UPI, text):
        → Always ASCII-safe → UTF-8 decode is fine
    """
    if not raw:
        return ""

    # Check if all bytes are printable ASCII (NUMERIC/ALPHANUM/text mode)
    # Aadhaar NUMERIC mode: all bytes are ASCII digit chars (0x30-0x39)
    try:
        decoded = raw.decode("utf-8")
        # If it decoded cleanly and is a valid decimal string, keep as-is
        # (this is the paper/e-Aadhaar path)
        return decoded.strip()
    except UnicodeDecodeError:
        pass

    # Binary payload (PVC Aadhaar BYTE mode) — convert bytes → decimal string
    # This is mathematically equivalent to reading the same QR in NUMERIC mode:
    # the QR data matrix stores the same compressed binary either way.
    try:
        n = int.from_bytes(raw, byteorder="big")
        decimal_str = str(n)
        # Sanity check: Aadhaar payloads are always very long numbers (>50 digits)
        if len(decimal_str) >= 50:
            logger.debug(
                "[QR] Binary BYTE-mode QR converted to decimal (%d digits) — likely Aadhaar PVC",
                len(decimal_str),
            )
        return decimal_str
    except Exception as exc:
        logger.debug("[QR] Binary→decimal conversion failed: %s", exc)
        # Last resort: lossy UTF-8 for non-Aadhaar binary payloads
        return raw.decode("utf-8", errors="replace").strip()


def _preprocess_strategies(gray):
    """
    Generate multiple preprocessed grayscale images from a single gray image.
    Each strategy targets a different failure mode (glare, low contrast, noise).
    Returns list of BGR images ready for _try_decode_image().
    """
    strategies = []
    h, w = gray.shape[:2]

    # 1. Raw (no preprocessing)
    strategies.append(cv2.cvtColor(gray, cv2.COLOR_GRAY2BGR))

    # 2. Adaptive Gaussian threshold — best for glare/uneven lighting on PVC
    #    Handles bright hot-spots by normalising each local region independently
    adapt = cv2.adaptiveThreshold(
        gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
    )
    strategies.append(cv2.cvtColor(adapt, cv2.COLOR_GRAY2BGR))

    # 3. CLAHE + Otsu — boosts local contrast (good for faded/low-contrast prints)
    clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
    enhanced = clahe.apply(gray)
    _, otsu_clahe = cv2.threshold(enhanced, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    strategies.append(cv2.cvtColor(otsu_clahe, cv2.COLOR_GRAY2BGR))

    # 4. Bilateral filter + Otsu — smooths noise while preserving QR edges
    bilateral = cv2.bilateralFilter(gray, 9, 75, 75)
    _, otsu_bi = cv2.threshold(bilateral, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    strategies.append(cv2.cvtColor(otsu_bi, cv2.COLOR_GRAY2BGR))

    # 5. Sharpen + adaptive threshold — recovers detail from slightly-blurry captures
    kernel_sharpen = np.array([[-1, -1, -1], [-1, 9, -1], [-1, -1, -1]])
    sharpened = cv2.filter2D(gray, -1, kernel_sharpen)
    adapt_sharp = cv2.adaptiveThreshold(
        sharpened, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
    )
    strategies.append(cv2.cvtColor(adapt_sharp, cv2.COLOR_GRAY2BGR))

    # 6. 2× upscale + adaptive threshold
    #    Helps when QR is small relative to image (PVC card captured from distance)
    up2 = cv2.resize(gray, (w * 2, h * 2), interpolation=cv2.INTER_CUBIC)
    adapt_up2 = cv2.adaptiveThreshold(
        up2, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
    )
    strategies.append(cv2.cvtColor(adapt_up2, cv2.COLOR_GRAY2BGR))

    # 7. 3× upscale + CLAHE + Otsu
    #    Extreme upscale for very small QR codes that fill <15% of the frame
    up3 = cv2.resize(gray, (w * 3, h * 3), interpolation=cv2.INTER_CUBIC)
    clahe3 = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    up3_enh = clahe3.apply(up3)
    _, otsu_up3 = cv2.threshold(up3_enh, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    strategies.append(cv2.cvtColor(otsu_up3, cv2.COLOR_GRAY2BGR))

    return strategies


def decode_qr_codes(image_path: str) -> list[str]:
    """
    Decode all QR codes found in an image file.

    Uses both OpenCV QRCodeDetector and pyzbar (if available) and
    de-duplicates results. Applies multiple preprocessing strategies
    to handle challenging real-world conditions:
      - PVC card glare/specular reflections   → adaptive threshold
      - Low-contrast plastic prints           → CLAHE + Otsu
      - Slightly blurry captures              → bilateral filter
      - Small QR relative to image size       → 2-3× upscaling

    Returns a list of decoded payload strings. Never raises — returns
    an empty list on any failure so callers stay safe.
    """
    found: set[str] = set()

    if not os.path.isfile(image_path):
        return []

    # ── Strategy 0: plain OpenCV + pyzbar on original (fastest, try first) ───
    if CV2_AVAILABLE:
        try:
            img = cv2.imread(image_path)
            if img is not None:
                results = _try_decode_image(img)
                found.update(results)
        except Exception as exc:
            logger.debug("[QR] Raw decode error on %s: %s", image_path, exc)

    if not found and ZBAR_AVAILABLE and not CV2_AVAILABLE:
        # OpenCV not available — try raw pyzbar directly
        try:
            pil_img = PilImage.open(image_path)
            for r in zbar_decode(pil_img):
                payload = r.data.decode("utf-8", errors="ignore").strip()
                if payload:
                    found.add(payload)
        except Exception as exc:
            logger.debug("[QR] Raw pyzbar error on %s: %s", image_path, exc)

    # ── Preprocessing strategies (only if raw decode failed) ─────────────────
    if not found and CV2_AVAILABLE:
        try:
            img = cv2.imread(image_path)
            if img is not None:
                gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                for i, processed in enumerate(_preprocess_strategies(gray)):
                    results = _try_decode_image(processed)
                    if results:
                        logger.debug("[QR] Decoded with preprocessing strategy %d on %s", i, image_path)
                        found.update(results)
                        break  # Stop at first successful strategy
        except Exception as exc:
            logger.debug("[QR] Preprocessing decode error on %s: %s", image_path, exc)

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
