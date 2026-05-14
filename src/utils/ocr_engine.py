import cv2
import pytesseract
import os
import re

from utils.config import TESSERACT_CMD, debug_log


if TESSERACT_CMD:
    pytesseract.pytesseract.tesseract_cmd = TESSERACT_CMD

_TESSERACT_READY = None


def _tesseract_available():
    global _TESSERACT_READY

    if _TESSERACT_READY is not None:
        return _TESSERACT_READY

    try:
        pytesseract.get_tesseract_version()
        _TESSERACT_READY = True
    except pytesseract.TesseractNotFoundError:
        configured = TESSERACT_CMD or "PATH"
        print(
            "[OCR SETUP] Tesseract is not available. Install Tesseract OCR "
            "or set TESSERACT_CMD in .env. Current setting: "
            f"{configured}"
        )
        _TESSERACT_READY = False
    except Exception as e:
        print(f"[OCR SETUP] Could not validate Tesseract OCR: {e}")
        _TESSERACT_READY = False

    return _TESSERACT_READY


def _clean_ocr_candidate(text):
    if not text:
        return ""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[^\S\n]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _ocr_score(text, confidences):
    cleaned = _clean_ocr_candidate(text)
    if not cleaned:
        return -1

    signal_chars = len(re.findall(r"[A-Za-z0-9/@:._%+-]", cleaned))
    replacement_penalty = cleaned.count("|") + cleaned.count("~") + cleaned.count("`")

    numeric_conf = []
    for conf in confidences:
        try:
            value = float(conf)
        except (TypeError, ValueError):
            continue
        if value >= 0:
            numeric_conf.append(value)

    avg_conf = sum(numeric_conf) / len(numeric_conf) if numeric_conf else 0
    useful_lines = len([line for line in cleaned.splitlines() if re.search(r"[A-Za-z0-9]", line)])

    return signal_chars + (avg_conf * 2.0) + (useful_lines * 8) - (replacement_penalty * 5)


def _image_variants(gray):
    enlarged = cv2.resize(gray, None, fx=2.5, fy=2.5, interpolation=cv2.INTER_CUBIC)
    clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8)).apply(enlarged)
    _, otsu = cv2.threshold(clahe, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    inverted = cv2.bitwise_not(otsu)
    adaptive = cv2.adaptiveThreshold(
        clahe,
        255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY,
        31,
        11,
    )

    return [
        ("grayscale_upscaled", enlarged),
        ("contrast", clahe),
        ("otsu", otsu),
        ("inverted", inverted),
        ("adaptive", adaptive),
    ]


def _run_tesseract(image, psm):
    config = f"--oem 3 --psm {psm}"
    text = pytesseract.image_to_string(image, config=config)
    data = pytesseract.image_to_data(image, config=config, output_type=pytesseract.Output.DICT)
    return text, data.get("conf", [])


def extract_text_from_image(image_path):

    try:
        if not _tesseract_available():
            return ""

        if not os.path.exists(image_path):
            return ""

        img = cv2.imread(image_path)

        if img is None:
            return ""

        height, width = img.shape[:2]

        if width < 120 or height < 60:
            return ""

        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

        best_text = ""
        best_score = -1
        best_variant = "none"

        for variant_name, variant in _image_variants(gray):
            for psm in (3, 6, 11):
                try:
                    text, confidences = _run_tesseract(variant, psm)
                except Exception as e:
                    debug_log(f"[OCR DEBUG] Variant {variant_name}/psm{psm} failed: {e}")
                    continue

                score = _ocr_score(text, confidences)
                if score > best_score:
                    best_score = score
                    best_text = text
                    best_variant = f"{variant_name}/psm{psm}"

        text = _clean_ocr_candidate(best_text)
        debug_log(f"[OCR DEBUG] Best variant={best_variant} score={best_score:.2f}\n{text}")
        
        return text

    except Exception as e:
        print(f"[OCR ERROR] {e}")
        return ""
