import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

import pytesseract
from PIL import Image, ImageDraw

from utils.ocr_engine import extract_text_from_image


class OcrEngineTests(unittest.TestCase):
    def test_ocr_smoke_when_tesseract_is_available(self):
        try:
            pytesseract.get_tesseract_version()
        except pytesseract.TesseractNotFoundError as exc:
            self.skipTest(f"Tesseract is not configured: {exc}")

        image = Image.new("RGB", (640, 180), "white")
        draw = ImageDraw.Draw(image)
        draw.text((30, 60), "Security Scan Report 37/100", fill="black")

        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            path = tmp.name

        try:
            image.save(path)
            text = extract_text_from_image(path)
        finally:
            if os.path.exists(path):
                os.remove(path)

        self.assertIn("Security", text)
        self.assertIn("Report", text)


if __name__ == "__main__":
    unittest.main()
