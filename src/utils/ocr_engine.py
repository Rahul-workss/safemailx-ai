import cv2
import pytesseract
import os

# Set Tesseract path for Windows users if it's not in your PATH
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'


def extract_text_from_image(image_path):

    try:

        if not os.path.exists(image_path):
            return ""

        img = cv2.imread(image_path)

        if img is None:
            return ""

        height, width = img.shape[:2]

        if width < 120 or height < 60:
            return ""

        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

        # 1. Upscale by 2.5x using high-quality cubic interpolation. 
        # This solves the issue of Tesseract outputting garbage for tiny fonts.
        gray = cv2.resize(gray, None, fx=2.5, fy=2.5, interpolation=cv2.INTER_CUBIC)

        # 2. Adaptive Contrast Equalization (CLAHE)
        # Bypasses "Dark text on Dark Background" evasion tricks
        clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8,8))
        gray = clahe.apply(gray)
        
        # 3. Aggressive Otsu's Binarization
        # Hard limits pixel domains directly into True Black / True White to mathematically destroy color noise
        _, gray = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        
        # 4. PSM 3 = Fully automatic page segmentation
        config = "--oem 3 --psm 3"
        text = pytesseract.image_to_string(gray, config=config)
        print("OCR extracted text:", text)
        
        return text.strip()

    except Exception as e:
        print(f"OCR Error: {e}")
        return ""