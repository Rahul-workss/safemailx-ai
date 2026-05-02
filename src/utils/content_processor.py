from .ocr_engine import extract_text_from_image
from .config import debug_log


def build_full_email_text(email_body, image_paths=None):
    """
    Combine email body text with OCR extracted text.
    Verbose text dumps are gated behind SAFEMAILX_DEBUG=true.
    """

    combined_text = email_body

    if image_paths:

        for img in image_paths:

            print(f"[OCR] Running OCR on image: {img}")

            ocr_text = extract_text_from_image(img)

            debug_log(f"[OCR DEBUG] OCR text for {img}:\n{ocr_text}")

            combined_text += "\n" + ocr_text

    debug_log(f"[CONTENT DEBUG] Final analysis text:\n{combined_text}")

    return combined_text
