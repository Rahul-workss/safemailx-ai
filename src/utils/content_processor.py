from .ocr_engine import extract_text_from_image


def build_full_email_text(email_body, image_paths=None):
    """
    Combine email body text with OCR extracted text.
    Also prints extracted text for debugging.
    """

    print("\n==============================")
    print("EMAIL BODY TEXT:")
    print("==============================")
    print(email_body)

    combined_text = email_body

    if image_paths:

        for img in image_paths:

            print("\nRunning OCR on image:", img)

            ocr_text = extract_text_from_image(img)

            print("\nOCR EXTRACTED TEXT:")
            print("--------------------")
            print(ocr_text)

            combined_text += "\n" + ocr_text

    print("\n==============================")
    print("FINAL TEXT USED FOR ANALYSIS:")
    print("==============================")
    print(combined_text)

    return combined_text