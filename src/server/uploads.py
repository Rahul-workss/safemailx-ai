import tempfile
from pathlib import Path

from docx import Document

from utils.content_processor import clean_extracted_text
from utils.ocr_engine import extract_text_from_image


IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff", ".tif"}
TEXT_EXTENSIONS = {".txt", ".eml", ".html", ".htm"}
PDF_EXTENSIONS = {".pdf"}
OFFICE_EXTENSIONS = {".docx", ".doc", ".docm", ".xlsx", ".xls", ".xlsm", ".pptx", ".ppt", ".pptm"}
SUPPORTED_UPLOAD_EXTENSIONS = IMAGE_EXTENSIONS | TEXT_EXTENSIONS | PDF_EXTENSIONS | OFFICE_EXTENSIONS


def _extract_pdf_text(file_bytes: bytes) -> str:
    try:
        import fitz
    except ImportError:
        return ""

    try:
        with fitz.open(stream=file_bytes, filetype="pdf") as doc:
            return "\n".join(page.get_text() for page in doc)
    except Exception:
        return ""


def _extract_docx_text(file_bytes: bytes) -> str:
    try:
        with tempfile.NamedTemporaryFile(suffix=".docx", delete=True) as tmp:
            tmp.write(file_bytes)
            tmp.flush()
            doc = Document(tmp.name)
            return "\n".join(paragraph.text for paragraph in doc.paragraphs)
    except Exception:
        return ""


def _extract_image_text(file_bytes: bytes, suffix: str) -> str:
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=True) as tmp:
            tmp.write(file_bytes)
            tmp.flush()
            return extract_text_from_image(tmp.name)
    except Exception:
        return ""


def extract_upload_text(filename: str, file_bytes: bytes) -> tuple[str, list[str]]:
    suffix = Path(filename).suffix.lower()
    notes = []

    if suffix in TEXT_EXTENSIONS:
        text = file_bytes.decode("utf-8", errors="ignore")
    elif suffix in PDF_EXTENSIONS:
        text = _extract_pdf_text(file_bytes)
        notes.append("pdf_text_extraction")
    elif suffix in OFFICE_EXTENSIONS:
        text = _extract_docx_text(file_bytes)
        notes.append("office_text_extraction")
    elif suffix in IMAGE_EXTENSIONS:
        text = _extract_image_text(file_bytes, suffix)
        notes.append("image_ocr")
    else:
        text = ""
        notes.append("unsupported_text_extraction")

    return clean_extracted_text(text), notes
