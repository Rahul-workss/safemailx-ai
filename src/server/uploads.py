from io import BytesIO
import tempfile
import zipfile
from pathlib import Path

from docx import Document

from utils.content_processor import clean_extracted_text
from utils.ocr_engine import extract_text_from_image


IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff", ".tif"}
TEXT_EXTENSIONS = {".txt", ".eml", ".html", ".htm"}
PDF_EXTENSIONS = {".pdf"}
OFFICE_EXTENSIONS = {".docx", ".doc", ".docm", ".xlsx", ".xls", ".xlsm", ".pptx", ".ppt", ".pptm"}
SUPPORTED_UPLOAD_EXTENSIONS = IMAGE_EXTENSIONS | TEXT_EXTENSIONS | PDF_EXTENSIONS | OFFICE_EXTENSIONS


def validate_upload_bytes(filename: str, file_bytes: bytes) -> None:
    """Reject path tricks and obvious archive bombs before parsing user files."""
    if not filename or len(filename) > 255 or "\x00" in filename:
        raise ValueError("Invalid upload filename")
    path_parts = filename.replace("\\", "/").split("/")
    if len(path_parts) != 1 or any(part in {"", ".", ".."} for part in path_parts):
        raise ValueError("Invalid upload filename")

    # Do not pass executable-looking content to document/image parsers even if
    # a caller gives it a harmless extension.
    if file_bytes[:2] == b"MZ":
        raise ValueError("Unsupported executable content")

    if file_bytes[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(BytesIO(file_bytes)) as archive:
                entries = archive.infolist()
                if len(entries) > 1000:
                    raise ValueError("Archive contains too many files")
                total_uncompressed = 0
                for entry in entries:
                    entry_parts = entry.filename.replace("\\", "/").split("/")
                    if entry.filename.startswith(("/", "\\")) or ".." in entry_parts:
                        raise ValueError("Archive contains an unsafe path")
                    total_uncompressed += max(0, entry.file_size)
                    if total_uncompressed > 50 * 1024 * 1024:
                        raise ValueError("Archive expands beyond the safety limit")
                    if entry.compress_size == 0 and entry.file_size > 1024 * 1024:
                        raise ValueError("Archive compression ratio is unsafe")
                    if entry.compress_size and entry.file_size / entry.compress_size > 1000:
                        raise ValueError("Archive compression ratio is unsafe")
        except zipfile.BadZipFile:
            # Existing behavior tolerates malformed office fixtures and lets
            # the extractor return an empty result; only valid archives need
            # the archive-bomb checks above.
            return


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
