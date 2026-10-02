"""
SafeMail X — Aadhaar Secure QR Decoder
======================================
Decodes the UIDAI Aadhaar Secure QR (post-2019 format) from a raw decimal string.

Algorithm based on pyaadhaar (tanmoysrt/pyaadhaar) and the UIDAI QR Code
User Manual v3 (2019). Uses ONLY Python stdlib — no third-party packages.

Secure QR Format:
  1. QR scanner returns a very large decimal number (string)
  2. Convert to bytes:  int(decimal).to_bytes(ceil(bits/8), 'big')
  3. Decompress:  zlib.decompress(bytes, 16 + zlib.MAX_WBITS)  ← GZIP
  4. Split result by byte 0xFF (value 255) → fields
  5. Decode each field as ISO-8859-1 (Latin-1), NOT UTF-8

Field order (0-indexed):
  [0]  email_mobile_status  — "0"=none, "1"=email, "2"=mobile, "3"=both
  [1]  referenceid          — first 4 chars = last 4 digits of Aadhaar
  [2]  name
  [3]  dob                  — "DD-MM-YYYY" or "YYYY"
  [4]  gender               — "M" / "F" / "T"
  [5]  careof
  [6]  district
  [7]  landmark
  [8]  house
  [9]  location             (locality)
  [10] pincode
  [11] postoffice
  [12] state
  [13] street
  [14] subdistrict
  [15] vtc                  (village/town/city)
  [16+] photo bytes (JPEG or JPEG-2000, after all text fields)

Optional Vx format (newer PVC cards):
  If decompressed bytes start with "V" + digit (e.g., "V3"), insert a
  "version" field at [0] and append "last_4_digits_mobile_no" at the end.
"""

import zlib
import base64
import logging
import math
import io
from typing import Optional

logger = logging.getLogger("AADHAAR_DECODER")

FIELD_NAMES = [
    "email_mobile_status", "referenceid", "name", "dob", "gender",
    "careof", "district", "landmark", "house", "location",
    "pincode", "postoffice", "state", "street", "subdistrict", "vtc",
]


def _convert_photo_to_jpeg_base64(photo_bytes: bytes) -> Optional[str]:
    """
    Convert Aadhaar photo bytes (JPEG-2000 / JP2 format) to standard JPEG
    base64 that React Native's Image component can display.

    Aadhaar Secure QR stores the face photo as JPEG-2000 (ISO 15444-1),
    which most mobile image components cannot render natively. Pillow with
    the OpenJPEG backend (libopenjp2 system library) can decode JP2 images.

    If Pillow cannot decode the bytes (e.g., missing OpenJPEG on the server,
    or the photo is actually a regular JPEG), this function falls back to
    returning the raw bytes as base64 — the frontend will try to display it
    as-is and may still succeed for regular JPEG photos.
    """
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(photo_bytes))
        buf = io.BytesIO()
        # Convert to RGB (JP2 may be in other colour spaces like YCbCr)
        img.convert("RGB").save(buf, format="JPEG", quality=90)
        return base64.b64encode(buf.getvalue()).decode("ascii")
    except Exception as e:
        logger.debug("[AADHAAR] JP2→JPEG conversion failed (%s), returning raw bytes", e)
        # Fall back: return raw bytes as base64
        # (regular JPEG photos will still display in React Native)
        try:
            return base64.b64encode(photo_bytes).decode("ascii")
        except Exception:
            return None


def _decimal_to_bytes(decimal_str: str) -> bytes:
    """Convert large decimal string to big-endian bytes (strip leading zeros)."""
    n = int(decimal_str)
    if n == 0:
        return b'\x00'
    byte_length = math.ceil(n.bit_length() / 8)
    return n.to_bytes(byte_length, 'big')


def decode_aadhaar_secure_qr(decimal_str: str) -> dict:
    """
    Decode an Aadhaar Secure QR code from its decimal string payload.

    Args:
        decimal_str: The raw string returned by a QR code scanner
                     (must be all digits, typically 1000–8000 chars)

    Returns:
        dict with keys: success, name, dob, gender, uid_last4, address,
        email_linked, mobile_linked, photo_base64 (optional), error (on failure)
    """
    decimal_str = decimal_str.strip()

    if not decimal_str.isdigit():
        return {"success": False, "error": "Not a numeric Aadhaar QR payload"}

    # Step 1: Decimal → bytes
    try:
        raw_bytes = _decimal_to_bytes(decimal_str)
    except Exception as e:
        logger.error("[AADHAAR] decimal_to_bytes failed: %s", e)
        return {"success": False, "error": f"Conversion error: {e}"}

    # Step 2: GZIP decompress
    # Python: zlib.decompress(data, 16 + zlib.MAX_WBITS)
    # The gzip decompressor automatically stops at the gzip end-of-stream marker,
    # so appended signature bytes (last 256 bytes) are automatically ignored.
    try:
        decompressed = zlib.decompress(raw_bytes, 16 + zlib.MAX_WBITS)
    except zlib.error as e:
        # Fallback: try plain zlib (older format)
        try:
            decompressed = zlib.decompress(raw_bytes)
        except zlib.error:
            logger.error("[AADHAAR] decompression failed: %s", e)
            return {"success": False, "error": "Decompression failed — QR may be corrupted or unsupported format"}

    # Step 3: Find all 0xFF delimiter positions
    delimiters = [-1]
    for i, byte in enumerate(decompressed):
        if byte == 255:  # 0xFF
            delimiters.append(i)

    if len(delimiters) < 2:
        return {"success": False, "error": "No field delimiters found — unexpected QR format"}

    # Step 4: Check for Vx version marker (newer PVC cards)
    field_names = list(FIELD_NAMES)
    first_field = decompressed[0:delimiters[1]].decode("iso-8859-1", errors="ignore")
    has_version = len(first_field) >= 2 and first_field[0] == 'V' and first_field[1].isdigit()
    if has_version:
        field_names.insert(0, "version")
        field_names.append("last_4_digits_mobile_no")

    # Step 5: Extract text fields (ISO-8859-1)
    data: dict = {}
    for i, field_name in enumerate(field_names):
        if i + 1 >= len(delimiters):
            data[field_name] = ""
            continue
        start = delimiters[i] + 1
        end = delimiters[i + 1]
        data[field_name] = decompressed[start:end].decode("iso-8859-1", errors="ignore")

    # Step 6: Parse email/mobile status
    try:
        status = int(data.get("email_mobile_status", "0") or "0")
    except ValueError:
        status = 0
    email_linked = status in (1, 3)
    mobile_linked = status in (2, 3)

    uid_last4 = (data.get("referenceid", "") or "")[:4]

    # Step 7: Extract photo (bytes after last text field delimiter)
    # The photo in Aadhaar Secure QR is stored as JPEG-2000 (JP2 format),
    # which React Native's Image component cannot display natively.
    # We use Pillow to convert JP2 → standard JPEG before sending to the app.
    photo_base64: Optional[str] = None
    num_text_fields = len(field_names)
    if num_text_fields < len(delimiters):
        photo_start = delimiters[num_text_fields] + 1
        photo_bytes = decompressed[photo_start:]
        if len(photo_bytes) > 100:
            photo_base64 = _convert_photo_to_jpeg_base64(photo_bytes)

    gender_raw = data.get("gender", "")
    gender = "Male" if gender_raw == "M" else "Female" if gender_raw == "F" else "Transgender" if gender_raw == "T" else gender_raw

    result = {
        "success": True,
        "name": data.get("name", ""),
        "dob": data.get("dob", ""),
        "gender": gender,
        "uid_last4": uid_last4,
        "address": {
            "careOf": data.get("careof", ""),
            "district": data.get("district", ""),
            "house": data.get("house", ""),
            "locality": data.get("location", ""),
            "pincode": data.get("pincode", ""),
            "state": data.get("state", ""),
            "street": data.get("street", ""),
            "vtc": data.get("vtc", ""),
        },
        "email_linked": email_linked,
        "mobile_linked": mobile_linked,
        "format": "SECURE_QR",
        "signature_valid": None,  # Not verified (UIDAI key not configured)
    }
    if photo_base64:
        result["photo_base64"] = photo_base64

    return result
