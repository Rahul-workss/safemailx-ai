import requests
import os
from uuid import uuid4
from PIL import Image
from io import BytesIO
import warnings
import base64

from utils.config import TEMP_IMAGES_DIR, debug_log

# suppress PIL transparency warnings
warnings.filterwarnings("ignore", category=UserWarning, module="PIL")


def download_images(image_urls):

    saved_images = []

    os.makedirs(TEMP_IMAGES_DIR, exist_ok=True)

    MAX_IMAGES = 5

    for index, url in enumerate(image_urls, start=1):

        if len(saved_images) >= MAX_IMAGES:
            break

        try:
            source_preview = str(url)[:120]
            debug_log(f"[IMAGE DEBUG] Inspecting image {index}/{len(image_urls)}: {source_preview}")

            if url.startswith("data:"):
                # Handle images converted to base64 by the frontend
                header, encoded = url.split(",", 1)
                img_data = base64.b64decode(encoded)
                img = Image.open(BytesIO(img_data))

            else:
                if url.lower().endswith((".gif", ".svg", ".ico")):
                    debug_log("[IMAGE DEBUG] Skipped unsupported image type.")
                    continue

                r = requests.get(
                    url,
                    timeout=10,
                    headers={
                        "User-Agent": (
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 (KHTML, like Gecko) "
                            "Chrome/124.0 Safari/537.36"
                        )
                    },
                )

                if r.status_code != 200:
                    debug_log(f"[IMAGE DEBUG] Download failed with HTTP {r.status_code}.")
                    continue

                img = Image.open(BytesIO(r.content))

            width, height = img.size
            debug_log(f"[IMAGE DEBUG] Loaded image size: {width}x{height}")

            # ignore extreme tiny tracking pixels
            if width < 50 or height < 50:
                debug_log("[IMAGE DEBUG] Skipped tiny/tracking-sized image.")
                continue

            # fix palette transparency images
            if img.mode == "P" or img.mode == "RGBA":
                img = img.convert("RGBA")

            img = img.convert("RGB")

            filename = str(TEMP_IMAGES_DIR / f"{uuid4()}.png")

            img.save(filename, "PNG")

            saved_images.append(filename)
            debug_log(f"[IMAGE DEBUG] Saved OCR candidate: {filename}")

        except Exception as e:
            debug_log(f"[IMAGE DEBUG] Failed to process image {index}: {e}")
            continue

    debug_log(f"[IMAGE DEBUG] Saved {len(saved_images)} OCR candidate image(s).")
    return saved_images
