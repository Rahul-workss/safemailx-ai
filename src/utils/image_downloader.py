import requests
import os
from uuid import uuid4
from PIL import Image
from io import BytesIO
import warnings
import base64

# suppress PIL transparency warnings
warnings.filterwarnings("ignore", category=UserWarning, module="PIL")


def download_images(image_urls):

    saved_images = []

    os.makedirs("temp_images", exist_ok=True)

    MAX_IMAGES = 5

    for url in image_urls:

        if len(saved_images) >= MAX_IMAGES:
            break

        try:

            if url.startswith("data:"):
                # Handle images converted to base64 by the frontend
                header, encoded = url.split(",", 1)
                img_data = base64.b64decode(encoded)
                img = Image.open(BytesIO(img_data))

            else:
                if url.lower().endswith((".gif", ".svg", ".ico")):
                    continue

                r = requests.get(url, timeout=5)

                if r.status_code != 200:
                    continue

                img = Image.open(BytesIO(r.content))

            width, height = img.size

            # ignore extreme tiny tracking pixels
            if width < 50 or height < 50:
                continue

            # fix palette transparency images
            if img.mode == "P" or img.mode == "RGBA":
                img = img.convert("RGBA")

            img = img.convert("RGB")

            filename = f"temp_images/{uuid4()}.png"

            img.save(filename, "PNG")

            saved_images.append(filename)

        except Exception:
            continue

    return saved_images