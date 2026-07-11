FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr libgl1 libglib2.0-0 nginx curl \
        libzbar0 \
        # Feature 7 (vishing): uncomment 'ffmpeg' below if FEATURE_VISHING_DETECTION_ENABLED=true
        # ffmpeg \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
ENV PYTHONPATH=/app/src

RUN chmod +x /app/start.sh

CMD ["bash", "/app/start.sh"]
