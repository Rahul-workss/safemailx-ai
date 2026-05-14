import time

import requests

from utils.config import LLM_BASE_URL, TESSERACT_CMD, is_configured_secret


def check_llm_health() -> tuple[str, dict]:
    start = time.time()
    try:
        base = LLM_BASE_URL.rsplit("/v1/", 1)[0]
        response = requests.get(f"{base}/v1/models", timeout=3)
        if response.status_code < 500:
            return "online", {"latency_ms": int((time.time() - start) * 1000)}
    except Exception as exc:
        return "offline", {"error": str(exc)}
    return "degraded", {"status_code": response.status_code}


def check_ocr_health() -> str:
    if TESSERACT_CMD and is_configured_secret(TESSERACT_CMD):
        return "configured"
    return "unknown"


def build_health(redis_status: str = "unknown", database_status: str = "online") -> dict:
    llm_status, _ = check_llm_health()
    return {
        "api": "online",
        "database": database_status,
        "redis": redis_status,
        "ocr": check_ocr_health(),
        "llm": llm_status,
        "gmail_watcher": "configured",
    }
