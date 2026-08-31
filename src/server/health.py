import time

import requests

from utils.config import TESSERACT_CMD, is_configured_secret


def check_llm_health() -> tuple[str, dict]:
    start = time.time()
    try:
        from utils.config import LLM_BASE_URL
        from engines.llm_analyzer import _get_live_config
        live = _get_live_config()
        # Use /v1/models (lightweight GET) instead of a chat completion.
        # A completion ping causes JIT model loading, can trigger 400 errors with Qwen 3
        # thinking mode, and is slow. The models endpoint only checks connectivity
        # and tells us which model is actually loaded right now.
        models_url = LLM_BASE_URL.replace("/v1/chat/completions", "/v1/models")
        response = requests.get(models_url, timeout=5)
        latency = int((time.time() - start) * 1000)
        if response.status_code != 200:
            return "degraded", {"error": "models_endpoint_failed", "status_code": response.status_code}
        loaded = [m.get("id", "") for m in response.json().get("data", [])]
        if live["model"] in loaded:
            return "online", {"latency_ms": latency, "model": live["model"], "loaded_models": loaded}
        # LM Studio is reachable but expected model not loaded yet
        return "degraded", {
            "error": "expected_model_not_loaded",
            "expected": live["model"],
            "loaded_models": loaded,
            "latency_ms": latency,
        }
    except requests.exceptions.Timeout:
        return "degraded", {"error": "connection_timeout", "latency_ms": int((time.time() - start) * 1000)}
    except Exception as exc:
        return "offline", {"error": str(exc)}






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
