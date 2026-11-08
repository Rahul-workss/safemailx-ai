import time

import requests

from utils.config import TESSERACT_CMD, is_configured_secret


def check_llm_health() -> tuple[str, dict]:
    """
    Provider-aware LLM health check.

    - cloudflare: validate API key + model are configured; skip network call
      (Cloudflare Workers AI has no lightweight probe endpoint and billing
      only triggers on actual inference calls).
    - lmstudio / local: check /v1/models as before.
    """
    start = time.time()
    try:
        from utils.config import LLM_BASE_URL, LLM_API_KEY, LLM_PROVIDER
        from engines.llm_analyzer import _get_live_config
        live = _get_live_config()

        provider = LLM_PROVIDER.lower()

        # ── Cloud providers: config-only check ───────────────────────────────
        # Cloudflare Workers AI (and similar) don't expose a cheap probe
        # endpoint.  We confirm the credentials are set and return "online"
        # so the health page doesn't mislead operators.
        if provider in {"cloudflare", "groq", "openrouter", "openai"}:
            latency = int((time.time() - start) * 1000)
            if not LLM_API_KEY:
                return "degraded", {
                    "error": "LLM_API_KEY not configured",
                    "provider": provider,
                    "latency_ms": latency,
                }
            if not LLM_BASE_URL:
                return "degraded", {
                    "error": "LLM_BASE_URL not configured",
                    "provider": provider,
                    "latency_ms": latency,
                }
            return "online", {
                "provider": provider,
                "model": live["model"],
                "thinking": live["thinking"],
                "max_tokens": live["max_tokens"],
                "latency_ms": latency,
            }

        # ── Local / LM Studio: probe /v1/models ──────────────────────────────
        models_url = LLM_BASE_URL.replace("/v1/chat/completions", "/v1/models")
        response = requests.get(models_url, timeout=5)
        latency = int((time.time() - start) * 1000)
        if response.status_code != 200:
            return "degraded", {"error": "models_endpoint_failed", "status_code": response.status_code}
        loaded = [m.get("id", "") for m in response.json().get("data", [])]
        if live["model"] in loaded:
            return "online", {"latency_ms": latency, "model": live["model"], "loaded_models": loaded}
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
