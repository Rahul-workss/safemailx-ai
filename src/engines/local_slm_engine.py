import json
import re
import logging
import requests

logger = logging.getLogger("LLM_ANALYZER")

try:
    from llama_cpp import Llama
    LLAMA_CPP_AVAILABLE = True
except (ImportError, Exception) as e:
    LLAMA_CPP_AVAILABLE = False
    logger.warning(f"llama-cpp-python failed to load ({e}). Falling back to HTTP LM Studio.")

# Pre-load SLM globally if available
_SLM = None
if LLAMA_CPP_AVAILABLE:
    try:
        # User stores massive models externally to keep the project repository small
        _SLM = Llama(model_path=r"D:\SAFEMAIL-X WORK\phi-3-mini-4k-geminified-q4_k_m.gguf", n_ctx=2048, verbose=False)
        logger.info("4-bit SLM successfully loaded via llama-cpp-python.")
    except Exception as e:
        logger.error(f"Failed to load SLM: {e}")

# Zero Chain-of-Thought Prompts
URL_PROMPT = """You are SafeMail X SLM. Evaluate this URL using the provided deterministic structural features.
DO NOT use chain-of-thought. DO NOT output reasoning steps.
Output ONLY a JSON object exactly like this:
{"is_malicious": true/false, "confidence": 0.9, "reasoning": "Brief 1-sentence explanation."}"""

FILE_PROMPT = """You are SafeMail X SLM. Evaluate this File text using the provided deterministic structural features.
DO NOT use chain-of-thought. DO NOT output reasoning steps.
Output ONLY a JSON object exactly like this:
{"is_malicious": true/false, "confidence": 0.9, "reasoning": "Brief 1-sentence explanation."}"""

SMS_PROMPT = """You are SafeMail X SLM. Evaluate this SMS using the provided deterministic structural features.
DO NOT use chain-of-thought. DO NOT output reasoning steps.
Output ONLY a JSON object exactly like this:
{"is_malicious": true/false, "confidence": 0.9, "reasoning": "Brief 1-sentence explanation."}"""

PROMPTS = {
    "url": URL_PROMPT,
    "file": FILE_PROMPT,
    "sms": SMS_PROMPT,
    "email": FILE_PROMPT  # Fallback
}

def run_quantized_slm(channel: str, target_content: str, features: dict) -> dict:
    """
    Stage 4: Deep Reasoning via Quantized SLM
    Executes the 4-bit model locally. If unavailable, falls back to LM Studio.
    """
    system_prompt = PROMPTS.get(channel, PROMPTS["url"])
    
    user_content = (
        f"--- TARGET ---\n{target_content}\n\n"
        f"--- DETERMINISTIC FEATURES ---\n{json.dumps(features, indent=2)}\n\n"
        f"Remember: Output ONLY valid JSON."
    )

    if _SLM:
        try:
            logger.info("Executing embedded SLM inference...")
            res = _SLM.create_chat_completion(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content}
                ],
                max_tokens=100,
                temperature=0.1
            )
            raw = res["choices"][0]["message"]["content"]
            return _parse_json_output(raw)
        except Exception as e:
            logger.error(f"SLM Inference failed: {e}")
            return {"is_malicious": False, "confidence": 0.0, "reasoning": "SLM execution failed."}
            
    else:
        # Fallback to standard HTTP LM Studio if llama-cpp-python isn't installed
        logger.info("Executing LM Studio HTTP fallback...")
        payload = {
            "model": "local-model",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content}
            ],
            "temperature": 0.1,
            "max_tokens": 150
        }
        try:
            from utils.config import LLM_BASE_URL
            resp = requests.post(LLM_BASE_URL, json=payload, timeout=3.0)
            resp.raise_for_status()
            msg = resp.json()["choices"][0]["message"]
            raw = msg.get("content", "")
            return _parse_json_output(raw)
        except Exception as e:
            logger.warning(f"LM Studio fallback failed: {e}")
            return {"is_malicious": False, "confidence": 0.0, "reasoning": "LLM offline."}


def _parse_json_output(raw: str) -> dict:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        clean_raw = re.sub(r"```(?:json)?\s*([\s\S]*?)\s*```", r"\1", raw).strip()
        try:
            return json.loads(clean_raw)
        except json.JSONDecodeError:
            matches = list(re.finditer(r"\{[\s\S]*\}", raw))
            if matches:
                return json.loads(matches[-1].group(0))
    return {"is_malicious": False, "confidence": 0.0, "reasoning": "Failed to parse SLM JSON."}

# Shim to support legacy `run_llm_analysis` calls from the old codebase
def run_llm_analysis(*args, **kwargs):
    logger.warning("Legacy run_llm_analysis called. Please update to SmartVetoOrchestrator.")
    text = args[0] if args else kwargs.get("text", "")
    channel = kwargs.get("channel", "url")
    return run_quantized_slm(channel, text, {"legacy": True})

# Shim for legacy arbitration check
def run_arbitration_check(*args, **kwargs):
    logger.warning("Legacy run_arbitration_check called. Returning bypass.")
    return {"arbitration": "bypass", "reason": "Legacy engine deprecated in favor of SmartVeto.", "confidence": 1.0, "neutralization_strength": "hard"}
