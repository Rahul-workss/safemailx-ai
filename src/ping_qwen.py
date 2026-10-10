import requests, json, sys

# Quick Qwen3 connectivity test
payload = {
    "model": "qwen3-8b",
    "messages": [{"role": "user", "content": "Say hello in exactly 3 words."}],
    "temperature": 0.1,
    "max_tokens": 30,
    "stream": False,
    "chat_template_kwargs": {"enable_thinking": False}
}
try:
    r = requests.post("http://127.0.0.1:1234/v1/chat/completions", json=payload, timeout=15)
    msg = r.json()["choices"][0]["message"]
    print("Qwen3 online:", msg.get("content", ""))
    sys.exit(0)
except Exception as e:
    print("Qwen3 error:", e)
    sys.exit(1)
