"""Test how long Qwen3 actually takes for a full call analysis prompt."""
import requests, time, json

start = time.time()
payload = {
    "model": "qwen3-8b",
    "messages": [
        {
            "role": "system",
            "content": "You analyze phone calls for scams. Reply with ONLY valid JSON: {\"threat_probability\": 0.95, \"final_verdict\": \"CRITICAL\", \"confidence\": 0.92, \"plain_english\": \"This is a bank OTP scam.\", \"means_for_you\": \"Your bank already knows the OTP they sent you.\", \"next_tactics\": [\"They will use your OTP to drain your account.\"], \"tactics_detected\": [\"otp_harvesting\"], \"override_reason\": null}"
        },
        {
            "role": "user",
            "content": "=== CALL DESCRIPTION ===\nSomeone called claiming to be SBI Bank. Said my account will be blocked. Asked for OTP. Said don't tell anyone.\n\n=== SIGNALS ===\nOrg claimed: SBI Bank\nActions: OTP or PIN\nWarnings: Don't tell anyone\n\n=== RULE ENGINE ===\nRule Final Score: 0.950\n\nOutput ONLY the JSON object."
        }
    ],
    "temperature": 0.6,
    "top_p": 0.95,
    "max_tokens": 600,
    "stream": False,
    "chat_template_kwargs": {"enable_thinking": True}
}
try:
    r = requests.post("http://127.0.0.1:1234/v1/chat/completions", json=payload, timeout=180)
    elapsed = time.time() - start
    msg = r.json()["choices"][0]["message"]
    think_words = len((msg.get("reasoning_content", "") or "").split())
    content = (msg.get("content", "") or "").strip()
    print(f"Time taken: {elapsed:.1f}s")
    print(f"Thinking words: {think_words}")
    print(f"Content: {content[:300]}")
except Exception as e:
    elapsed = time.time() - start
    print(f"Error after {elapsed:.1f}s: {e}")
