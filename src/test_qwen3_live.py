"""
Test Qwen3 live path specifically with a voice transcript case.
Shows the full personalised output Qwen3 generates.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engines.scam_intelligence_engine import analyze

print("=" * 60)
print("QWEN3 LIVE PERSONALISATION TEST")
print("Voice transcript: SBI OTP scam with isolation command")
print("=" * 60)

result = analyze({
    "input_mode": "transcript",
    "transcript": (
        "Someone called me claiming to be from SBI Bank fraud department. "
        "They said my account shows suspicious activity and will be blocked in 2 hours. "
        "They asked me to share the OTP that was just sent to my phone to verify my identity. "
        "They also said I should not hang up or tell anyone about this call until it is resolved."
    ),
    "org_claimed": "SBI Bank",
    "actions_requested": ["OTP or PIN"],
    "warning_phrases": ["Don't tell anyone", "Stay on the line"],
})

print(f"\nRisk Band    : {result['risk_band']}")
print(f"Score        : {result['score_display']}")
print(f"Confidence   : {round(result.get('confidence_score', 0) * 100)}%")
print(f"Qwen3 Active : {result.get('qwen_available', False)}")

print(f"\n--- plain_english (from Qwen3 or deterministic) ---")
print(result.get("plain_english") or result.get("deterministic_explanation", "(none)"))

print(f"\n--- means_for_you ---")
print(result.get("means_for_you", "(none)"))

print(f"\n--- next_tactics ---")
for t in result.get("next_tactics", []):
    print(f"  ! {t}")

print(f"\n--- how_to_verify ---")
for i, s in enumerate(result.get("how_to_verify", []), 1):
    print(f"  {i}. {s}")

print(f"\n--- why_flagged ---")
for w in result.get("why_flagged", []):
    print(f"  * {w[:120]}")

print(f"\n--- tactics_detected ---")
print(result.get("tactics_detected", []))

print(f"\n--- deterministic_explanation (fallback) ---")
print(result.get("deterministic_explanation", "(none)")[:300])
