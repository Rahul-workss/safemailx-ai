import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engines.scam_intelligence_engine import analyze

def run(label, data, expect_band=None, expect_min=None, expect_max=None):
    print()
    print("=" * 55)
    print("TEST:", label)
    r = analyze(data)
    band  = r["risk_band"]
    score = r["score_display"]
    conf  = round(r.get("confidence_score", 0) * 100)
    qwen  = r.get("qwen_available", False)
    print(f"  Band={band}  Score={score}  Conf={conf}%  Qwen3={qwen}")
    expl = (r.get("plain_english") or r.get("deterministic_explanation", ""))[:220]
    print(f"  Explanation: {expl}")
    mfy = r.get("means_for_you", "")[:160]
    if mfy:
        print(f"  MeansForYou: {mfy}")
    nt = r.get("next_tactics", [])
    if nt:
        print(f"  NextTactic1: {nt[0][:120]}")
    ok = True
    if expect_band and band != expect_band:
        print(f"  FAIL: expected band={expect_band} got={band}")
        ok = False
    if expect_min is not None and score < expect_min:
        print(f"  FAIL: score {score} < expected {expect_min}")
        ok = False
    if expect_max is not None and score > expect_max:
        print(f"  FAIL: score {score} > expected max {expect_max}")
        ok = False
    print("  PASS" if ok else "  FAIL")
    return ok

results = []

results.append(run(
    "T1: HDFC+OTP — classic bank OTP harvest",
    {"input_mode": "structured", "org_claimed": "HDFC Bank",
     "actions_requested": ["OTP or PIN"], "warning_phrases": []},
    expect_band="CRITICAL", expect_min=80,
))

results.append(run(
    "T2: UIDAI — org that never calls (hard floor)",
    {"input_mode": "structured", "org_claimed": "UIDAI",
     "actions_requested": [], "warning_phrases": []},
    expect_band="CRITICAL", expect_min=90,
))

results.append(run(
    "T3: Amazon+OTP — unknown org, action-based scoring",
    {"input_mode": "structured", "org_claimed": "Amazon",
     "actions_requested": ["OTP or PIN"], "warning_phrases": []},
    expect_min=75,
))

results.append(run(
    "T4: SBI no action — anti false-positive (should be SAFE)",
    {"input_mode": "structured", "org_claimed": "SBI Bank",
     "actions_requested": [], "warning_phrases": []},
    expect_max=40,
))

results.append(run(
    "T5: Police/CBI + arrest + money — digital arrest scam",
    {"input_mode": "structured", "org_claimed": "Police/CBI",
     "actions_requested": ["Transfer money"], "warning_phrases": ["Arrest warrant / FIR"]},
    expect_band="CRITICAL", expect_min=90,
))

results.append(run(
    "T6: Voice transcript — rich personalisation with Qwen3",
    {
        "input_mode": "transcript",
        "transcript": (
            "Someone called me claiming to be from SBI Bank fraud department. "
            "They said my account shows suspicious activity and will be blocked in 2 hours. "
            "They asked me to share the OTP that was just sent to my phone to verify my identity. "
            "They also said I should not hang up or tell anyone about this call."
        ),
        "org_claimed": "SBI Bank",
        "actions_requested": ["OTP or PIN"],
        "warning_phrases": ["Don't tell anyone", "Stay on the line"],
    },
    expect_band="CRITICAL", expect_min=85,
))

print()
print("=" * 55)
total  = len(results)
passed = sum(results)
print(f"RESULTS: {passed}/{total} PASSED")
if passed == total:
    print("ALL TESTS PASSED")
else:
    print(f"{total - passed} TESTS FAILED")
