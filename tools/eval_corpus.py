#!/usr/bin/env python3
"""
tools/eval_corpus.py — SafeMail X AI corpus evaluation harness.

Usage:
    python tools/eval_corpus.py <label>
    e.g.: python tools/eval_corpus.py qwen25

Writes: tools/eval_results_<label>.json
Prints: per-case results + aggregate confusion matrix table.

Run IDENTICALLY for Qwen 2.5 baseline (Step 1) and Qwen 3 re-verification (Step 5).
Compare output files to detect regressions before proceeding with the migration.
"""

import json
import os
import re
import sys
import time
from pathlib import Path

# ── Path setup ───────────────────────────────────────────────────────────────
# This script lives in tools/; the engine lives in src/.
REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_DIR))
sys.path.insert(0, str(REPO_ROOT))

from engines.instant_scan_engine import SmartVetoOrchestrator

CORPUS_DIR = REPO_ROOT / "tests" / "corpus"
CHANNELS = ["email", "sms", "url", "file"]

# ── Verdict label mapping ─────────────────────────────────────────────────────
# If any new label string appears in .expected.json files that is NOT in one of
# these sets, the label audit will stop the run and tell you what to add.
POSITIVE_VERDICTS  = {"phishing", "Phishing", "PHISHING"}
NEGATIVE_VERDICTS  = {"legitimate", "Legitimate", "LEGITIMATE", "safe", "Safe", "SAFE"}
SUSPICIOUS_VERDICTS = {"suspicious", "Suspicious", "SUSPICIOUS"}

PARSE_FAILURE_REASONS = {
    "empty_content", "malformed_json", "think_tag_leaked", "truncated_output"
}

# ── Arbitration system IDs (must match analysis_steps log strings) ────────────
SYSTEM_IDS = [
    "correlation_engine", "smart_veto_hard", "smart_veto_soft", "smart_veto_safe",
    "specificity_scorer", "intent_ceiling", "intent_floor", "attack_vector_gate",
    "vip_domain_trust", "vip_spoof_penalty", "prompt_injection_guard",
    "confidence_override", "fallback_safety_net",
]

STEP_PATTERNS = {
    "correlation_engine":     "Correlation Engine",
    "smart_veto_hard":        "Smart Veto: HARD VETO",
    "smart_veto_soft":        "Smart Veto: SOFT VETO",
    "smart_veto_safe":        "Smart Veto: SAFE override",
    "specificity_scorer":     "specificity",
    "intent_ceiling":         "Intent ceiling",
    "intent_floor":           "Intent floor",
    "attack_vector_gate":     "Attack Vector Gate",
    "vip_domain_trust":       "VIP Domain",
    "vip_spoof_penalty":      "vip_spoof",
    "prompt_injection_guard": "Prompt-injection",
    "confidence_override":    "Confidence override",
    "fallback_safety_net":    "fallback",
}


# ═══════════════════════════════════════════════════════════════════════════════
# Label audit
# ═══════════════════════════════════════════════════════════════════════════════
def audit_labels() -> tuple[set, bool]:
    """Collect all unique verdict label strings. Return (label_set, ok)."""
    found = set()
    for channel in CHANNELS:
        for f in (CORPUS_DIR / channel).glob("*.expected.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                v = data.get("expected_verdict")
                if v is not None:
                    found.add(str(v))
            except Exception:
                pass

    all_known = POSITIVE_VERDICTS | NEGATIVE_VERDICTS | SUSPICIOUS_VERDICTS
    unexpected = found - all_known
    if unexpected:
        print("\n[EVAL] Unknown verdict label strings found in corpus:")
        for label in sorted(unexpected):
            print(f"         '{label}'")
        print("[EVAL]    Add them to POSITIVE_VERDICTS / NEGATIVE_VERDICTS / "
              "SUSPICIOUS_VERDICTS in this script and re-run.")
        return found, False
    print(f"[EVAL] Label audit passed. All unique labels: {sorted(found)}")
    return found, True


# -----------------------------------------------------------------------------
# Bucket assignment
# -----------------------------------------------------------------------------
def assign_bucket(expected_raw: str, actual_verdict: str) -> str:
    expected = expected_raw.lower()
    actual   = actual_verdict.lower()
    is_pos_expected = expected in {v.lower() for v in POSITIVE_VERDICTS}
    is_pos_actual   = actual == "phishing"
    if is_pos_expected and is_pos_actual:
        return "TP"
    if not is_pos_expected and is_pos_actual:
        return "FP"
    if is_pos_expected and not is_pos_actual:
        return "FN"
    return "TN"


# -----------------------------------------------------------------------------
# Think block helpers (used when model exposes reasoning_content)
# -----------------------------------------------------------------------------
def extract_think_block(raw_response: str) -> tuple[bool, int]:
    """Return (thinking_block_present, thinking_tokens_estimate)."""
    m = re.search(r"<think>([\s\S]*?)</think>", raw_response, re.IGNORECASE)
    if m:
        chars = len(m.group(1))
        return True, chars // 4
    return False, 0


def detect_parse_failure(content: str) -> str | None:
    """Classify parse failure reason using the 4-value enum."""
    if not content or not content.strip():
        return "empty_content"
    if re.search(r"</?think(?:ing)?>", content, re.IGNORECASE):
        return "think_tag_leaked"
    try:
        json.loads(content.strip())
        return None
    except json.JSONDecodeError:
        if content.strip().startswith("{") and not content.strip().endswith("}"):
            return "truncated_output"
        return "malformed_json"


# -----------------------------------------------------------------------------
# Systems-fired inference from analysis_steps strings
# -----------------------------------------------------------------------------
def infer_systems_fired(analysis_steps: list, llm_available: bool) -> list:
    steps_str = " ".join(analysis_steps).lower()
    fired = []
    for sys_id, pattern in STEP_PATTERNS.items():
        if pattern.lower() in steps_str:
            fired.append(sys_id)
    if not llm_available and "fallback_safety_net" not in fired:
        fired.append("fallback_safety_net")
    return fired


# -----------------------------------------------------------------------------
# Run one corpus case
# -----------------------------------------------------------------------------
def run_case(engine: SmartVetoOrchestrator, channel: str,
             txt_path: Path, expected_json_path: Path) -> dict:
    with open(txt_path, "rb") as f:
        content_bytes = f.read()
    with open(expected_json_path, "r", encoding="utf-8") as f:
        expected_data = json.load(f)

    expected_verdict = expected_data.get("expected_verdict", "legitimate")
    case_id = f"{channel}/{txt_path.stem}"

    t0 = time.time()
    try:
        if channel == "sms":
            result = engine.process_sms_scan(content_bytes.decode("utf-8", errors="replace"))
        elif channel == "url":
            result = engine.process_url_scan(content_bytes.decode("utf-8", errors="replace").strip())
        elif channel == "file":
            result = engine.process_file_scan(txt_path.name, "text/plain", content_bytes)
        elif channel == "email":
            # Email channel uses file_scan with email content (MIME or raw text)
            result = engine.process_file_scan(txt_path.name, "text/plain", content_bytes)
        else:
            raise ValueError(f"Unknown channel: {channel}")
    except Exception as e:
        return {"case_id": case_id, "channel": channel,
                "expected": expected_verdict, "error": str(e)}

    elapsed_ms = int((time.time() - t0) * 1000)
    actual_verdict = result.verdict
    bucket = assign_bucket(expected_verdict, actual_verdict)

    # LLM metadata — best-effort from result attributes
    llm_score_value = getattr(result, "llm_score", None)
    llm_available   = llm_score_value is not None

    # Think block detection: SmartVetoOrchestrator does not expose raw reasoning_content.
    # When the parser is updated in Step 3 to log thinking data, wire it in here.
    thinking_block_present = False
    thinking_tokens        = 0
    parse_failure_reason   = None
    json_parse_success     = True

    # Try to infer systems fired from analysis_steps if available
    analysis_steps  = getattr(result, "analysis_steps", []) or []
    systems_fired   = infer_systems_fired(analysis_steps, llm_available)

    return {
        "case_id":               case_id,
        "channel":               channel,
        "expected":              expected_verdict,
        "actual":                actual_verdict,
        "correct":               bucket in ("TP", "TN"),
        "bucket":                bucket,
        "final_score":           round(float(result.risk_score) / 100, 3),
        "llm_score":             round(float(llm_score_value), 3) if llm_score_value is not None else None,
        "llm_available":         llm_available,
        "response_time_ms":      elapsed_ms,
        "token_usage":           {"prompt": None, "completion": None, "total": None},
        "json_parse_success":    json_parse_success,
        "parse_failure_reason":  parse_failure_reason,
        "thinking_block_present": thinking_block_present,
        "thinking_tokens":       thinking_tokens,
        "systems_fired":         systems_fired,
        "fallback_activated":    not llm_available,
    }


# -----------------------------------------------------------------------------
# Aggregate metrics computation
# -----------------------------------------------------------------------------
def compute_metrics(records: list, channel_filter: str | None = None) -> dict:
    subset = [r for r in records if "error" not in r]
    if channel_filter:
        subset = [r for r in subset if r.get("channel") == channel_filter]
    if not subset:
        return {}

    tp = sum(1 for r in subset if r["bucket"] == "TP")
    fp = sum(1 for r in subset if r["bucket"] == "FP")
    tn = sum(1 for r in subset if r["bucket"] == "TN")
    fn = sum(1 for r in subset if r["bucket"] == "FN")
    total = len(subset)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy  = (tp + tn) / total if total else 0.0

    avg_rt = sum(r["response_time_ms"] for r in subset) / len(subset)

    parse_ok   = [r for r in subset if r.get("json_parse_success")]
    parse_fail = [r for r in subset if not r.get("json_parse_success")]
    parse_success_rate = len(parse_ok) / total

    fail_breakdown: dict[str, int] = {}
    for r in parse_fail:
        reason = r.get("parse_failure_reason") or "unknown"
        fail_breakdown[reason] = fail_breakdown.get(reason, 0) + 1

    thinking_cases = [r for r in subset if r.get("thinking_block_present")]
    thinking_rate  = len(thinking_cases) / total
    avg_thinking_tokens = (
        sum(r["thinking_tokens"] for r in thinking_cases) / len(thinking_cases)
        if thinking_cases else 0
    )
    thinking_suppressed = [
        r["case_id"] for r in subset
        if not r.get("thinking_block_present") and r.get("llm_available")
    ]

    fallback_rate = sum(1 for r in subset if r.get("fallback_activated")) / total

    system_fire_rates: dict[str, dict] = {}
    for sys_id in SYSTEM_IDS:
        count = sum(1 for r in subset if sys_id in r.get("systems_fired", []))
        system_fire_rates[sys_id] = {"count": count, "rate": round(count / total, 3)}

    return {
        "total":    total,
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "precision": round(precision, 4),
        "recall":    round(recall, 4),
        "f1":        round(f1, 4),
        "accuracy":  round(accuracy, 4),
        "avg_response_time_ms": round(avg_rt, 1),
        "json_parse_success_rate": round(parse_success_rate, 4),
        "parse_failure_breakdown": fail_breakdown,
        "thinking_block_present_rate": round(thinking_rate, 4),
        "avg_thinking_tokens":         round(avg_thinking_tokens, 1),
        "thinking_suppressed_cases":   thinking_suppressed,
        "fallback_safety_net_rate":    round(fallback_rate, 4),
        "system_fire_rates":           system_fire_rates,
    }


# -----------------------------------------------------------------------------
# Print summary table
# -----------------------------------------------------------------------------
def print_summary(metrics: dict, label: str = "Aggregate") -> None:
    W = 42
    print(f"\n{'------------------------------------------------------------'}")
    print(f"  {label} Metrics")
    print(f"{'------------------------------------------------------------'}")
    keys = [
        "total", "TP", "FP", "TN", "FN",
        "precision", "recall", "f1", "accuracy",
        "avg_response_time_ms", "json_parse_success_rate",
        "thinking_block_present_rate", "avg_thinking_tokens",
        "fallback_safety_net_rate",
    ]
    for k in keys:
        v = metrics.get(k, "n/a")
        print(f"  {k:{W}}: {v}")
    print()
    pb = metrics.get("parse_failure_breakdown", {})
    if pb:
        print(f"  {'parse_failure_breakdown':{W}}:")
        for reason, cnt in pb.items():
            print(f"    {'':2}{reason:{W-2}}: {cnt}")
    sf = metrics.get("system_fire_rates", {})
    if sf:
        print(f"\n  Arbitration System Fire Rates:")
        for sys_id, data in sf.items():
            print(f"    {sys_id:{W-2}}: count={data['count']}  rate={data['rate']:.1%}")


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
def main() -> None:
    label = sys.argv[1] if len(sys.argv) > 1 else "unlabeled"
    print(f"\n[EVAL] === SafeMail X AI -- Corpus Evaluation Harness ===")
    print(f"[EVAL] Label: {label}")
    print(f"[EVAL] Corpus: {CORPUS_DIR}")

    # Step 1: label audit
    _, ok = audit_labels()
    if not ok:
        sys.exit(1)

    engine  = SmartVetoOrchestrator()
    records: list[dict] = []

    for channel in CHANNELS:
        channel_dir = CORPUS_DIR / channel
        if not channel_dir.exists():
            print(f"[EVAL] WARNING Channel '{channel}' directory not found -- skipping.")
            continue
        txt_files = sorted(channel_dir.glob("*.txt"))
        if not txt_files:
            print(f"[EVAL] WARNING Channel '{channel}' has 0 .txt files -- skipping.")
            continue

        print(f"[EVAL] -- Channel: {channel} ({len(txt_files)} cases) --")
        if len(txt_files) < 5:
            print(f"[EVAL] WARNING Only {len(txt_files)} cases -- metrics are directional only.")

        for txt_path in txt_files:
            expected_path = txt_path.with_suffix("").with_suffix(".expected.json")
            if not expected_path.exists():
                print(f"[EVAL] ERROR Missing label file: {expected_path}")
                sys.exit(1)
            record = run_case(engine, channel, txt_path, expected_path)
            records.append(record)

            if "error" in record:
                print(f"  [E] {record['case_id']:45s}  ERROR: {record['error']}")
            else:
                status = "OK" if record["correct"] else "XX"
                print(f"  [{status}] {record['case_id']:45s}  "
                      f"expected={record['expected']:12s}  "
                      f"actual={record['actual']:12s}  "
                      f"bucket={record['bucket']}  "
                      f"score={record['final_score']:.3f}  "
                      f"rt={record['response_time_ms']}ms")

    # Compute aggregate + per-channel metrics
    overall     = compute_metrics(records)
    per_channel = {ch: compute_metrics(records, ch) for ch in CHANNELS}

    # Write JSON output
    output = {
        "label":       label,
        "per_case":    records,
        "aggregate":   overall,
        "per_channel": per_channel,
    }
    out_path = REPO_ROOT / "tools" / f"eval_results_{label}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n[EVAL] Results written to {out_path}")

    # Print tables
    print_summary(overall, "Aggregate")
    for ch in CHANNELS:
        if per_channel.get(ch):
            print_summary(per_channel[ch], f"Channel: {ch}")

    # Flag any errors
    errors = [r for r in records if "error" in r]
    if errors:
        print(f"\n[EVAL] ERROR {len(errors)} case(s) errored -- fix before treating metrics as valid:")
        for r in errors:
            print(f"  {r['case_id']}: {r['error']}")

    # Highlight fallback rate
    fb_rate = overall.get("fallback_safety_net_rate", 0)
    if fb_rate > 0.05:
        print(f"\n[EVAL] WARNING FALLBACK SAFETY NET rate = {fb_rate:.1%} (>5% threshold!)")
        print(f"       Check LM Studio is running and LLM_BASE_URL is reachable.")

    wrong = [r for r in records if not r.get("correct") and "error" not in r]
    if wrong:
        print(f"\n[EVAL] XX Incorrect predictions ({len(wrong)}):")
        for r in wrong:
            print(f"  {r['case_id']:45s}  expected={r['expected']}  actual={r['actual']}  "
                  f"bucket={r['bucket']}  score={r['final_score']:.3f}")


if __name__ == "__main__":
    main()
