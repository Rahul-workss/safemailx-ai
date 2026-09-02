"""
Layer 1 — Policy Verification Engine
Checks whether caller's actions violate the real-world policies of the claimed org.
"""
import json
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("POLICY_VERIFICATION")

_ORG_POLICIES: Optional[dict] = None
_ORG_POLICIES_PATH = Path(__file__).resolve().parents[2] / "data" / "org_policies.json"

# Special: these orgs NEVER legitimately call citizens at all
NEVER_CALL_ORGS = ["uidai", "rbi", "reserve bank", "aadhaar"]

# Special: law enforcement never does these
LAW_ENFORCEMENT_KEYWORDS = ["cbi", "police", "enforcement directorate", "ed ", "cyber crime", "narcotics"]


def _load_policies() -> dict:
    global _ORG_POLICIES
    if _ORG_POLICIES is not None:
        return _ORG_POLICIES
    try:
        with open(_ORG_POLICIES_PATH, "r", encoding="utf-8") as f:
            _ORG_POLICIES = json.load(f)
        logger.info("[POLICY] Loaded %d org policies.", len(_ORG_POLICIES))
    except Exception as e:
        logger.warning("[POLICY] Failed to load org_policies.json: %s", e)
        _ORG_POLICIES = {}
    return _ORG_POLICIES


def _find_org(org_claimed: str) -> Optional[dict]:
    """Fuzzy match org_claimed to a policy entry via aliases."""
    policies = _load_policies()
    org_lower = org_claimed.lower()
    for key, entry in policies.items():
        # Check canonical name
        if entry.get("name", "").lower() in org_lower or org_lower in entry.get("name", "").lower():
            return entry
        # Check aliases
        for alias in entry.get("aliases", []):
            if alias.lower() in org_lower or org_lower in alias.lower():
                return entry
    return None


def analyze(transcript: str, claims: Optional[dict] = None) -> dict:
    org_claimed = ""
    actions_requested = []

    if claims:
        org_claimed = claims.get("org_claimed", "")
        actions_requested = claims.get("actions_requested", [])

    if not org_claimed:
        # Try to detect from transcript
        org_claimed = transcript[:500] if transcript else ""

    if not org_claimed:
        return {
            "score": 0.30,
            "finding": "no_org_claimed",
            "plain_english": "No organization name detected in the description.",
            "evidence": {},
            "hard_floor": None,
            "official_callback": ""
        }

    org_lower = org_claimed.lower()

    # Special case: orgs that NEVER call citizens
    for never_call in NEVER_CALL_ORGS:
        if never_call in org_lower:
            return {
                "score": 0.97,
                "finding": "org_never_calls_citizens",
                "plain_english": f"POLICY VIOLATION: {org_claimed.title()} NEVER calls citizens directly for any reason. Any call claiming to be from this organization is fraudulent.",
                "evidence": {"org_claimed": org_claimed, "rule": "never_calls_citizens"},
                "hard_floor": 0.97,
                "official_callback": "1947 (UIDAI Helpline)" if "uidai" in never_call or "aadhaar" in never_call else ""
            }

    # Special case: law enforcement digital arrest
    for le_kw in LAW_ENFORCEMENT_KEYWORDS:
        if le_kw in org_lower:
            return {
                "score": 0.96,
                "finding": "law_enforcement_phone_scam",
                "plain_english": f"POLICY VIOLATION: {org_claimed.title()} agencies NEVER arrest citizens via phone or video call. 'Digital arrest' is not a legal concept in India. This is a scam.",
                "evidence": {"org_claimed": org_claimed, "rule": "no_phone_arrests"},
                "hard_floor": 0.96,
                "official_callback": "1930 (Cyber Crime Helpline)"
            }

    # Look up org in policy database
    org_entry = _find_org(org_claimed)

    if not org_entry:
        return {
            "score": 0.45,
            "finding": "org_not_in_database",
            "plain_english": f"Cannot verify official policies for '{org_claimed}'. Exercise caution and call the organization's official number directly to verify.",
            "evidence": {"org_claimed": org_claimed},
            "hard_floor": None,
            "official_callback": ""
        }

    # Check actions against never_via_call list
    violations = []
    never_list = org_entry.get("never_via_call", [])
    for action in actions_requested:
        action_lower = action.lower()
        for forbidden in never_list:
            if any(word in forbidden.lower() for word in action_lower.split() if len(word) > 3):
                violations.append({"action": action, "policy_rule": forbidden})
                break

    # Also scan transcript for action keywords
    if not actions_requested and transcript:
        transcript_lower = transcript.lower()
        for forbidden in never_list:
            if any(word in transcript_lower for word in forbidden.lower().split() if len(word) > 3):
                violations.append({"action": "detected in description", "policy_rule": forbidden})

    official_numbers = org_entry.get("official_numbers", [])
    callback = official_numbers[0] if official_numbers else ""
    org_name = org_entry.get("name", org_claimed)

    if violations:
        v = violations[0]
        return {
            "score": 0.92,
            "finding": "policy_violation",
            "plain_english": f"POLICY VIOLATION: {org_name} would NEVER '{v['policy_rule']}'. This directly violates their official policy. Call {org_name} directly at {callback} to verify.",
            "evidence": {"org": org_name, "violations": violations, "policy_source": org_entry.get("verified_source", "")},
            "hard_floor": 0.88,
            "official_callback": callback
        }
    else:
        return {
            "score": 0.10,
            "finding": "no_policy_violation",
            "plain_english": f"Call purpose appears consistent with {org_name}'s known practices. If still unsure, call them directly at {callback}.",
            "evidence": {"org": org_name},
            "hard_floor": None,
            "official_callback": callback
        }
