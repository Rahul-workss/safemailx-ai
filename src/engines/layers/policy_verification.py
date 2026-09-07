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

# Special: law enforcement / customs never arrest or demand payment via phone
LAW_ENFORCEMENT_KEYWORDS = ["cbi", "police", "enforcement directorate", "ed ", "cyber crime", "narcotics", "customs", "dri"]

# Special: tax authorities never collect payment via phone
NEVER_PAYMENT_ORGS = ["income tax", "income-tax", "tax department", "tax officer", "tds"]
PAYMENT_DEMAND_KEYWORDS = ["upi", "payment", "pay", "transfer", "money", "dues", "fine", "fee", "rupees", "amount"]


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

    # If no org is claimed at all, return a neutral/slightly cautious score
    if not org_claimed or not org_claimed.strip():
        return {
            "score": 0.25,
            "finding": "no_org_claimed",
            "plain_english": "No organization name was provided. Cannot run policy verification. If the caller did not identify their organization, this itself is a warning sign.",
            "evidence": {},
            "hard_floor": None,
            "official_callback": ""
        }

    org_lower = org_claimed.lower()

    # Special case: orgs that NEVER call citizens (only when org is actually named)
    if org_lower:
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

        # Special case: law enforcement / customs digital arrest or payment demand
        for le_kw in LAW_ENFORCEMENT_KEYWORDS:
            if le_kw in org_lower:
                is_customs = "customs" in org_lower or "dri" in org_lower
                msg = (
                    "POLICY VIOLATION: Indian Customs NEVER calls citizens to demand payment. "
                    "Any call claiming a parcel contains drugs and demanding UPI/bank transfer is a scam."
                    if is_customs else
                    f"POLICY VIOLATION: {org_claimed.title()} agencies NEVER arrest citizens via phone or video call. "
                    "'Digital arrest' is not a legal concept in India. This is a scam."
                )
                return {
                    "score": 0.96,
                    "finding": "law_enforcement_phone_scam",
                    "plain_english": msg,
                    "evidence": {"org_claimed": org_claimed, "rule": "no_phone_arrests"},
                    "hard_floor": 0.96,
                    "official_callback": "1930 (Cyber Crime Helpline)"
                }

        # Special case: income tax / tax orgs demanding payment via phone call
        for tax_kw in NEVER_PAYMENT_ORGS:
            if tax_kw in org_lower:
                all_actions_text = " ".join(actions_requested).lower()
                if any(pk in all_actions_text for pk in PAYMENT_DEMAND_KEYWORDS):
                    return {
                        "score": 0.95,
                        "finding": "tax_payment_phone_scam",
                        "plain_english": (
                            f"POLICY VIOLATION: The Income Tax Department NEVER collects payments over the phone. "
                            "Tax dues are paid only via the official portal at incometax.gov.in. This call is a scam."
                        ),
                        "evidence": {"org_claimed": org_claimed, "rule": "no_phone_payment_collection"},
                        "hard_floor": 0.92,
                        "official_callback": "1800-103-0025 (Income Tax Helpline)"
                    }

    # Look up org in policy database
    org_entry = _find_org(org_claimed)

    if not org_entry:
        return {
            "score": 0.52,
            "finding": "org_not_in_database",
            "plain_english": f"Cannot verify official policies for '{org_claimed}'. We have no record of this organization. Treat the call with caution and call the organization's official number from their website to verify.",
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
            # Require meaningful word (>4 chars) to avoid single-word false positives
            meaningful_words = [w for w in action_lower.split() if len(w) > 4]
            if meaningful_words and any(word in forbidden.lower() for word in meaningful_words):
                violations.append({"action": action, "policy_rule": forbidden})
                break

    # Scan transcript ONLY when no structured actions given AND transcript has real content
    # Require 2+ meaningful keyword hits to prevent false positives from innocent synthetic text
    if not actions_requested and transcript and len(transcript.strip()) > 60:
        transcript_lower = transcript.lower()
        for forbidden in never_list:
            forbidden_words = [w for w in forbidden.lower().split() if len(w) > 4]
            hits = sum(1 for word in forbidden_words if word in transcript_lower)
            if hits >= 2:
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
