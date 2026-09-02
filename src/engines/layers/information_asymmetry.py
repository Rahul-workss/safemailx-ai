"""
Layer 3 — Information Asymmetry Detector
Logical proof of fraud: if the org generated/possesses the data they're asking for,
asking for it proves they are not that org.
"""
import logging
from typing import Optional

logger = logging.getLogger("INFO_ASYMMETRY")

# Org type classification keywords
ORG_TYPE_MAP = {
    "bank": ["sbi", "hdfc", "icici", "axis", "kotak", "pnb", "bank", "yes bank",
             "canara", "idfc", "bob", "bank of baroda", "union bank"],
    "uidai": ["uidai", "aadhaar", "aadhar", "unique identification"],
    "courier": ["fedex", "dhl", "dtdc", "bluedart", "customs", "courier",
                "parcel", "amazon delivery", "india post"],
    "income_tax": ["income tax", "gst", "tax department", "tds", "it department",
                   "income tax officer"],
    "law_enforcement": ["cbi", "police", "enforcement", "ed ", "enforcement directorate",
                        "cyber crime", "narcotics", "court", "judiciary"],
    "telecom": ["trai", "jio", "airtel", "vodafone", "bsnl", "telecom"],
    "payment": ["paytm", "phonepe", "google pay", "gpay", "bhim"],
}

# What each org type already possesses — never legitimate to ask for
NEVER_LEGITIMATE = {
    "bank": [
        "otp", "one time password", "one-time password",
        "full card number", "card number", "cvv", "cvc",
        "internet banking password", "net banking password", "password",
        "upi pin", "mpin", "atm pin", "debit card pin",
        "aadhaar number", "aadhar number",
    ],
    "uidai": [
        "aadhaar number", "aadhar number", "biometric",
        "otp", "registered mobile", "personal details",
    ],
    "courier": [
        "customs duty", "processing fee", "card details", "otp",
        "payment to release", "bank account",
    ],
    "income_tax": [
        "payment over phone", "bank account number", "otp",
        "upi transfer", "google pay payment",
    ],
    "law_enforcement": [
        "money transfer", "safe account", "bail amount",
        "otp", "bank details", "upi payment", "google pay",
    ],
    "telecom": [
        "otp", "bank details", "payment to unblock",
        "card number", "upi pin",
    ],
    "payment": [
        "otp", "upi pin", "mpin", "password",
        "card details", "cvv",
    ],
}


def _classify_org(org_claimed: str) -> Optional[str]:
    org_lower = org_claimed.lower()
    for org_type, keywords in ORG_TYPE_MAP.items():
        for kw in keywords:
            if kw in org_lower:
                return org_type
    return None


def _find_violations(org_type: str, actions: list[str]) -> list[str]:
    violations = []
    never_list = NEVER_LEGITIMATE.get(org_type, [])
    for action in actions:
        action_lower = action.lower()
        for forbidden in never_list:
            if forbidden in action_lower or action_lower in forbidden:
                violations.append(f"{action} (forbidden for {org_type})")
                break
    return violations


def analyze(transcript: str, claims: Optional[dict] = None) -> dict:
    """
    Check for information asymmetry violations.
    Works on both Path A transcript and Path B structured claims.
    """
    # Extract org and actions from claims dict (Path B) or from transcript (Path A)
    org_claimed = ""
    actions_requested = []

    if claims:
        org_claimed = claims.get("org_claimed", "")
        actions_requested = claims.get("actions_requested", [])

    # If no structured claims, try to extract from transcript keywords
    if not org_claimed and transcript:
        org_claimed = transcript  # layer will try to classify from full text

    if not org_claimed:
        return {
            "score": 0.0,
            "finding": "no_org_claimed",
            "plain_english": "No organization identity claimed — cannot assess asymmetry.",
            "evidence": {},
            "hard_floor": None
        }

    org_type = _classify_org(org_claimed)
    if not org_type:
        return {
            "score": 0.0,
            "finding": "unrecognized_org_type",
            "plain_english": f"Cannot classify '{org_claimed}' — no asymmetry rule applies.",
            "evidence": {"org_claimed": org_claimed},
            "hard_floor": None
        }

    violations = _find_violations(org_type, actions_requested)

    # Also scan transcript for action keywords if no structured actions provided
    if not actions_requested and transcript:
        transcript_lower = transcript.lower()
        for forbidden in NEVER_LEGITIMATE.get(org_type, []):
            if forbidden in transcript_lower:
                violations.append(forbidden)

    if violations:
        org_display = org_claimed or org_type
        first_violation = violations[0]
        reason = {
            "bank": f"{org_display} SENDS you the OTP — they already know what it is. Asking you to read it back proves this caller is NOT {org_display}.",
            "uidai": f"UIDAI has your Aadhaar on file. They never call citizens. This cannot be UIDAI.",
            "courier": f"Legitimate couriers never ask for payment over phone to release a package. This is a fraud.",
            "income_tax": f"The Income Tax Department never collects payments via phone call or UPI.",
            "law_enforcement": f"Law enforcement agencies never arrest citizens via phone or video call, and never ask for money transfer.",
            "telecom": f"{org_display} already knows your SIM details. They never ask for OTP or payment to unblock a number.",
            "payment": f"{org_display} never asks for your UPI PIN or OTP — these are secret credentials only you should know.",
        }.get(org_type, f"LOGICAL PROOF: {org_display} already possesses this information. Asking for it proves caller is not {org_display}.")

        logger.info("[INFO_ASYMMETRY] Violations found for %s: %s", org_type, violations)
        return {
            "score": 0.95,
            "finding": "information_asymmetry_proven",
            "plain_english": f"LOGICAL PROOF OF FRAUD: {reason}",
            "evidence": {
                "org_claimed": org_claimed,
                "org_type": org_type,
                "violations": violations
            },
            "hard_floor": 0.90
        }
    else:
        return {
            "score": 0.0,
            "finding": "no_asymmetry_detected",
            "plain_english": "No information asymmetry detected.",
            "evidence": {"org_claimed": org_claimed, "org_type": org_type},
            "hard_floor": None
        }
