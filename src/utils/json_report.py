# ==================================
# JSON Forensic Report Generator
# ==================================

import json
import os
from datetime import datetime


def save_json_report(evidence):

    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))

    reports_dir = os.path.join(base_dir, "reports")

    os.makedirs(reports_dir, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    filepath = os.path.join(reports_dir, f"forensic_report_{timestamp}.json")

    with open(filepath, "w") as f:
        json.dump(evidence, f, indent=4)

    return filepath