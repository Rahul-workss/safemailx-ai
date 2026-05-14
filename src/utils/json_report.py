# ==================================
# JSON Forensic Report Generator
# ==================================

import json
import os
from datetime import datetime, timezone

from utils.config import REPORTS_DIR


def save_json_report(evidence):

    os.makedirs(REPORTS_DIR, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    filepath = os.path.join(REPORTS_DIR, f"forensic_report_{timestamp}.json")

    with open(filepath, "w") as f:
        json.dump(evidence, f, indent=4)

    return filepath
