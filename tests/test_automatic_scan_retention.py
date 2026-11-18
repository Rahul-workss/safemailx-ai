import sys
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from server.scan_service import ScanService


def test_automatic_scan_persists_only_aggregate_verdict():
    repo = Mock()
    repo.get_scan.return_value = {"id": "scan-1", "final_label": "phishing"}
    service = ScanService(repo)
    evidence = {"email_metadata": {"subject": "sensitive subject"}, "scan_input": {"body_text": "sensitive body"}}
    result = {"final_label": "phishing", "final_score": 0.98, "llm_available": False}
    with patch("server.scan_service.hybrid_detect", return_value=result), \
         patch("server.scan_service.build_forensic_evidence", return_value=evidence), \
         patch("server.scan_service.save_json_report") as save_json, \
         patch("server.scan_service.generate_pdf_report") as save_pdf:
        service.run_manual_text_scan(
            subject="Sensitive subject", sender="person@example.com", body="sensitive body",
            scan_id="scan-1", source_type="email", retain_content=False,
            metadata={"source": "automatic_protection", "provider": "gmail", "message_id": "m1"},
        )
    saved = repo.complete_scan.call_args.kwargs
    assert saved["subject"] == "Automatically scanned email"
    assert saved["sender"] == "redacted"
    assert saved["report_pdf"] is None and saved["report_json"] is None
    assert "scan_input" not in saved["evidence"]
    assert "sensitive" not in str(saved["evidence"])
    assert saved["evidence"]["final_label"] == "phishing"
    save_json.assert_not_called()
    save_pdf.assert_not_called()
