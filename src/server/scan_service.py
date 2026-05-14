from pathlib import Path
from typing import Any

from engines.attachment_analyzer import analyze_attachments
from engines.hybrid_engine import hybrid_detect
from engines.url_analyzer import analyze_urls
from utils.evidence_builder import build_forensic_evidence
from utils.forwarding_parser import extract_original_headers, extract_original_sender
from utils.json_report import save_json_report
from utils.pdf_report import generate_pdf_report
from utils.url_extractor import extract_urls
from utils.content_processor import clean_extracted_text

from server.repository import ScanRepository


SCAN_STAGES = [
    "intake",
    "text_extraction",
    "url_analysis",
    "attachment_analysis",
    "qwen_reasoning",
    "hybrid_scoring",
    "report_generation",
]


class ScanService:
    def __init__(self, repository: ScanRepository | None = None) -> None:
        self.repository = repository or ScanRepository()

    def run_manual_text_scan(
        self,
        *,
        subject: str,
        sender: str,
        body: str,
        scan_mode: str = "balanced",
        attachments: list[dict[str, Any]] | None = None,
        scan_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        user_id: str = "local",
    ) -> dict[str, Any]:
        target_text = clean_extracted_text(body)
        original_sender = extract_original_sender(target_text)
        if original_sender == "unknown_origin":
            original_sender = sender or "manual_input"

        original_headers, auth_context = extract_original_headers(target_text)
        security_headers = original_headers if auth_context == "original_headers" else {}

        url_details = extract_urls(target_text)
        url_flags = analyze_urls(url_details) if url_details else []
        for detail in url_details:
            flags = detail.setdefault("flags", [])
            for flag in url_flags:
                if flag not in flags:
                    flags.append(flag)

        attachment_result = {"attachment_score": None, "attachment_findings": []}
        if attachments:
            attachment_result = analyze_attachments(attachments)

        result = hybrid_detect(
            subject,
            target_text,
            original_sender,
            attachment_score=attachment_result.get("attachment_score"),
            url_flags=url_flags,
            security_headers=security_headers,
            auth_context=auth_context,
        )

        llm_used = bool(result.get("llm_available"))
        degraded = not llm_used and scan_mode in {"balanced", "strict"}

        evidence = build_forensic_evidence(
            subject,
            target_text,
            result,
            attachment_result=attachment_result,
            security_headers=security_headers,
            sender_raw=original_sender,
            forwarder_raw=sender,
            url_details=url_details,
            auth_context=auth_context,
        )
        evidence["scan_mode"] = scan_mode
        evidence["degraded"] = degraded
        evidence["scan_input"] = {
            "body_text": target_text,
            "subject": subject,
            "sender": sender,
        }
        if metadata:
            evidence.update(metadata)

        report_json = save_json_report(evidence)
        report_pdf = generate_pdf_report(evidence)

        if scan_id:
            self.repository.complete_scan(
                scan_id,
                subject=subject,
                sender=original_sender,
                final_label=result["final_label"],
                final_score=result["final_score"],
                llm_used=llm_used,
                degraded=degraded,
                evidence=evidence,
                report_pdf=str(Path(report_pdf)),
                report_json=str(Path(report_json)),
            )
        else:
            scan_id = self.repository.create_scan(
                subject=subject,
                sender=original_sender,
                final_label=result["final_label"],
                final_score=result["final_score"],
                llm_used=llm_used,
                degraded=degraded,
                evidence=evidence,
                report_pdf=str(Path(report_pdf)),
                report_json=str(Path(report_json)),
                user_id=user_id,
            )

        return self.repository.get_scan(scan_id)
