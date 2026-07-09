from pathlib import Path
from typing import Any
from urllib.parse import urlparse

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
        security_headers_override: dict[str, Any] | None = None,
        auth_context_override: str | None = None,
        original_sender_override: str | None = None,
        link_details_override: list[dict[str, Any]] | None = None,
        source_type: str = "text",
    ) -> dict[str, Any]:
        target_text = clean_extracted_text(body)
        original_sender = extract_original_sender(target_text, forwarder_email=sender)
        if original_sender == "unknown_origin":
            original_sender = sender or "manual_input"
        if original_sender_override:
            original_sender = original_sender_override

        original_headers, auth_context = extract_original_headers(target_text)
        if security_headers_override is not None:
            original_headers = security_headers_override
        if auth_context_override:
            auth_context = auth_context_override
        security_headers = original_headers if auth_context == "original_headers" else {}

        url_details = _merge_url_details(
            extract_urls(target_text),
            link_details_override or [],
        )
        url_flags = analyze_urls(
            [u["normalized_url"] for u in url_details if "normalized_url" in u],
            sender_domain=_sender_domain_from_value(original_sender),
        ) if url_details else []
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
            url_details=url_details,
            source_type=source_type,
            link_evidence_mode=_detect_link_evidence_mode(source_type, url_details),
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
            link_forensics=_build_link_forensics(source_type, url_details, original_sender),
        )
        
        evidence["scan_mode"] = scan_mode
        evidence["degraded"] = degraded
        evidence["scan_input"] = {
            "body_text": target_text,
            "subject": subject,
            "sender": sender,
        }
        evidence["source_type"] = source_type
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

    def run_sms_scan(
        self,
        *,
        text: str,
        sender_number: str | None = None,
        scan_mode: str = "balanced",
        user_id: str = "local",
    ) -> dict[str, Any]:
        target_text = clean_extracted_text(text)
        sender = sender_number or "unknown_sms_sender"
        subject = f"SMS Message from {sender}"

        # SMS doesn't have email headers or auth context
        security_headers = {}
        auth_context = "sms_message"

        url_details = extract_urls(target_text)
        url_flags = analyze_urls([u["normalized_url"] for u in url_details if "normalized_url" in u]) if url_details else []
        for detail in url_details:
            flags = detail.setdefault("flags", [])
            for flag in url_flags:
                if flag not in flags:
                    flags.append(flag)

        result = hybrid_detect(
            subject,
            target_text,
            sender,
            attachment_score=None,
            url_flags=url_flags,
            security_headers=security_headers,
            auth_context=auth_context,
            url_details=url_details,
            source_type="sms",
            link_evidence_mode=_detect_link_evidence_mode("sms", url_details),
        )

        llm_used = bool(result.get("llm_available"))
        degraded = not llm_used and scan_mode in {"balanced", "strict"}

        evidence = build_forensic_evidence(
            subject,
            target_text,
            result,
            attachment_result=None,
            security_headers=security_headers,
            sender_raw=sender,
            forwarder_raw="sms_scanner",
            url_details=url_details,
            auth_context=auth_context,
            link_forensics=_build_link_forensics("sms", url_details, sender),
        )
        
        evidence["scan_mode"] = scan_mode
        evidence["degraded"] = degraded
        evidence["scan_input"] = {
            "body_text": target_text,
            "subject": subject,
            "sender": sender,
        }
        evidence["source_type"] = "sms"

        report_json = save_json_report(evidence)
        report_pdf = generate_pdf_report(evidence)

        scan_id = self.repository.create_scan(
            subject=subject,
            sender=sender,
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

    def run_url_scan(
        self,
        *,
        url: str,
        scan_mode: str = "balanced",
        user_id: str = "local",
    ) -> dict[str, Any]:
        normalized = clean_extracted_text(url)
        subject = f"URL Scan: {normalized}"
        sender = "url_checker"
        body = f"Suspicious URL submitted for analysis:\n{normalized}"

        url_details = extract_urls(body)
        if not url_details:
            raise ValueError("Submitted text did not contain a valid URL")

        url_flags = analyze_urls([u["normalized_url"] for u in url_details if "normalized_url" in u])
        for detail in url_details:
            flags = detail.setdefault("flags", [])
            for flag in url_flags:
                if flag not in flags:
                    flags.append(flag)

        result = hybrid_detect(
            subject,
            body,
            sender,
            attachment_score=None,
            url_flags=url_flags,
            security_headers={},
            auth_context="url_only",
            url_details=url_details,
            source_type="url",
            link_evidence_mode="visible_url",
        )

        llm_used = bool(result.get("llm_available"))
        degraded = not llm_used and scan_mode in {"balanced", "strict"}

        evidence = build_forensic_evidence(
            subject,
            body,
            result,
            attachment_result=None,
            security_headers={},
            sender_raw=sender,
            forwarder_raw="url_checker",
            url_details=url_details,
            auth_context="url_only",
            link_forensics=_build_link_forensics("url", url_details, sender),
        )
        evidence["scan_mode"] = scan_mode
        evidence["degraded"] = degraded
        evidence["scan_input"] = {
            "submitted_url": normalized,
            "body_text": body,
            "subject": subject,
            "sender": sender,
        }
        evidence["source_type"] = "url"

        report_json = save_json_report(evidence)
        report_pdf = generate_pdf_report(evidence)
        scan_id = self.repository.create_scan(
            subject=subject,
            sender=sender,
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


def _sender_domain_from_value(sender: str) -> str:
    if "@" not in (sender or ""):
        return ""
    return sender.split("@")[-1].replace(">", "").strip().lower()


def _merge_url_details(
    extracted_details: list[dict[str, Any]],
    link_overrides: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    merged = {detail.get("normalized_url"): detail for detail in extracted_details if detail.get("normalized_url")}

    for link in link_overrides:
        href = link.get("href") or link.get("normalized_url") or ""
        parsed = urlparse(href)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        normalized = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path or ''}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        record = merged.setdefault(normalized, {
            "raw_url": href,
            "normalized_url": normalized,
            "domain": (parsed.hostname or "").lower(),
            "is_ip": False,
            "is_short": False,
            "flags": [],
            "safebrowsing_hit": False,
        })
        record["anchor_text"] = link.get("anchor_text") or record.get("anchor_text")
        record["href"] = href
        record["href_domain"] = link.get("href_domain") or record.get("href_domain") or record.get("domain")
        record["is_cta"] = bool(link.get("is_cta"))
        record["link_source"] = link.get("link_source", "raw_href")
    return list(merged.values())


def _detect_link_evidence_mode(source_type: str, url_details: list[dict[str, Any]]) -> str:
    if any(detail.get("link_source") == "raw_href" for detail in url_details):
        return "raw_href"
    if url_details:
        return "visible_url"
    if source_type == "screenshot":
        return "none_visible"
    return "none_visible"


def _build_link_forensics(source_type: str, url_details: list[dict[str, Any]], sender: str) -> dict[str, Any]:
    return {
        "link_evidence_mode": _detect_link_evidence_mode(source_type, url_details),
        "cta_texts": [detail.get("anchor_text") for detail in url_details if detail.get("is_cta") and detail.get("anchor_text")],
        "sender_domain": _sender_domain_from_value(sender),
        "destination_domains": [detail.get("href_domain") or detail.get("domain") for detail in url_details if detail.get("href_domain") or detail.get("domain")],
        "final_destination_domains": [detail.get("resolved_domain") for detail in url_details if detail.get("resolved_domain")],
        "brand_match": not any(
            "domain_mismatch" in flag
            for detail in url_details
            for flag in detail.get("flags", [])
        ),
    }
