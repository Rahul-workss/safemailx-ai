import logging
from server.schemas import (
    InstantEmailScanRequest, InstantScanResult, InstantSmsScanRequest, InstantUrlScanRequest
)
from engines.smart_veto import SmartVetoOrchestrator

logger = logging.getLogger("INLINE_SCANNER")

class InlineScanService:
    def __init__(self, repository):
        self.repository = repository
        self.orchestrator = SmartVetoOrchestrator()

    def _save_to_repo(self, result: InstantScanResult, subject: str, sender: str, user_id: str) -> None:
        scan_id = self.repository.create_scan(
            subject=subject,
            sender=sender,
            final_label=result.verdict,
            final_score=result.risk_score / 100.0,
            llm_used=bool(result.llm_reasoning),
            degraded=result.degraded,
            evidence={
                "summary": result.summary,
                "confidence": result.confidence,
                "top_signals": [s.model_dump() for s in result.top_signals] if result.top_signals and hasattr(result.top_signals[0], "model_dump") else (result.top_signals or []),
                "llm_reasoning": result.llm_reasoning,
                "artifacts": result.artifacts.model_dump() if hasattr(result.artifacts, "model_dump") else result.artifacts,
                "recommended_action": result.recommended_action,
                "evidence_quality": result.evidence_quality,
                "analysis_mode": result.analysis_mode,
                "external_checks_used": list(result.external_checks_used or []),
                "external_checks_failed": list(result.external_checks_failed or []),
                "degraded_reasons": list(result.degraded_reasons or []),
                "privacy_notice": result.privacy_notice,
                "scan_category": result.scan_category,
            },
            report_pdf=None,
            report_json=None,
            user_id=user_id,
        )
        result.scan_id = scan_id
        result.saved_to_history = True

    def scan_sms(self, request: InstantSmsScanRequest, user_id: str) -> InstantScanResult:
        logger.info(f"Scanning SMS via SMART VETO for user {user_id}")
        result = self.orchestrator.process_sms_scan(
            request.text,
            sender=request.sender_number,
            scan_mode=request.scan_mode,
        )
        self._save_to_repo(result, subject="Instant SMS Scan", sender=request.sender_number or "unknown_sender", user_id=user_id)
        return result

    def scan_url(self, request: InstantUrlScanRequest, user_id: str) -> InstantScanResult:
        logger.info("Scanning URL via SMART VETO for user %s", user_id)
        result = self.orchestrator.process_url_scan(str(request.url), scan_mode=request.scan_mode)
        self._save_to_repo(result, subject="Instant URL Scan", sender="url_scanner", user_id=user_id)
        return result

    def scan_file(
        self,
        filename: str,
        content_type: str,
        file_bytes: bytes,
        user_id: str,
        *,
        subject: str | None = None,
        sender: str | None = None,
        scan_mode: str = "balanced",
    ) -> InstantScanResult:
        logger.info(f"Scanning File via SMART VETO for user {user_id}: {filename}")
        result = self.orchestrator.process_file_scan(filename, content_type, file_bytes, scan_mode=scan_mode)
        self._save_to_repo(
            result,
            subject=subject or f"File Scan: {filename}",
            sender=sender or "file_scanner",
            user_id=user_id,
        )
        return result

    def scan_email(self, request: InstantEmailScanRequest, user_id: str) -> InstantScanResult:
        """Direct email body scan via SmartVetoOrchestrator (Qwen 3 + rules).
        This is the instant path — Gmail label scans go through the worker queue instead.
        """
        logger.info("Scanning Email via SMART VETO for user %s", user_id)
        result = self.orchestrator.process_email_scan(
            body=request.body,
            subject=request.subject,
            sender=request.sender,
            scan_mode=request.scan_mode,
        )
        self._save_to_repo(
            result,
            subject=request.subject or "Instant Email Scan",
            sender=request.sender or "unknown_sender",
            user_id=user_id,
        )
        return result
