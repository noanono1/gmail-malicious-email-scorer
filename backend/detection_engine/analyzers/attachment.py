from __future__ import annotations

import re

from detection_engine.analyzers.base import BaseAnalyzer
from detection_engine.domain.email import EmailData
from detection_engine.domain.enums import BlindSpotArea, SignalCategory, SignalSeverity
from detection_engine.domain.signals import BlindSpot, AnalysisOutput, Signal

_DANGEROUS_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi",
    ".com", ".pif", ".hta", ".wsf", ".cpl", ".reg",
    ".html", ".htm",
})

_MACRO_EXTENSIONS: frozenset[str] = frozenset({
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm",
})

_ARCHIVE_MIME_TYPES: frozenset[str] = frozenset({
    "application/zip",
    "application/x-rar-compressed",
    "application/vnd.rar",
    "application/x-7z-compressed",
    "application/gzip",
})

_PASSWORD_HINT_PATTERN = re.compile(
    r"password\s*[:=\-–—is]\s*\S+", re.IGNORECASE
)


def _get_extensions(filename: str) -> list[str]:
    parts = filename.rsplit("/", 1)[-1].split(".")
    if len(parts) <= 1:
        return []
    return [f".{ext.lower()}" for ext in parts[1:]]


class AttachmentAnalyzer(BaseAnalyzer):

    @property
    def name(self) -> str:
        return "attachment_analyzer"

    @property
    def category(self) -> SignalCategory:
        return SignalCategory.ATTACHMENT

    def analyze(self, email: EmailData) -> AnalysisOutput:
        if not email.attachments:
            return AnalysisOutput.empty()

        signals: list[Signal] = []

        self._check_dangerous_extensions(email, signals)
        self._check_double_extensions(email, signals)
        self._check_macro_enabled(email, signals)
        self._check_password_protected_archive(email, signals)

        blind_spots = (
            BlindSpot(
                area=BlindSpotArea.ATTACHMENT_CONTENT,
                reason="Attachment content not inspected — metadata-only analysis",
                risk_note="File content could contain malicious code undetectable by extension checks",
            ),
        )

        return AnalysisOutput(signals=tuple(signals), blind_spots=blind_spots)

    def _check_dangerous_extensions(
        self, email: EmailData, signals: list[Signal]
    ) -> None:
        dangerous_files: list[str] = []
        for attachment in email.attachments:
            extensions = _get_extensions(attachment.filename)
            if extensions and extensions[-1] in _DANGEROUS_EXTENSIONS:
                dangerous_files.append(attachment.filename)

        if dangerous_files:
            signals.append(
                Signal(
                    id="dangerous_file_extension",
                    category=SignalCategory.ATTACHMENT,
                    severity=SignalSeverity.CRITICAL,
                    confidence=0.95,
                    evidence=f"Dangerous file type: {', '.join(dangerous_files[:3])}",
                )
            )

    def _check_double_extensions(
        self, email: EmailData, signals: list[Signal]
    ) -> None:
        double_ext_files: list[str] = []
        for attachment in email.attachments:
            extensions = _get_extensions(attachment.filename)
            if len(extensions) >= 2 and extensions[-1] in _DANGEROUS_EXTENSIONS:
                safe_looking = extensions[-2]
                if safe_looking not in _DANGEROUS_EXTENSIONS:
                    double_ext_files.append(attachment.filename)

        if double_ext_files:
            signals.append(
                Signal(
                    id="double_file_extension",
                    category=SignalCategory.ATTACHMENT,
                    severity=SignalSeverity.CRITICAL,
                    confidence=1.0,
                    evidence=f"Double extension masquerading: {', '.join(double_ext_files[:3])}",
                )
            )

    def _check_macro_enabled(
        self, email: EmailData, signals: list[Signal]
    ) -> None:
        macro_files: list[str] = []
        for attachment in email.attachments:
            extensions = _get_extensions(attachment.filename)
            if extensions and extensions[-1] in _MACRO_EXTENSIONS:
                macro_files.append(attachment.filename)

        if macro_files:
            signals.append(
                Signal(
                    id="macro_enabled_document",
                    category=SignalCategory.ATTACHMENT,
                    severity=SignalSeverity.HIGH,
                    confidence=0.85,
                    evidence=f"Macro-enabled document: {', '.join(macro_files[:3])}",
                )
            )

    def _check_password_protected_archive(
        self, email: EmailData, signals: list[Signal]
    ) -> None:
        has_archive = any(
            a.mime_type in _ARCHIVE_MIME_TYPES for a in email.attachments
        )
        if not has_archive:
            return

        body = f"{email.subject} {email.body_text}".lower()
        if _PASSWORD_HINT_PATTERN.search(body) or "password" in body:
            archive_names = [
                a.filename for a in email.attachments if a.mime_type in _ARCHIVE_MIME_TYPES
            ]
            signals.append(
                Signal(
                    id="password_protected_archive",
                    category=SignalCategory.ATTACHMENT,
                    severity=SignalSeverity.HIGH,
                    confidence=0.8,
                    evidence=f"Archive with password hint in body: {', '.join(archive_names[:3])}",
                )
            )
