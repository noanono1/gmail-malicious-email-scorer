from __future__ import annotations

import re

from detection_engine.analyzers.base import BaseAnalyzer
from detection_engine.domain.email import EmailData
from detection_engine.domain.blind_spot_catalog import ATTACHMENT_CONTENT
from detection_engine.domain.enums import SignalCategory, SignalSeverity
from detection_engine.domain.signals import AnalysisOutput, Signal

# .html/.htm kept at CRITICAL — open decision tracked in
# docs/detection-policy.md ("Open decision: .html / .htm severity").
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

    def analyze(self, email: EmailData) -> AnalysisOutput:
        if not email.attachments:
            return AnalysisOutput.empty()

        candidates = (
            self._dangerous_extension_signal(email),
            self._double_extension_signal(email),
            self._macro_enabled_signal(email),
            self._password_protected_archive_signal(email),
        )
        return AnalysisOutput(
            signals=tuple(signal for signal in candidates if signal is not None),
            blind_spots=(ATTACHMENT_CONTENT,),
        )

    def _dangerous_extension_signal(self, email: EmailData) -> Signal | None:
        dangerous_files: list[str] = []
        for attachment in email.attachments:
            extensions = _get_extensions(attachment.filename)
            if extensions and extensions[-1] in _DANGEROUS_EXTENSIONS:
                dangerous_files.append(attachment.filename)

        if not dangerous_files:
            return None
        return Signal(
            id="dangerous_file_extension",
            category=SignalCategory.ATTACHMENT,
            severity=SignalSeverity.CRITICAL,
            confidence=0.95,
            summary=f"Dangerous file type: {', '.join(dangerous_files[:3])}",
        )

    def _double_extension_signal(self, email: EmailData) -> Signal | None:
        double_ext_files: list[str] = []
        for attachment in email.attachments:
            extensions = _get_extensions(attachment.filename)
            if len(extensions) >= 2 and extensions[-1] in _DANGEROUS_EXTENSIONS:
                safe_looking = extensions[-2]
                if safe_looking not in _DANGEROUS_EXTENSIONS:
                    double_ext_files.append(attachment.filename)

        if not double_ext_files:
            return None
        return Signal(
            id="double_file_extension",
            category=SignalCategory.ATTACHMENT,
            severity=SignalSeverity.CRITICAL,
            confidence=1.0,
            summary=f"Double extension masquerading: {', '.join(double_ext_files[:3])}",
        )

    def _macro_enabled_signal(self, email: EmailData) -> Signal | None:
        macro_files: list[str] = []
        for attachment in email.attachments:
            extensions = _get_extensions(attachment.filename)
            if extensions and extensions[-1] in _MACRO_EXTENSIONS:
                macro_files.append(attachment.filename)

        if not macro_files:
            return None
        return Signal(
            id="macro_enabled_document",
            category=SignalCategory.ATTACHMENT,
            severity=SignalSeverity.HIGH,
            confidence=0.85,
            summary=f"Macro-enabled document: {', '.join(macro_files[:3])}",
        )

    def _password_protected_archive_signal(self, email: EmailData) -> Signal | None:
        has_archive = any(
            a.mime_type in _ARCHIVE_MIME_TYPES for a in email.attachments
        )
        if not has_archive:
            return None

        body = f"{email.subject} {email.body_text}".lower()
        if not (_PASSWORD_HINT_PATTERN.search(body) or "password" in body):
            return None

        archive_names = [
            a.filename for a in email.attachments
            if a.mime_type in _ARCHIVE_MIME_TYPES
        ]
        return Signal(
            id="password_protected_archive",
            category=SignalCategory.ATTACHMENT,
            severity=SignalSeverity.HIGH,
            confidence=0.8,
            summary=f"Archive with password hint in body: {', '.join(archive_names[:3])}",
        )
