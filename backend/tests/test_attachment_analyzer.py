"""Unit tests for AttachmentAnalyzer — dangerous extensions, double extensions, macros, password-protected archives."""

from __future__ import annotations

import pytest

from detection_engine.analyzers.attachment import AttachmentAnalyzer
from detection_engine.domain.email import Attachment, EmailData, EmailHeaders
from detection_engine.domain.enums import BlindSpotArea, SignalSeverity
from tests.email_fixtures import (
    EMPTY_MINIMAL,
    LEGIT_AMAZON_ORDER,
    MALWARE_DOUBLE_EXTENSION,
    MALWARE_HTML_ATTACHMENT,
    MALWARE_MACRO_DOC,
    MALWARE_PASSWORD_PROTECTED_ZIP,
    build_email_data,
)


def _make_email(
    attachments: list[Attachment] | None = None,
    subject: str = "Test",
    body_text: str = "",
) -> EmailData:
    return EmailData(
        message_id="test-attach-001",
        sender_address="test@example.com",
        sender_display_name="",
        recipient="user@example.com",
        subject=subject,
        body_text=body_text,
        body_html="",
        attachments=tuple(attachments) if attachments else (),
        headers=EmailHeaders([("From", "test@example.com")]),
    )


def _attachment(
    filename: str,
    mime_type: str = "application/octet-stream",
    size_bytes: int = 1024,
) -> Attachment:
    return Attachment(
        filename=filename,
        mime_type=mime_type,
        size_bytes=size_bytes,
    )


@pytest.fixture
def analyzer() -> AttachmentAnalyzer:
    return AttachmentAnalyzer()


# ---------------------------------------------------------------------------
# ATTACH-1: Dangerous file extensions
# ---------------------------------------------------------------------------


class TestDangerousExtensions:
    @pytest.mark.parametrize("ext", [".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi"])
    def test_common_dangerous_extensions(self, analyzer: AttachmentAnalyzer, ext: str):
        output = analyzer.analyze(_make_email(attachments=[_attachment(f"file{ext}")]))
        signals = [s for s in output.signals if s.id == "dangerous_file_extension"]
        assert len(signals) == 1
        assert signals[0].severity == SignalSeverity.CRITICAL

    def test_html_attachment_flagged(self, analyzer: AttachmentAnalyzer):
        output = analyzer.analyze(_make_email(attachments=[_attachment("page.html")]))
        assert [s for s in output.signals if s.id == "dangerous_file_extension"]

    def test_safe_extension_not_flagged(self, analyzer: AttachmentAnalyzer):
        output = analyzer.analyze(_make_email(attachments=[_attachment("report.pdf")]))
        assert not [s for s in output.signals if s.id == "dangerous_file_extension"]

    def test_docx_not_flagged(self, analyzer: AttachmentAnalyzer):
        output = analyzer.analyze(_make_email(attachments=[_attachment("doc.docx")]))
        assert not [s for s in output.signals if s.id == "dangerous_file_extension"]

    def test_multiple_dangerous_reported_together(self, analyzer: AttachmentAnalyzer):
        attachments = [_attachment("a.exe"), _attachment("b.bat")]
        output = analyzer.analyze(_make_email(attachments=attachments))
        signals = [s for s in output.signals if s.id == "dangerous_file_extension"]
        assert len(signals) == 1
        assert "a.exe" in signals[0].summary
        assert "b.bat" in signals[0].summary


# ---------------------------------------------------------------------------
# ATTACH-2: Double file extensions
# ---------------------------------------------------------------------------


class TestDoubleExtensions:
    def test_pdf_exe_flagged(self, analyzer: AttachmentAnalyzer):
        output = analyzer.analyze(_make_email(attachments=[_attachment("invoice.pdf.exe")]))
        signals = [s for s in output.signals if s.id == "double_file_extension"]
        assert len(signals) == 1
        assert signals[0].severity == SignalSeverity.CRITICAL
        assert signals[0].confidence == 1.0

    def test_doc_scr_flagged(self, analyzer: AttachmentAnalyzer):
        output = analyzer.analyze(_make_email(attachments=[_attachment("report.doc.scr")]))
        assert [s for s in output.signals if s.id == "double_file_extension"]

    def test_tar_gz_not_flagged(self, analyzer: AttachmentAnalyzer):
        output = analyzer.analyze(_make_email(attachments=[_attachment("archive.tar.gz")]))
        assert not [s for s in output.signals if s.id == "double_file_extension"]

    def test_single_dangerous_not_double(self, analyzer: AttachmentAnalyzer):
        output = analyzer.analyze(_make_email(attachments=[_attachment("malware.exe")]))
        assert not [s for s in output.signals if s.id == "double_file_extension"]

    def test_two_dangerous_extensions_not_flagged(self, analyzer: AttachmentAnalyzer):
        output = analyzer.analyze(_make_email(attachments=[_attachment("payload.bat.exe")]))
        assert not [s for s in output.signals if s.id == "double_file_extension"]


# ---------------------------------------------------------------------------
# ATTACH-3: Macro-enabled documents
# ---------------------------------------------------------------------------


class TestMacroEnabled:
    @pytest.mark.parametrize("ext", [".docm", ".xlsm", ".pptm"])
    def test_macro_extensions_flagged(self, analyzer: AttachmentAnalyzer, ext: str):
        output = analyzer.analyze(_make_email(attachments=[_attachment(f"file{ext}")]))
        signals = [s for s in output.signals if s.id == "macro_enabled_document"]
        assert len(signals) == 1
        assert signals[0].severity == SignalSeverity.HIGH

    def test_docx_not_flagged_as_macro(self, analyzer: AttachmentAnalyzer):
        output = analyzer.analyze(_make_email(attachments=[_attachment("file.docx")]))
        assert not [s for s in output.signals if s.id == "macro_enabled_document"]

    def test_xlsx_not_flagged_as_macro(self, analyzer: AttachmentAnalyzer):
        output = analyzer.analyze(_make_email(attachments=[_attachment("file.xlsx")]))
        assert not [s for s in output.signals if s.id == "macro_enabled_document"]


# ---------------------------------------------------------------------------
# ATTACH-4: Password-protected archive
# ---------------------------------------------------------------------------


class TestPasswordProtectedArchive:
    def test_zip_with_password_in_body(self, analyzer: AttachmentAnalyzer):
        output = analyzer.analyze(_make_email(
            attachments=[_attachment("data.zip", mime_type="application/zip")],
            body_text="The password is: secret123",
        ))
        signals = [s for s in output.signals if s.id == "password_protected_archive"]
        assert len(signals) == 1
        assert signals[0].severity == SignalSeverity.HIGH

    def test_zip_with_password_in_subject(self, analyzer: AttachmentAnalyzer):
        output = analyzer.analyze(_make_email(
            attachments=[_attachment("data.zip", mime_type="application/zip")],
            subject="Files attached (password: abc)",
        ))
        assert [s for s in output.signals if s.id == "password_protected_archive"]

    def test_zip_without_password_not_flagged(self, analyzer: AttachmentAnalyzer):
        output = analyzer.analyze(_make_email(
            attachments=[_attachment("data.zip", mime_type="application/zip")],
            body_text="Please see the attached files.",
        ))
        assert not [s for s in output.signals if s.id == "password_protected_archive"]

    def test_non_archive_with_password_not_flagged(self, analyzer: AttachmentAnalyzer):
        output = analyzer.analyze(_make_email(
            attachments=[_attachment("report.pdf")],
            body_text="The password is: secret123",
        ))
        assert not [s for s in output.signals if s.id == "password_protected_archive"]

    def test_rar_archive_detected(self, analyzer: AttachmentAnalyzer):
        output = analyzer.analyze(_make_email(
            attachments=[_attachment("data.rar", mime_type="application/x-rar-compressed")],
            body_text="password: test",
        ))
        assert [s for s in output.signals if s.id == "password_protected_archive"]


# ---------------------------------------------------------------------------
# Blind spots and edge cases
# ---------------------------------------------------------------------------


class TestBlindSpotsAndEdgeCases:
    def test_attachment_content_blind_spot(self, analyzer: AttachmentAnalyzer):
        output = analyzer.analyze(_make_email(attachments=[_attachment("report.pdf")]))
        areas = [bs.area for bs in output.blind_spots]
        assert BlindSpotArea.ATTACHMENT_CONTENT in areas

    def test_no_attachments_returns_empty(self, analyzer: AttachmentAnalyzer):
        output = analyzer.analyze(_make_email())
        assert len(output.signals) == 0
        assert len(output.blind_spots) == 0

# ---------------------------------------------------------------------------
# Real fixtures
# ---------------------------------------------------------------------------


class TestRealFixtures:
    def test_malware_double_extension(self, analyzer: AttachmentAnalyzer):
        email = build_email_data(MALWARE_DOUBLE_EXTENSION["email"])
        output = analyzer.analyze(email)
        ids = {s.id for s in output.signals}
        assert "double_file_extension" in ids
        assert "dangerous_file_extension" in ids

    def test_malware_macro_doc(self, analyzer: AttachmentAnalyzer):
        email = build_email_data(MALWARE_MACRO_DOC["email"])
        output = analyzer.analyze(email)
        ids = {s.id for s in output.signals}
        assert "macro_enabled_document" in ids

    def test_malware_password_protected_zip(self, analyzer: AttachmentAnalyzer):
        email = build_email_data(MALWARE_PASSWORD_PROTECTED_ZIP["email"])
        output = analyzer.analyze(email)
        ids = {s.id for s in output.signals}
        assert "password_protected_archive" in ids

    def test_malware_html_attachment(self, analyzer: AttachmentAnalyzer):
        email = build_email_data(MALWARE_HTML_ATTACHMENT["email"])
        output = analyzer.analyze(email)
        ids = {s.id for s in output.signals}
        assert "dangerous_file_extension" in ids

    def test_legit_amazon_no_attachment_signals(self, analyzer: AttachmentAnalyzer):
        email = build_email_data(LEGIT_AMAZON_ORDER["email"])
        output = analyzer.analyze(email)
        assert len(output.signals) == 0

    def test_empty_minimal(self, analyzer: AttachmentAnalyzer):
        email = build_email_data(EMPTY_MINIMAL["email"])
        output = analyzer.analyze(email)
        assert len(output.signals) == 0
