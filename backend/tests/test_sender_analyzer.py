"""Unit tests for SenderAnalyzer — cousin domains, freemail, reply-to, return-path."""

from __future__ import annotations

import pytest

from detection_engine.analyzers.sender import (
    SenderAnalyzer,
    _extract_display_name,
    _extract_domain,
    _levenshtein,
    _normalize,
)
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
    sender: str = "test@example.com",
    headers: list[tuple[str, str]] | None = None,
) -> EmailData:
    if headers is None:
        headers = [("From", sender), ("To", "user@example.com")]
    return EmailData(
        message_id="test-001",
        sender=sender,
        recipient="user@example.com",
        subject="Test",
        body_text="",
        body_html="",
        headers=EmailHeaders(headers),
    )


@pytest.fixture
def analyzer() -> SenderAnalyzer:
    return SenderAnalyzer()


# ---------------------------------------------------------------------------
# SENDER-1: Cousin domain detection
# ---------------------------------------------------------------------------


class TestCousinDomain:
    def test_paypal_lookalike_with_digit(self, analyzer: SenderAnalyzer):
        email = _make_email(sender="user@paypa1-support.com")
        output = analyzer.analyze(email)
        cousin = [s for s in output.signals if s.id == "cousin_domain"]
        assert len(cousin) == 1
        assert cousin[0].severity == SignalSeverity.CRITICAL
        assert "paypal" in cousin[0].evidence

    def test_amazon_lookalike_with_rn(self, analyzer: SenderAnalyzer):
        email = _make_email(sender="user@arnazon.com")
        output = analyzer.analyze(email)
        cousin = [s for s in output.signals if s.id == "cousin_domain"]
        assert len(cousin) == 1
        assert "amazon" in cousin[0].evidence

    def test_legitimate_brand_not_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(sender="user@paypal.com")
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "cousin_domain"]

    def test_legitimate_subdomain_not_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(sender="user@mail.paypal.com")
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "cousin_domain"]

    def test_unrelated_domain_not_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(sender="user@totally-unrelated.com")
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "cousin_domain"]

    def test_confidence_exact_after_normalization(self, analyzer: SenderAnalyzer):
        email = _make_email(sender="user@paypa1.com")
        output = analyzer.analyze(email)
        signal = [s for s in output.signals if s.id == "cousin_domain"][0]
        assert signal.confidence == 1.0

    def test_only_one_cousin_signal_per_email(self, analyzer: SenderAnalyzer):
        email = _make_email(sender="user@paypa1.com")
        output = analyzer.analyze(email)
        assert len([s for s in output.signals if s.id == "cousin_domain"]) == 1


# ---------------------------------------------------------------------------
# SENDER-2: Freemail with organizational display name
# ---------------------------------------------------------------------------


class TestFreemailOrgName:
    def test_freemail_with_org_keyword(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender="fake@gmail.com",
            headers=[
                ("From", '"PayPal Security" <fake@gmail.com>'),
                ("To", "user@example.com"),
            ],
        )
        output = analyzer.analyze(email)
        freemail = [s for s in output.signals if s.id == "freemail_org_name"]
        assert len(freemail) == 1
        assert freemail[0].severity == SignalSeverity.MEDIUM

    def test_freemail_without_display_name(self, analyzer: SenderAnalyzer):
        email = _make_email(sender="user@gmail.com")
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "freemail_org_name"]

    def test_freemail_with_personal_name(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender="john@gmail.com",
            headers=[
                ("From", '"John Smith" <john@gmail.com>'),
                ("To", "user@example.com"),
            ],
        )
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "freemail_org_name"]

    def test_non_freemail_with_org_name(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender="user@company.com",
            headers=[
                ("From", '"IT Security" <user@company.com>'),
                ("To", "user@example.com"),
            ],
        )
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "freemail_org_name"]


# ---------------------------------------------------------------------------
# SENDER-3: Reply-To mismatch
# ---------------------------------------------------------------------------


class TestReplyToMismatch:
    def test_different_domain_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender="user@company.com",
            headers=[
                ("From", "user@company.com"),
                ("To", "recipient@example.com"),
                ("Reply-To", "secret@different.com"),
            ],
        )
        output = analyzer.analyze(email)
        mismatch = [s for s in output.signals if s.id == "reply_to_mismatch"]
        assert len(mismatch) == 1
        assert mismatch[0].severity == SignalSeverity.HIGH

    def test_same_domain_not_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender="user@company.com",
            headers=[
                ("From", "user@company.com"),
                ("To", "recipient@example.com"),
                ("Reply-To", "other@company.com"),
            ],
        )
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "reply_to_mismatch"]

    def test_absent_reply_to_not_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(sender="user@company.com")
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "reply_to_mismatch"]


# ---------------------------------------------------------------------------
# SENDER-4: Return-Path mismatch (ESP-aware)
# ---------------------------------------------------------------------------


class TestReturnPathMismatch:
    def test_different_non_esp_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender="user@company.com",
            headers=[
                ("From", "user@company.com"),
                ("To", "recipient@example.com"),
                ("Return-Path", "bounce@shady.xyz"),
            ],
        )
        output = analyzer.analyze(email)
        rp = [s for s in output.signals if s.id == "return_path_mismatch"]
        assert len(rp) == 1
        assert rp[0].severity == SignalSeverity.MEDIUM

    def test_esp_return_path_not_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender="user@company.com",
            headers=[
                ("From", "user@company.com"),
                ("To", "recipient@example.com"),
                ("Return-Path", "bounces@em.sendgrid.net"),
            ],
        )
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "return_path_mismatch"]

    def test_amazonses_not_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender="user@amazon.com",
            headers=[
                ("From", "user@amazon.com"),
                ("To", "recipient@example.com"),
                ("Return-Path", "bounce@amazonses.com"),
            ],
        )
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "return_path_mismatch"]

    def test_same_domain_not_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender="user@company.com",
            headers=[
                ("From", "user@company.com"),
                ("To", "recipient@example.com"),
                ("Return-Path", "noreply@company.com"),
            ],
        )
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "return_path_mismatch"]


# ---------------------------------------------------------------------------
# Score contribution
# ---------------------------------------------------------------------------


class TestScoreContribution:
    def test_all_signals_have_zero_contribution(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender="user@paypa1.com",
            headers=[
                ("From", "user@paypa1.com"),
                ("To", "recipient@example.com"),
                ("Reply-To", "secret@evil.com"),
                ("Return-Path", "bounce@shady.xyz"),
            ],
        )
        output = analyzer.analyze(email)
        assert len(output.signals) > 0
        assert all(s.score_contribution == 0.0 for s in output.signals)


# ---------------------------------------------------------------------------
# Real fixtures
# ---------------------------------------------------------------------------


class TestRealFixtures:
    def test_mass_phishing(self, analyzer: SenderAnalyzer):
        email = build_email_data(MASS_PHISHING["email"])
        output = analyzer.analyze(email)
        ids = {s.id for s in output.signals}
        assert "cousin_domain" in ids
        assert "return_path_mismatch" in ids

    def test_legit_amazon(self, analyzer: SenderAnalyzer):
        email = build_email_data(LEGIT_AMAZON_ORDER["email"])
        output = analyzer.analyze(email)
        assert len(output.signals) == 0

    def test_bec_reply_to_mismatch(self, analyzer: SenderAnalyzer):
        email = build_email_data(BEC_WIRE_TRANSFER["email"])
        output = analyzer.analyze(email)
        ids = {s.id for s in output.signals}
        assert "reply_to_mismatch" in ids

    def test_spear_phish_cousin_domain(self, analyzer: SenderAnalyzer):
        email = build_email_data(SPEAR_PHISH_COUSIN_DOMAIN["email"])
        output = analyzer.analyze(email)
        ids = {s.id for s in output.signals}
        assert "cousin_domain" in ids

    def test_legit_marketing(self, analyzer: SenderAnalyzer):
        email = build_email_data(LEGIT_MARKETING["email"])
        output = analyzer.analyze(email)
        assert len(output.signals) == 0

    def test_malware_no_sender_signals(self, analyzer: SenderAnalyzer):
        email = build_email_data(MALWARE_ATTACHMENT["email"])
        output = analyzer.analyze(email)
        assert len(output.signals) == 0

    def test_empty_minimal(self, analyzer: SenderAnalyzer):
        email = build_email_data(EMPTY_MINIMAL["email"])
        output = analyzer.analyze(email)
        assert len(output.signals) == 0


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_extract_domain_bare(self):
        assert _extract_domain("user@example.com") == "example.com"

    def test_extract_domain_angle_brackets(self):
        assert _extract_domain("<user@example.com>") == "example.com"

    def test_extract_domain_display_name(self):
        assert _extract_domain('"Name" <user@example.com>') == "example.com"

    def test_extract_domain_invalid(self):
        assert _extract_domain("not-an-email") is None

    def test_levenshtein_identical(self):
        assert _levenshtein("paypal", "paypal") == 0

    def test_levenshtein_one_substitution(self):
        assert _levenshtein("paypal", "paypol") == 1

    def test_levenshtein_one_insertion(self):
        assert _levenshtein("paypal", "paypall") == 1

    def test_levenshtein_arnazon_amazon(self):
        assert _levenshtein("arnazon", "amazon") == 2

    def test_normalize_digit_one(self):
        assert _normalize("paypa1") == "paypal"

    def test_normalize_rn_to_m(self):
        assert _normalize("arnazon") == "amazon"

    def test_normalize_digit_zero(self):
        assert _normalize("g00gle") == "google"

    def test_display_name_quoted(self):
        assert _extract_display_name('"John Smith" <john@x.com>') == "John Smith"

    def test_display_name_unquoted(self):
        assert _extract_display_name("John Smith <john@x.com>") == "John Smith"

    def test_display_name_bare_email(self):
        assert _extract_display_name("john@x.com") is None
