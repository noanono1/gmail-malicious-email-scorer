"""Unit tests for AuthenticationAnalyzer — parsing correctness and signal emission."""

from __future__ import annotations

import pytest

from detection_engine.analyzers.authentication import AuthenticationAnalyzer
from detection_engine.domain.email import EmailData, EmailHeaders
from detection_engine.domain.enums import (
    BlindSpotArea,
    SignalCategory,
    SignalSeverity,
)
from tests.email_fixtures import (
    LEGIT_AMAZON_ORDER,
    MASS_PHISHING,
    build_email_data,
)


def _make_email(auth_results: str | None) -> EmailData:
    header_pairs = [("From", "test@example.com"), ("To", "user@example.com")]
    if auth_results is not None:
        header_pairs.append(("Authentication-Results", auth_results))
    return EmailData(
        message_id="test-001",
        sender_address="test@example.com",
        sender_display_name="",
        recipient="user@example.com",
        subject="Test",
        body_text="",
        body_html="",
        headers=EmailHeaders(header_pairs),
    )


@pytest.fixture
def analyzer() -> AuthenticationAnalyzer:
    return AuthenticationAnalyzer()


class TestAllAuthFail:
    def test_emits_three_signals(self, analyzer: AuthenticationAnalyzer):
        email = _make_email(
            "mx.example.com; spf=fail smtp.mailfrom=evil.com; "
            "dkim=fail header.d=evil.com; dmarc=fail header.from=evil.com"
        )
        output = analyzer.analyze(email)
        assert len(output.signals) == 3
        assert len(output.blind_spots) == 0

    def test_signal_ids(self, analyzer: AuthenticationAnalyzer):
        email = _make_email(
            "mx.example.com; spf=fail; dkim=fail; dmarc=fail"
        )
        output = analyzer.analyze(email)
        ids = {s.id for s in output.signals}
        assert ids == {"spf_fail", "dkim_fail", "dmarc_fail"}

    def test_severities(self, analyzer: AuthenticationAnalyzer):
        email = _make_email("mx.example.com; spf=fail; dkim=fail; dmarc=fail")
        output = analyzer.analyze(email)
        by_id = {s.id: s for s in output.signals}
        assert by_id["spf_fail"].severity == SignalSeverity.HIGH
        assert by_id["dkim_fail"].severity == SignalSeverity.HIGH
        assert by_id["dmarc_fail"].severity == SignalSeverity.CRITICAL

    def test_confidences_are_one(self, analyzer: AuthenticationAnalyzer):
        email = _make_email("mx.example.com; spf=fail; dkim=fail; dmarc=fail")
        output = analyzer.analyze(email)
        assert all(s.confidence == 1.0 for s in output.signals)


class TestAllAuthPass:
    def test_no_signals(self, analyzer: AuthenticationAnalyzer):
        email = _make_email(
            "mx.google.com; spf=pass smtp.mailfrom=good.com; "
            "dkim=pass header.d=good.com; dmarc=pass header.from=good.com"
        )
        output = analyzer.analyze(email)
        assert len(output.signals) == 0
        assert len(output.blind_spots) == 0


class TestSoftfail:
    def test_spf_softfail_signal(self, analyzer: AuthenticationAnalyzer):
        email = _make_email("mx.example.com; spf=softfail; dkim=pass; dmarc=pass")
        output = analyzer.analyze(email)
        assert len(output.signals) == 1
        signal = output.signals[0]
        assert signal.id == "spf_softfail"
        assert signal.severity == SignalSeverity.HIGH
        assert signal.confidence == 0.7


class TestNoneResults:
    def test_dkim_none(self, analyzer: AuthenticationAnalyzer):
        email = _make_email("mx.example.com; spf=pass; dkim=none; dmarc=pass")
        output = analyzer.analyze(email)
        assert len(output.signals) == 1
        assert output.signals[0].id == "dkim_none"
        assert output.signals[0].confidence == 0.8

    def test_dmarc_none(self, analyzer: AuthenticationAnalyzer):
        email = _make_email("mx.example.com; spf=pass; dkim=pass; dmarc=none")
        output = analyzer.analyze(email)
        assert len(output.signals) == 1
        assert output.signals[0].id == "dmarc_none"
        assert output.signals[0].severity == SignalSeverity.CRITICAL
        assert output.signals[0].confidence == 0.8


class TestMissingAuthHeader:
    def test_returns_blind_spot(self, analyzer: AuthenticationAnalyzer):
        email = _make_email(None)
        output = analyzer.analyze(email)
        assert len(output.signals) == 0
        assert len(output.blind_spots) == 1
        assert output.blind_spots[0].area == BlindSpotArea.AUTHENTICATION_HEADERS


class TestMalformedAuthHeader:
    def test_garbage_produces_no_signals(self, analyzer: AuthenticationAnalyzer):
        email = _make_email("completely garbage value with no structure")
        output = analyzer.analyze(email)
        assert len(output.signals) == 0
        assert len(output.blind_spots) == 0


class TestPartialResults:
    def test_missing_method_is_not_failure(self, analyzer: AuthenticationAnalyzer):
        email = _make_email("mx.example.com; spf=pass; dmarc=fail")
        output = analyzer.analyze(email)
        assert len(output.signals) == 1
        assert output.signals[0].id == "dmarc_fail"


class TestScoreContributionIsZero:
    def test_all_signals_have_zero_contribution(self, analyzer: AuthenticationAnalyzer):
        email = _make_email("mx.example.com; spf=fail; dkim=fail; dmarc=fail")
        output = analyzer.analyze(email)
        assert all(s.score_contribution == 0.0 for s in output.signals)


class TestRealFixtures:
    def test_mass_phishing(self, analyzer: AuthenticationAnalyzer):
        email = build_email_data(MASS_PHISHING["email"])
        output = analyzer.analyze(email)
        assert len(output.signals) == 3
        ids = {s.id for s in output.signals}
        assert ids == {"spf_fail", "dkim_fail", "dmarc_fail"}

    def test_legit_amazon(self, analyzer: AuthenticationAnalyzer):
        email = build_email_data(LEGIT_AMAZON_ORDER["email"])
        output = analyzer.analyze(email)
        assert len(output.signals) == 0
        assert len(output.blind_spots) == 0


class TestCategoryIsAuthentication:
    def test_all_signals_tagged_correctly(self, analyzer: AuthenticationAnalyzer):
        email = _make_email("mx.example.com; spf=fail; dkim=fail; dmarc=fail")
        output = analyzer.analyze(email)
        assert all(s.category == SignalCategory.AUTHENTICATION for s in output.signals)
