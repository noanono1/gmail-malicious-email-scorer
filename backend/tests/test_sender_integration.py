"""Integration tests — AuthenticationAnalyzer + SenderAnalyzer through the engine."""

from __future__ import annotations

import pytest

from detection_engine import DetectionEngine, SignalCategory, Verdict
from detection_engine.analyzers.authentication import AuthenticationAnalyzer
from detection_engine.analyzers.sender import SenderAnalyzer
from tests.email_fixtures import (
    ALL_FIXTURES,
    BEC_WIRE_TRANSFER,
    EMPTY_MINIMAL,
    LEGIT_AMAZON_ORDER,
    LEGIT_MARKETING,
    MALWARE_ATTACHMENT,
    MASS_PHISHING,
    SPEAR_PHISH_COUSIN_DOMAIN,
    build_email_data,
)


def _engine() -> DetectionEngine:
    return DetectionEngine(
        analyzers=[AuthenticationAnalyzer(), SenderAnalyzer()], intel_sources=[]
    )


class TestMassPhishingCrossCategory:
    """Auth failures + cousin domain + return-path → cross-category boost → MALICIOUS."""

    def test_verdict_is_malicious(self):
        result = _engine().analyze(build_email_data(MASS_PHISHING["email"]))
        assert result.verdict == Verdict.MALICIOUS

    def test_score_exceeds_65(self):
        result = _engine().analyze(build_email_data(MASS_PHISHING["email"]))
        assert result.score >= 65.0

    def test_two_active_categories(self):
        result = _engine().analyze(build_email_data(MASS_PHISHING["email"]))
        assert SignalCategory.AUTHENTICATION in result.active_categories
        assert SignalCategory.SENDER_IDENTITY in result.active_categories

    def test_both_analyzers_in_scope(self):
        result = _engine().analyze(build_email_data(MASS_PHISHING["email"]))
        assert "authentication_analyzer" in result.scope.analyzers_run
        assert "sender_analyzer" in result.scope.analyzers_run


class TestSpearPhishCousinDomain:
    """Auth passes but cousin domain alone → LIKELY_MALICIOUS (≥35)."""

    def test_score_at_least_35(self):
        result = _engine().analyze(build_email_data(SPEAR_PHISH_COUSIN_DOMAIN["email"]))
        assert result.score >= 35.0

    def test_verdict_at_least_likely_malicious(self):
        result = _engine().analyze(build_email_data(SPEAR_PHISH_COUSIN_DOMAIN["email"]))
        assert result.verdict in {Verdict.LIKELY_MALICIOUS, Verdict.MALICIOUS}


class TestBecWireTransfer:
    """Reply-to mismatch → SUSPICIOUS (≥15)."""

    def test_score_at_least_15(self):
        result = _engine().analyze(build_email_data(BEC_WIRE_TRANSFER["email"]))
        assert result.score >= 15.0

    def test_verdict_is_suspicious_or_higher(self):
        result = _engine().analyze(build_email_data(BEC_WIRE_TRANSFER["email"]))
        assert result.verdict in {Verdict.SUSPICIOUS, Verdict.LIKELY_MALICIOUS}


class TestLegitEmailsStaySafe:
    @pytest.mark.parametrize(
        "fixture",
        [LEGIT_AMAZON_ORDER, LEGIT_MARKETING],
        ids=["amazon", "marketing"],
    )
    def test_score_below_15_and_safe(self, fixture):
        result = _engine().analyze(build_email_data(fixture["email"]))
        assert result.score < 15.0
        assert result.verdict == Verdict.SAFE


class TestEmptyMinimalStaySafe:
    def test_safe_and_no_crash(self):
        result = _engine().analyze(build_email_data(EMPTY_MINIMAL["email"]))
        assert result.verdict == Verdict.SAFE
        assert result.score == 0.0


class TestNoCrashOnAllFixtures:
    @pytest.mark.parametrize(
        "fixture",
        ALL_FIXTURES,
        ids=[f["label"][:40] for f in ALL_FIXTURES],
    )
    def test_engine_does_not_crash(self, fixture):
        result = _engine().analyze(build_email_data(fixture["email"]))
        assert 0.0 <= result.score <= 100.0
        assert result.verdict in Verdict
