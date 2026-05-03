"""Integration tests — AuthenticationAnalyzer through the engine, scoring, and verdict."""

from __future__ import annotations

import pytest

from detection_engine import DetectionEngine, SignalCategory, Verdict
from detection_engine.analyzers.authentication import AuthenticationAnalyzer
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
    return DetectionEngine(analyzers=[AuthenticationAnalyzer()], intel_sources=[])


class TestMassPhishingScoring:
    """3 auth failures → capped at 50, verdict = LIKELY_MALICIOUS."""

    def test_score_is_capped_at_fifty(self):
        result = _engine().analyze(build_email_data(MASS_PHISHING["email"]))
        assert result.score == pytest.approx(50.0, abs=0.01)

    def test_verdict_is_likely_malicious(self):
        result = _engine().analyze(build_email_data(MASS_PHISHING["email"]))
        assert result.verdict == Verdict.LIKELY_MALICIOUS

    def test_single_active_category(self):
        result = _engine().analyze(build_email_data(MASS_PHISHING["email"]))
        assert result.active_categories == frozenset({SignalCategory.AUTHENTICATION})

    def test_three_signals_emitted(self):
        result = _engine().analyze(build_email_data(MASS_PHISHING["email"]))
        assert len(result.signals) == 3

    def test_header_analyzer_in_scope(self):
        result = _engine().analyze(build_email_data(MASS_PHISHING["email"]))
        assert "authentication_analyzer" in result.scope.analyzers_run


class TestLegitEmailsScoreZero:
    @pytest.mark.parametrize(
        "fixture",
        [LEGIT_AMAZON_ORDER, LEGIT_MARKETING],
        ids=["amazon", "marketing"],
    )
    def test_score_zero_and_safe(self, fixture):
        result = _engine().analyze(build_email_data(fixture["email"]))
        assert result.score == 0.0
        assert result.verdict == Verdict.SAFE


class TestAuthPassFixtures:
    """Fixtures with passing auth produce no auth signals."""

    @pytest.mark.parametrize(
        "fixture",
        [BEC_WIRE_TRANSFER, SPEAR_PHISH_COUSIN_DOMAIN],
        ids=["bec", "spear_phish"],
    )
    def test_no_auth_signals(self, fixture):
        result = _engine().analyze(build_email_data(fixture["email"]))
        auth_signals = [
            s for s in result.signals if s.category == SignalCategory.AUTHENTICATION
        ]
        assert len(auth_signals) == 0


class TestMalwareAttachmentAuth:
    """Auth failures present but not all three — still capped by single category."""

    def test_score_is_capped(self):
        result = _engine().analyze(build_email_data(MALWARE_ATTACHMENT["email"]))
        assert 35.0 <= result.score <= 50.0

    def test_verdict_is_likely_malicious(self):
        result = _engine().analyze(build_email_data(MALWARE_ATTACHMENT["email"]))
        assert result.verdict == Verdict.LIKELY_MALICIOUS


class TestEmptyMinimal:
    def test_no_crash_and_safe(self):
        result = _engine().analyze(build_email_data(EMPTY_MINIMAL["email"]))
        assert result.verdict == Verdict.SAFE
        assert result.score == 0.0

    def test_has_auth_blind_spot(self):
        result = _engine().analyze(build_email_data(EMPTY_MINIMAL["email"]))
        auth_blind_spots = [
            bs for bs in result.blind_spots if bs.area.value == "authentication_headers"
        ]
        assert len(auth_blind_spots) == 1


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
