"""Tier 1 detection contract tests.

Every fixture in email_fixtures declares expected score bounds and verdicts.
These parametrized tests enforce those contracts across all ~40 scenarios.

Run: python -m pytest tests/test_tier1_detection.py -v
"""

from __future__ import annotations

import pytest

from detection_engine import DetectionEngine, Verdict
from detection_engine.analyzers.attachment import AttachmentAnalyzer
from detection_engine.analyzers.authentication import AuthenticationAnalyzer
from detection_engine.analyzers.body_content import BodyContentAnalyzer
from detection_engine.analyzers.sender import SenderAnalyzer
from detection_engine.analyzers.url_structure import UrlStructureAnalyzer

from tests.email_fixtures import (
    ALL_FIXTURES,
    SAFE_FIXTURES,
    build_email_data,
)


def _build_engine() -> DetectionEngine:
    return DetectionEngine(
        analyzers=[
            AuthenticationAnalyzer(),
            SenderAnalyzer(),
            BodyContentAnalyzer(),
            UrlStructureAnalyzer(),
            AttachmentAnalyzer(),
        ],
    )


ENGINE = _build_engine()


def _fixture_id(fixture: dict) -> str:
    return fixture["label"][:50]


# ---------------------------------------------------------------------------
# Universal contract: every fixture stays within its declared bounds
# ---------------------------------------------------------------------------


class TestScoreBounds:
    @pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=_fixture_id)
    def test_score_within_expected_range(self, fixture):
        result = ENGINE.analyze(build_email_data(fixture["email"]))
        expected = fixture["expected"]

        if "min_score" in expected:
            assert result.score >= expected["min_score"], (
                f"Score {result.score} below min {expected['min_score']}"
            )
        if "max_score" in expected:
            assert result.score <= expected["max_score"], (
                f"Score {result.score} above max {expected['max_score']}"
            )

    @pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=_fixture_id)
    def test_score_is_valid(self, fixture):
        result = ENGINE.analyze(build_email_data(fixture["email"]))
        assert 0.0 <= result.score <= 100.0


class TestVerdicts:
    @pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=_fixture_id)
    def test_verdict_matches_expected(self, fixture):
        result = ENGINE.analyze(build_email_data(fixture["email"]))
        expected = fixture["expected"]

        if "verdict" in expected:
            assert result.verdict == expected["verdict"], (
                f"Got {result.verdict.value}, expected {expected['verdict'].value}"
            )
        elif "verdict_in" in expected:
            assert result.verdict in expected["verdict_in"], (
                f"Got {result.verdict.value}, expected one of "
                f"{[v.value for v in expected['verdict_in']]}"
            )


# ---------------------------------------------------------------------------
# False-positive guard: all legitimate fixtures must score SAFE
# ---------------------------------------------------------------------------


class TestNoFalsePositives:
    @pytest.mark.parametrize("fixture", SAFE_FIXTURES, ids=_fixture_id)
    def test_legitimate_email_scores_safe(self, fixture):
        result = ENGINE.analyze(build_email_data(fixture["email"]))
        assert result.verdict == Verdict.SAFE, (
            f"False positive: '{fixture['label']}' scored {result.score} "
            f"({result.verdict.value})"
        )
        assert result.score < 15


# ---------------------------------------------------------------------------
# Robustness: engine never crashes on any fixture
# ---------------------------------------------------------------------------


class TestEngineRobustness:
    @pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=_fixture_id)
    def test_no_crash(self, fixture):
        result = ENGINE.analyze(build_email_data(fixture["email"]))
        assert result.verdict in Verdict

    @pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=_fixture_id)
    def test_all_analyzers_ran(self, fixture):
        result = ENGINE.analyze(build_email_data(fixture["email"]))
        assert "authentication_analyzer" in result.scope.analyzers_run
        assert "sender_analyzer" in result.scope.analyzers_run
        assert "body_content_analyzer" in result.scope.analyzers_run
        assert "url_structure_analyzer" in result.scope.analyzers_run
        assert "attachment_analyzer" in result.scope.analyzers_run
