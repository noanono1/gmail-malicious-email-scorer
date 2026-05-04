"""Unit tests for the scoring algorithm — severity points, attenuation,
category cap, cross-category boost, and verdict classification."""

from __future__ import annotations

import pytest

from detection_engine.domain.enums import SignalCategory, SignalSeverity, Verdict
from detection_engine.domain.signals import Signal
from detection_engine.scoring import (
    CATEGORY_CAP,
    CROSS_CATEGORY_BOOST,
    SEVERITY_POINTS,
    WITHIN_CATEGORY_ATTENUATION,
    classify_verdict,
    score_signals,
)


def _signal(
    severity: SignalSeverity,
    category: SignalCategory = SignalCategory.AUTHENTICATION,
    confidence: float = 1.0,
) -> Signal:
    return Signal(
        id=f"test_{severity.value}",
        category=category,
        severity=severity,
        confidence=confidence,
        summary="test signal",
    )


# ---------------------------------------------------------------------------
# Single signal scoring — base points × confidence
# ---------------------------------------------------------------------------


class TestSingleSignalScoring:
    @pytest.mark.parametrize(
        "severity",
        [
            SignalSeverity.CRITICAL,
            SignalSeverity.HIGH,
            SignalSeverity.MEDIUM,
            SignalSeverity.LOW,
            SignalSeverity.INFO,
        ],
    )
    def test_full_confidence_matches_severity_points(self, severity):
        report = score_signals([_signal(severity)])
        assert report.final_score == pytest.approx(SEVERITY_POINTS[severity])

    def test_confidence_scales_contribution(self):
        report = score_signals([_signal(SignalSeverity.HIGH, confidence=0.5)])
        assert report.final_score == pytest.approx(SEVERITY_POINTS[SignalSeverity.HIGH] * 0.5)

    def test_no_signals(self):
        report = score_signals([])
        assert report.final_score == 0.0
        assert len(report.active_categories) == 0
        assert report.scored_signals == ()

    def test_contribution_reported_per_signal(self):
        signal = _signal(SignalSeverity.CRITICAL)
        report = score_signals([signal])
        assert report.scored_signals[0].signal is signal
        assert report.scored_signals[0].contribution == pytest.approx(
            SEVERITY_POINTS[SignalSeverity.CRITICAL]
        )

    def test_signal_is_not_mutated(self):
        signal = _signal(SignalSeverity.CRITICAL)
        score_signals([signal])
        assert not hasattr(signal, "score_contribution")


# ---------------------------------------------------------------------------
# Within-category attenuation — diminishing returns on correlated evidence
# ---------------------------------------------------------------------------


class TestWithinCategoryAttenuation:
    def test_second_signal_attenuated(self):
        s1 = _signal(SignalSeverity.CRITICAL)
        s2 = _signal(SignalSeverity.CRITICAL)
        report = score_signals([s1, s2])

        base = SEVERITY_POINTS[SignalSeverity.CRITICAL]
        expected_s1 = base
        expected_s2 = base / WITHIN_CATEGORY_ATTENUATION

        uncapped_total = expected_s1 + expected_s2
        if uncapped_total > CATEGORY_CAP:
            scale = CATEGORY_CAP / uncapped_total
            expected_s1 *= scale
            expected_s2 *= scale

        assert report.scored_signals[0].contribution == pytest.approx(expected_s1)
        assert report.scored_signals[1].contribution == pytest.approx(expected_s2)

    def test_third_signal_attenuated_more(self):
        signals = [_signal(SignalSeverity.HIGH) for _ in range(3)]
        report = score_signals(signals)

        base = SEVERITY_POINTS[SignalSeverity.HIGH]
        expected_raw = [base / (WITHIN_CATEGORY_ATTENUATION ** k) for k in range(3)]
        raw_total = sum(expected_raw)

        if raw_total > CATEGORY_CAP:
            scale = CATEGORY_CAP / raw_total
            expected_raw = [e * scale for e in expected_raw]

        for scored, expected in zip(report.scored_signals, expected_raw):
            assert scored.contribution == pytest.approx(expected)

    def test_strongest_severity_keeps_largest_contribution(self):
        # Input order is irrelevant to attenuation: scoring sorts by base
        # contribution within a category, so CRITICAL gets position 0
        # regardless of where it appears in the input.
        low = _signal(SignalSeverity.LOW)
        critical = _signal(SignalSeverity.CRITICAL)
        report = score_signals([low, critical])

        contribution_by_signal = {
            scored.signal: scored.contribution for scored in report.scored_signals
        }
        assert contribution_by_signal[critical] > contribution_by_signal[low]


# ---------------------------------------------------------------------------
# Category cap — single category cannot dominate
# ---------------------------------------------------------------------------


class TestCategoryCap:
    def test_many_signals_capped(self):
        signals = [_signal(SignalSeverity.CRITICAL) for _ in range(10)]
        report = score_signals(signals)
        assert report.final_score == pytest.approx(CATEGORY_CAP)

    def test_cap_preserves_relative_proportions(self):
        s1 = _signal(SignalSeverity.CRITICAL)
        s2 = _signal(SignalSeverity.MEDIUM)
        report = score_signals([s1, s2])

        base_critical = SEVERITY_POINTS[SignalSeverity.CRITICAL]
        base_medium = SEVERITY_POINTS[SignalSeverity.MEDIUM] / WITHIN_CATEGORY_ATTENUATION
        raw_total = base_critical + base_medium

        if raw_total > CATEGORY_CAP:
            c1 = report.scored_signals[0].contribution
            c2 = report.scored_signals[1].contribution
            assert c1 / c2 == pytest.approx(base_critical / base_medium)

    def test_single_critical_below_cap(self):
        report = score_signals([_signal(SignalSeverity.CRITICAL)])
        assert report.final_score < CATEGORY_CAP


# ---------------------------------------------------------------------------
# Cross-category boost — convergent evidence multiplier
# ---------------------------------------------------------------------------


class TestCrossCategoryBoost:
    def test_two_categories_boosted(self):
        auth = _signal(SignalSeverity.HIGH, category=SignalCategory.AUTHENTICATION)
        body = _signal(SignalSeverity.HIGH, category=SignalCategory.BODY_CONTENT)
        report = score_signals([auth, body])

        base = SEVERITY_POINTS[SignalSeverity.HIGH]
        raw_total = base * 2
        expected = raw_total * (1.0 + CROSS_CATEGORY_BOOST)
        assert report.final_score == pytest.approx(expected)
        assert len(report.active_categories) == 2

    def test_three_categories_boosted_more(self):
        signals = [
            _signal(SignalSeverity.HIGH, category=SignalCategory.AUTHENTICATION),
            _signal(SignalSeverity.HIGH, category=SignalCategory.BODY_CONTENT),
            _signal(SignalSeverity.HIGH, category=SignalCategory.URL_STRUCTURE),
        ]
        report = score_signals(signals)

        base = SEVERITY_POINTS[SignalSeverity.HIGH]
        raw_total = base * 3
        expected = raw_total * (1.0 + CROSS_CATEGORY_BOOST * 2)
        assert report.final_score == pytest.approx(expected)
        assert len(report.active_categories) == 3

    def test_single_category_no_boost(self):
        report = score_signals([_signal(SignalSeverity.HIGH)])
        assert report.final_score == pytest.approx(SEVERITY_POINTS[SignalSeverity.HIGH])

    def test_info_category_not_counted(self):
        auth = _signal(SignalSeverity.HIGH, category=SignalCategory.AUTHENTICATION)
        info = _signal(SignalSeverity.INFO, category=SignalCategory.URL_STRUCTURE)
        report = score_signals([auth, info])

        assert report.final_score == pytest.approx(SEVERITY_POINTS[SignalSeverity.HIGH])
        assert SignalCategory.URL_STRUCTURE not in report.active_categories

    def test_score_clamped_to_100(self):
        signals = [
            _signal(SignalSeverity.CRITICAL, category=cat)
            for cat in SignalCategory
        ]
        signals += [_signal(SignalSeverity.HIGH, category=cat) for cat in SignalCategory]
        report = score_signals(signals)
        assert report.final_score <= 100.0


# ---------------------------------------------------------------------------
# Verdict classification — threshold boundaries
# ---------------------------------------------------------------------------


class TestVerdictClassification:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (0.0, Verdict.SAFE),
            (14.9, Verdict.SAFE),
            (15.0, Verdict.SUSPICIOUS),
            (34.9, Verdict.SUSPICIOUS),
            (35.0, Verdict.LIKELY_MALICIOUS),
            (64.9, Verdict.LIKELY_MALICIOUS),
            (65.0, Verdict.MALICIOUS),
            (100.0, Verdict.MALICIOUS),
        ],
        ids=[
            "zero_is_safe",
            "just_below_suspicious",
            "exactly_suspicious",
            "just_below_likely_malicious",
            "exactly_likely_malicious",
            "just_below_malicious",
            "exactly_malicious",
            "max_score",
        ],
    )
    def test_classify(self, score, expected):
        assert classify_verdict(score) == expected


# ---------------------------------------------------------------------------
# End-to-end: scoring → verdict consistency
# ---------------------------------------------------------------------------


class TestScoringToVerdict:
    def test_single_critical_is_likely_malicious(self):
        report = score_signals([_signal(SignalSeverity.CRITICAL)])
        assert classify_verdict(report.final_score) == Verdict.LIKELY_MALICIOUS

    def test_single_high_is_suspicious(self):
        report = score_signals([_signal(SignalSeverity.HIGH)])
        assert classify_verdict(report.final_score) == Verdict.SUSPICIOUS

    def test_single_medium_is_safe(self):
        report = score_signals([_signal(SignalSeverity.MEDIUM)])
        assert classify_verdict(report.final_score) == Verdict.SAFE

    def test_convergence_pushes_verdict_up(self):
        auth_critical = _signal(
            SignalSeverity.CRITICAL, category=SignalCategory.AUTHENTICATION
        )
        body_critical = _signal(
            SignalSeverity.CRITICAL, category=SignalCategory.BODY_CONTENT
        )
        report = score_signals([auth_critical, body_critical])
        assert classify_verdict(report.final_score) == Verdict.MALICIOUS

    def test_single_category_cannot_reach_malicious(self):
        signals = [_signal(SignalSeverity.CRITICAL) for _ in range(20)]
        report = score_signals(signals)
        assert classify_verdict(report.final_score) != Verdict.MALICIOUS
