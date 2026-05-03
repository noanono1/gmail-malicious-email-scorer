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
        evidence="test signal",
    )


# ---------------------------------------------------------------------------
# Single signal scoring — base points × confidence
# ---------------------------------------------------------------------------


class TestSingleSignalScoring:
    def test_critical_full_confidence(self):
        signals = [_signal(SignalSeverity.CRITICAL)]
        score, _ = score_signals(signals)
        assert score == pytest.approx(SEVERITY_POINTS[SignalSeverity.CRITICAL])

    def test_high_full_confidence(self):
        signals = [_signal(SignalSeverity.HIGH)]
        score, _ = score_signals(signals)
        assert score == pytest.approx(SEVERITY_POINTS[SignalSeverity.HIGH])

    def test_medium_full_confidence(self):
        signals = [_signal(SignalSeverity.MEDIUM)]
        score, _ = score_signals(signals)
        assert score == pytest.approx(SEVERITY_POINTS[SignalSeverity.MEDIUM])

    def test_low_full_confidence(self):
        signals = [_signal(SignalSeverity.LOW)]
        score, _ = score_signals(signals)
        assert score == pytest.approx(SEVERITY_POINTS[SignalSeverity.LOW])

    def test_info_contributes_zero(self):
        signals = [_signal(SignalSeverity.INFO)]
        score, _ = score_signals(signals)
        assert score == 0.0

    def test_confidence_scales_contribution(self):
        signals = [_signal(SignalSeverity.HIGH, confidence=0.5)]
        score, _ = score_signals(signals)
        assert score == pytest.approx(SEVERITY_POINTS[SignalSeverity.HIGH] * 0.5)

    def test_no_signals(self):
        score, categories = score_signals([])
        assert score == 0.0
        assert len(categories) == 0

    def test_contribution_stored_on_signal(self):
        signal = _signal(SignalSeverity.CRITICAL)
        score_signals([signal])
        assert signal.score_contribution == pytest.approx(
            SEVERITY_POINTS[SignalSeverity.CRITICAL]
        )


# ---------------------------------------------------------------------------
# Within-category attenuation — diminishing returns on correlated evidence
# ---------------------------------------------------------------------------


class TestWithinCategoryAttenuation:
    def test_second_signal_attenuated(self):
        s1 = _signal(SignalSeverity.CRITICAL)
        s2 = _signal(SignalSeverity.CRITICAL)
        score_signals([s1, s2])

        base = SEVERITY_POINTS[SignalSeverity.CRITICAL]
        expected_s1 = base
        expected_s2 = base / WITHIN_CATEGORY_ATTENUATION

        uncapped_total = expected_s1 + expected_s2
        if uncapped_total > CATEGORY_CAP:
            scale = CATEGORY_CAP / uncapped_total
            expected_s1 *= scale
            expected_s2 *= scale

        assert s1.score_contribution == pytest.approx(expected_s1)
        assert s2.score_contribution == pytest.approx(expected_s2)

    def test_third_signal_attenuated_more(self):
        signals = [_signal(SignalSeverity.HIGH) for _ in range(3)]
        score_signals(signals)

        base = SEVERITY_POINTS[SignalSeverity.HIGH]
        expected_raw = [base / (WITHIN_CATEGORY_ATTENUATION ** k) for k in range(3)]
        raw_total = sum(expected_raw)

        if raw_total > CATEGORY_CAP:
            scale = CATEGORY_CAP / raw_total
            expected_raw = [e * scale for e in expected_raw]

        for signal, expected in zip(signals, expected_raw):
            assert signal.score_contribution == pytest.approx(expected)

    def test_sorting_highest_first(self):
        low = _signal(SignalSeverity.LOW)
        critical = _signal(SignalSeverity.CRITICAL)
        score_signals([low, critical])

        assert critical.score_contribution > low.score_contribution


# ---------------------------------------------------------------------------
# Category cap — single category cannot dominate
# ---------------------------------------------------------------------------


class TestCategoryCap:
    def test_many_signals_capped(self):
        signals = [_signal(SignalSeverity.CRITICAL) for _ in range(10)]
        score, _ = score_signals(signals)
        assert score == pytest.approx(CATEGORY_CAP)

    def test_cap_preserves_relative_proportions(self):
        s1 = _signal(SignalSeverity.CRITICAL)
        s2 = _signal(SignalSeverity.MEDIUM)
        score_signals([s1, s2])

        base_critical = SEVERITY_POINTS[SignalSeverity.CRITICAL]
        base_medium = SEVERITY_POINTS[SignalSeverity.MEDIUM] / WITHIN_CATEGORY_ATTENUATION
        raw_total = base_critical + base_medium

        if raw_total > CATEGORY_CAP:
            assert s1.score_contribution / s2.score_contribution == pytest.approx(
                base_critical / base_medium
            )

    def test_single_critical_below_cap(self):
        signals = [_signal(SignalSeverity.CRITICAL)]
        score, _ = score_signals(signals)
        assert score < CATEGORY_CAP


# ---------------------------------------------------------------------------
# Cross-category boost — convergent evidence multiplier
# ---------------------------------------------------------------------------


class TestCrossCategoryBoost:
    def test_two_categories_boosted(self):
        auth = _signal(SignalSeverity.HIGH, category=SignalCategory.AUTHENTICATION)
        body = _signal(SignalSeverity.HIGH, category=SignalCategory.BODY_CONTENT)
        score, categories = score_signals([auth, body])

        base = SEVERITY_POINTS[SignalSeverity.HIGH]
        raw_total = base * 2
        expected = raw_total * (1.0 + CROSS_CATEGORY_BOOST)
        assert score == pytest.approx(expected)
        assert len(categories) == 2

    def test_three_categories_boosted_more(self):
        signals = [
            _signal(SignalSeverity.HIGH, category=SignalCategory.AUTHENTICATION),
            _signal(SignalSeverity.HIGH, category=SignalCategory.BODY_CONTENT),
            _signal(SignalSeverity.HIGH, category=SignalCategory.URL_STRUCTURE),
        ]
        score, categories = score_signals(signals)

        base = SEVERITY_POINTS[SignalSeverity.HIGH]
        raw_total = base * 3
        expected = raw_total * (1.0 + CROSS_CATEGORY_BOOST * 2)
        assert score == pytest.approx(expected)
        assert len(categories) == 3

    def test_single_category_no_boost(self):
        signals = [_signal(SignalSeverity.HIGH)]
        score, _ = score_signals(signals)
        assert score == pytest.approx(SEVERITY_POINTS[SignalSeverity.HIGH])

    def test_info_category_not_counted(self):
        auth = _signal(SignalSeverity.HIGH, category=SignalCategory.AUTHENTICATION)
        info = _signal(SignalSeverity.INFO, category=SignalCategory.URL_STRUCTURE)
        score, categories = score_signals([auth, info])

        assert score == pytest.approx(SEVERITY_POINTS[SignalSeverity.HIGH])
        assert SignalCategory.URL_STRUCTURE not in categories

    def test_score_clamped_to_100(self):
        signals = [
            _signal(SignalSeverity.CRITICAL, category=cat)
            for cat in SignalCategory
        ]
        signals += [_signal(SignalSeverity.HIGH, category=cat) for cat in SignalCategory]
        score, _ = score_signals(signals)
        assert score <= 100.0


# ---------------------------------------------------------------------------
# Verdict classification — threshold boundaries
# ---------------------------------------------------------------------------


class TestVerdictClassification:
    def test_zero_is_safe(self):
        assert classify_verdict(0.0) == Verdict.SAFE

    def test_just_below_suspicious(self):
        assert classify_verdict(14.9) == Verdict.SAFE

    def test_exactly_suspicious(self):
        assert classify_verdict(15.0) == Verdict.SUSPICIOUS

    def test_just_below_likely_malicious(self):
        assert classify_verdict(34.9) == Verdict.SUSPICIOUS

    def test_exactly_likely_malicious(self):
        assert classify_verdict(35.0) == Verdict.LIKELY_MALICIOUS

    def test_just_below_malicious(self):
        assert classify_verdict(64.9) == Verdict.LIKELY_MALICIOUS

    def test_exactly_malicious(self):
        assert classify_verdict(65.0) == Verdict.MALICIOUS

    def test_max_score(self):
        assert classify_verdict(100.0) == Verdict.MALICIOUS


# ---------------------------------------------------------------------------
# End-to-end: scoring → verdict consistency
# ---------------------------------------------------------------------------


class TestScoringToVerdict:
    def test_single_critical_is_likely_malicious(self):
        signals = [_signal(SignalSeverity.CRITICAL)]
        score, _ = score_signals(signals)
        assert classify_verdict(score) == Verdict.LIKELY_MALICIOUS

    def test_single_high_is_suspicious(self):
        signals = [_signal(SignalSeverity.HIGH)]
        score, _ = score_signals(signals)
        assert classify_verdict(score) == Verdict.SUSPICIOUS

    def test_single_medium_is_safe(self):
        signals = [_signal(SignalSeverity.MEDIUM)]
        score, _ = score_signals(signals)
        assert classify_verdict(score) == Verdict.SAFE

    def test_convergence_pushes_verdict_up(self):
        auth_critical = _signal(
            SignalSeverity.CRITICAL, category=SignalCategory.AUTHENTICATION
        )
        body_critical = _signal(
            SignalSeverity.CRITICAL, category=SignalCategory.BODY_CONTENT
        )
        score, _ = score_signals([auth_critical, body_critical])
        assert classify_verdict(score) == Verdict.MALICIOUS

    def test_single_category_cannot_reach_malicious(self):
        signals = [_signal(SignalSeverity.CRITICAL) for _ in range(20)]
        score, _ = score_signals(signals)
        assert classify_verdict(score) != Verdict.MALICIOUS
