from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

from detection_engine.domain.enums import SignalCategory, SignalSeverity, Verdict
from detection_engine.domain.signals import ScoredSignal, Signal

SEVERITY_POINTS: dict[SignalSeverity, float] = {
    SignalSeverity.INFO: 0.0,
    SignalSeverity.LOW: 5.0,
    SignalSeverity.MEDIUM: 12.0,
    SignalSeverity.HIGH: 22.0,
    SignalSeverity.CRITICAL: 35.0,
}
"""Base points per severity tier. INFO is 0 because INFO signals are
informational only — they appear in the report but never push the verdict.
Tiers chosen so a single CRITICAL alone reaches LIKELY_MALICIOUS but not
MALICIOUS, forcing convergence across categories."""

CATEGORY_CAP: float = 50.0
"""Maximum points any single SignalCategory may contribute. Prevents
single-domain bias — five auth signals cannot push past LIKELY_MALICIOUS
without evidence from another category."""

WITHIN_CATEGORY_ATTENUATION: float = 1.6
"""Each additional signal in the same category is divided by ATTENUATION^k
(k = 0 for the first, 1 for the second, ...). Models diminishing returns
on correlated evidence — SPF fail and DKIM fail almost always co-occur."""

CROSS_CATEGORY_BOOST: float = 0.08
"""Multiplier added per additional active category beyond the first.
Two categories → x1.08, three → x1.16. Reflects that convergent evidence
across orthogonal categories is far more diagnostic than depth in one."""

VERDICT_THRESHOLDS: tuple[tuple[float, Verdict], ...] = (
    (65.0, Verdict.MALICIOUS),
    (35.0, Verdict.LIKELY_MALICIOUS),
    (15.0, Verdict.SUSPICIOUS),
    (0.0, Verdict.SAFE),
)
"""Lower bounds, checked in descending order. classify() picks the highest
tier whose bound the score meets. Tiers chosen so a typical legitimate email
lands well below 15 and an obvious phishing campaign lands above 65."""


@dataclass(frozen=True)
class ScoringReport:
    """Pure result of one scoring run over a set of Signals.

    `scored_signals` preserves the input order — callers can map back to
    their original sequence by index. Per-signal contribution is
    post-attenuation and post-cap, but does NOT include the cross-category
    boost; the boost is folded into `final_score` only."""

    final_score: float
    active_categories: frozenset[SignalCategory]
    scored_signals: tuple[ScoredSignal, ...]


def score_signals(signals: Sequence[Signal]) -> ScoringReport:
    """Score a list of signals. Pure — does not mutate the inputs.

    Per-category: signals are sorted by base contribution (severity points ×
    confidence) descending, then attenuated by position, then the category
    total is capped at CATEGORY_CAP (scaling members proportionally).
    Per-run: the final score is the sum of category totals multiplied by the
    cross-category boost, clamped to [0, 100]."""
    contributions = _per_signal_contributions(signals)
    category_totals = _category_totals(signals, contributions)

    raw_total = sum(category_totals.values())
    active_categories = frozenset(
        category for category, total in category_totals.items() if total > 0
    )
    multiplier = 1.0 + CROSS_CATEGORY_BOOST * max(0, len(active_categories) - 1)
    final_score = _clamp(raw_total * multiplier, 0.0, 100.0)

    scored_signals = tuple(
        ScoredSignal(signal=signal, contribution=contributions[index])
        for index, signal in enumerate(signals)
    )

    return ScoringReport(
        final_score=final_score,
        active_categories=active_categories,
        scored_signals=scored_signals,
    )


def classify_verdict(score_value: float) -> Verdict:
    """Return the highest Verdict whose threshold the score meets."""
    for threshold, verdict in VERDICT_THRESHOLDS:
        if score_value >= threshold:
            return verdict
    return Verdict.SAFE


def _per_signal_contributions(signals: Sequence[Signal]) -> dict[int, float]:
    """Compute each signal's contribution, keyed by its index in the input.

    Within each category: sort by base contribution descending, attenuate by
    position, then scale all members so the category total does not exceed
    CATEGORY_CAP."""
    indexed_by_category: dict[SignalCategory, list[tuple[int, Signal]]] = defaultdict(list)
    for index, signal in enumerate(signals):
        indexed_by_category[signal.category].append((index, signal))

    contributions: dict[int, float] = {}

    for category_signals in indexed_by_category.values():
        category_signals.sort(
            key=lambda indexed_signal: _base_points(indexed_signal[1]),
            reverse=True,
        )
        category_total = 0.0
        for position, (index, signal) in enumerate(category_signals):
            contribution = _base_points(signal) / (WITHIN_CATEGORY_ATTENUATION ** position)
            contributions[index] = contribution
            category_total += contribution

        if category_total > CATEGORY_CAP:
            cap_scale = CATEGORY_CAP / category_total
            for index, _ in category_signals:
                contributions[index] *= cap_scale

    return contributions


def _category_totals(
    signals: Sequence[Signal], contributions: dict[int, float]
) -> dict[SignalCategory, float]:
    totals: dict[SignalCategory, float] = defaultdict(float)
    for index, signal in enumerate(signals):
        totals[signal.category] += contributions[index]
    return totals


def _base_points(signal: Signal) -> float:
    return SEVERITY_POINTS[signal.severity] * signal.confidence


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(value, maximum))
