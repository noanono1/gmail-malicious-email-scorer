from __future__ import annotations

from collections import defaultdict

from detection_engine.domain.enums import SignalCategory, SignalSeverity, Verdict
from detection_engine.domain.signals import Signal

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


def score_signals(signals: list[Signal]) -> tuple[float, frozenset[SignalCategory]]:
    """Score a list of signals. Returns (final_score, active_categories).

    Mutates each signal's score_contribution in place — this is the one
    documented mutable field on Signal (see domain/signals.py)."""
    signals_by_category: dict[SignalCategory, list[Signal]] = defaultdict(list)
    for signal in signals:
        signals_by_category[signal.category].append(signal)

    category_totals: dict[SignalCategory, float] = {}

    for category, category_signals in signals_by_category.items():
        category_signals.sort(
            key=lambda signal: SEVERITY_POINTS[signal.severity] * signal.confidence,
            reverse=True,
        )
        category_running_total = 0.0
        for position, signal in enumerate(category_signals):
            base_points = SEVERITY_POINTS[signal.severity] * signal.confidence
            contribution = base_points / (WITHIN_CATEGORY_ATTENUATION ** position)
            signal.score_contribution = contribution
            category_running_total += contribution

        if category_running_total > CATEGORY_CAP:
            cap_scale = CATEGORY_CAP / category_running_total
            for signal in category_signals:
                signal.score_contribution *= cap_scale
            category_running_total = CATEGORY_CAP

        category_totals[category] = category_running_total

    raw_total = sum(category_totals.values())
    active_categories = frozenset(
        category for category, category_total in category_totals.items() if category_total > 0
    )
    multiplier = 1.0 + CROSS_CATEGORY_BOOST * max(0, len(active_categories) - 1)
    final_score = _clamp(raw_total * multiplier, 0.0, 100.0)

    return final_score, active_categories


def classify_verdict(score_value: float) -> Verdict:
    """Return the highest Verdict whose threshold the score meets."""
    for threshold, verdict in VERDICT_THRESHOLDS:
        if score_value >= threshold:
            return verdict
    return Verdict.SAFE


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(value, maximum))
