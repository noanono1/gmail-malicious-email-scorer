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
    SignalSeverity.HIGH: 25.0,
    SignalSeverity.CRITICAL: 40.0,
}
"""INFO is 0 (informational, never pushes verdict). Tiers chosen so a single
CRITICAL alone reaches LIKELY_MALICIOUS but not MALICIOUS — forces convergence
across categories. HIGH=25 keeps a confident HIGH (×0.9) above SUSPICIOUS;
CRITICAL=40 keeps a confident CRITICAL (×0.9) above LIKELY_MALICIOUS."""

CATEGORY_CAP: float = 50.0
"""Maximum points any single SignalCategory may contribute. Prevents
single-domain bias — five auth signals cannot push past LIKELY_MALICIOUS
without evidence from another category."""

WITHIN_CATEGORY_ATTENUATION: float = 1.4
"""Each additional signal in the same category is divided by ATTENUATION^k.
Models diminishing returns on correlated evidence (SPF fail + DKIM fail).
Calibrated against labeled fixtures: 1.6 decayed independent same-category
evidence too aggressively (3rd signal at 39% of base); 1.4 preserves more
of multi-signal categories (51% of base) without inflating correlated runs."""

CROSS_CATEGORY_BOOST: float = 0.15
"""Multiplier added per active category beyond the first. Convergent evidence
across orthogonal categories is more diagnostic than depth in one. Calibrated
against labeled fixtures: 0.10 left multi-category malicious cases short of
the MALICIOUS threshold; 0.15 widens the gap between depth-penalty and
breadth-reward, which is what we want."""

# Correlated categories — these probe the same underlying question ("is the
# sender legitimate?") from different angles, so co-firing is expected and
# the cross-category boost overstates independence.  URL/BODY/ATTACHMENT
# signals override the dampener because they represent genuinely orthogonal
# evidence.
_CORRELATED_CATEGORIES: frozenset[SignalCategory] = frozenset({
    SignalCategory.AUTHENTICATION,
    SignalCategory.SENDER_IDENTITY,
})

CORRELATION_DAMPENER: float = 0.78
"""Applied when ≥2 correlated categories fire and none clears CRITICAL.
Empirical: 0.85 leaves softfail+mismatch above the LIKELY_MALICIOUS threshold;
0.65 demotes genuine spoofing patterns that should read LIKELY_MALICIOUS."""

VERDICT_THRESHOLDS: tuple[tuple[float, Verdict], ...] = (
    (65.0, Verdict.MALICIOUS),
    (35.0, Verdict.LIKELY_MALICIOUS),
    (15.0, Verdict.SUSPICIOUS),
    (0.0, Verdict.SAFE),
)
"""Lower bounds, descending. Tiers chosen so a legitimate email lands well
below 15 and an obvious phishing campaign lands above 65."""


@dataclass(frozen=True)
class ScoringReport:
    """Pure result of one scoring run.

    ``scored_signals`` preserves input order. Per-signal contribution is
    post-attenuation and post-cap, but excludes the cross-category boost
    and infrastructure dampener — those fold into ``final_score`` only."""

    final_score: float
    active_categories: frozenset[SignalCategory]
    scored_signals: tuple[ScoredSignal, ...]


def score_signals(signals: Sequence[Signal]) -> ScoringReport:
    """Score a list of signals. Pure.

    Per-category: sort by base contribution (severity × confidence) desc,
    attenuate by position, cap at CATEGORY_CAP. Per-run: sum, apply cross-
    category boost and (if applicable) infrastructure dampener, clamp to
    [0, 100]."""
    contributions = _per_signal_contributions(signals)
    category_totals = _category_totals(signals, contributions)

    raw_total = sum(category_totals.values())
    active_categories = frozenset(
        category for category, total in category_totals.items() if total > 0
    )
    multiplier = (
        1.0 + CROSS_CATEGORY_BOOST * max(0, len(active_categories) - 1)
    ) * _correlated_only_factor(category_totals, active_categories)
    final_score = max(0.0, min(raw_total * multiplier, 100.0))

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
    """Per-signal contribution keyed by input index.

    Within a category: sort desc, attenuate by position, scale members down
    so the category total stays within CATEGORY_CAP."""
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


def _correlated_only_factor(
    category_totals: dict[SignalCategory, float],
    active_categories: frozenset[SignalCategory],
) -> float:
    if len(active_categories) < 2:
        return 1.0
    if not active_categories.issubset(_CORRELATED_CATEGORIES):
        return 1.0
    decisive = SEVERITY_POINTS[SignalSeverity.CRITICAL]
    if any(total >= decisive for total in category_totals.values()):
        return 1.0
    return CORRELATION_DAMPENER


def _base_points(signal: Signal) -> float:
    return SEVERITY_POINTS[signal.severity] * signal.confidence
