from __future__ import annotations

from logging import getLogger

from detection_engine.analyzers.base import BaseAnalyzer
from detection_engine.domain import blind_spot_catalog
from detection_engine.domain.email import EmailData
from detection_engine.domain.enums import SignalCategory, Verdict
from detection_engine.domain.exceptions import AnalyzerCrashed
from detection_engine.domain.signals import AnalysisOutput, BlindSpot, ScoredSignal, Signal
from detection_engine.domain.verdict import AnalysisResult, AnalysisScope
from detection_engine.scoring import classify_verdict, score_signals

logger = getLogger(__name__)


class DetectionEngine:
    """Orchestrates analyzers to produce an AnalysisResult."""

    def __init__(self, analyzers: list[BaseAnalyzer]) -> None:
        self._analyzers = analyzers

    def analyze(self, email: EmailData) -> AnalysisResult:
        structural_blind_spots = tuple(
            blind_spot for blind_spot in blind_spot_catalog.STRUCTURAL
            if blind_spot.applies is None or blind_spot.applies(email)
        )

        analyzer_output = self._run_analyzers(email)

        all_signals = analyzer_output.signals
        blind_spots = structural_blind_spots + analyzer_output.blind_spots

        report = score_signals(all_signals)
        verdict = classify_verdict(report.final_score)
        top_signals = _pick_top_signals(report.scored_signals, count=3)

        scope = AnalysisScope(
            analyzers_run=tuple(a.name for a in self._analyzers),
            has_html=bool(email.body_html),
            has_attachments=bool(email.attachments),
            has_auth_headers="authentication-results" in email.headers,
        )

        explanation = _explain(
            verdict, top_signals, report.active_categories, blind_spots,
        )

        return AnalysisResult(
            verdict=verdict,
            score=report.final_score,
            signals=report.scored_signals,
            top_signals=top_signals,
            active_categories=report.active_categories,
            blind_spots=blind_spots,
            scope=scope,
            explanation=explanation,
        )

    def _run_analyzers(self, email: EmailData) -> AnalysisOutput:
        signals: list[Signal] = []
        blind_spots: list[BlindSpot] = []

        for analyzer in self._analyzers:
            try:
                analyzer_output = analyzer.analyze(email)
            except Exception as exc:
                raise AnalyzerCrashed(analyzer.name, exc) from exc
            signals.extend(analyzer_output.signals)
            blind_spots.extend(analyzer_output.blind_spots)

        return AnalysisOutput(signals=tuple(signals), blind_spots=tuple(blind_spots))


def _pick_top_signals(
    scored_signals: tuple[ScoredSignal, ...], count: int
) -> tuple[ScoredSignal, ...]:
    by_contribution = sorted(scored_signals, key=lambda scored: scored.contribution, reverse=True)
    return tuple(by_contribution[:count])


def _explain(
    verdict: Verdict,
    top_signals: tuple[ScoredSignal, ...],
    active_categories: frozenset[SignalCategory],
    blind_spots: tuple[BlindSpot, ...],
) -> str:
    """Render a human-readable explanation.

    ``active_categories`` is from scoring (every category > 0 points).
    Deriving from ``top_signals`` would undercount past the top 3."""
    if not top_signals:
        if blind_spots:
            return (
                f"Verdict: {verdict.value}. \n No threat signals detected, "
                f"but {len(blind_spots)} area(s) could not be inspected."
            )
        return f"Verdict: {verdict.value}. \n No threat signals detected."

    header = f"Verdict: {verdict.value}."

    findings = "\n".join(
        f"• {scored.signal.category.value}: {scored.signal.summary} "
        f"({scored.signal.severity.value}, +{scored.contribution:.1f} pts)"
        for scored in top_signals
    )

    category_count = len(active_categories)
    category_note = (
        f"Evidence spans {category_count} categor{'y' if category_count == 1 else 'ies'}."
        if category_count
        else ""
    )

    blind_note = (
        f" {len(blind_spots)} area(s) could not be inspected."
        if blind_spots
        else ""
    )

    return f"{header}\n{findings}\n{category_note}{blind_note}"
