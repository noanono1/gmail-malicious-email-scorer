from __future__ import annotations

from dataclasses import dataclass
from logging import getLogger

from detection_engine.analyzers.base import BaseAnalyzer
from detection_engine.domain import blind_spot_catalog
from detection_engine.domain.email import EmailData
from detection_engine.domain.enums import IntelSourceType, Verdict
from detection_engine.domain.exceptions import AnalyzerCrashed
from detection_engine.domain.signals import AnalysisOutput, BlindSpot, ScoredSignal, Signal
from detection_engine.domain.verdict import AnalysisResult, AnalysisScope
from detection_engine.intel_sources.base import ThreatIntelSource
from detection_engine.scoring import classify_verdict, score_signals

logger = getLogger(__name__)


@dataclass(frozen=True)
class IntelRunResult:
    """Result of running all intel sources — extends AnalysisOutput with execution metadata."""

    output: AnalysisOutput
    sources_executed: tuple[IntelSourceType, ...]


class DetectionEngine:
    """Orchestrates analyzers and intel sources to produce an AnalysisResult.

    Constructor takes lists of analyzers and intel sources (both injected).
    Single public method: analyze(email) -> AnalysisResult."""

    def __init__(
        self,
        analyzers: list[BaseAnalyzer],
        intel_sources: list[ThreatIntelSource],
    ) -> None:
        self._analyzers = analyzers
        self._intel_sources = intel_sources

    def analyze(self, email: EmailData) -> AnalysisResult:
        # Collect structural blind spots up front so even a "safe" verdict reports what we couldn't inspect (e.g. encrypted attachments).
        structural_blind_spots = tuple(
            blind_spot for blind_spot in blind_spot_catalog.STRUCTURAL
            if blind_spot.applies is None or blind_spot.applies(email)
        )

        analyzer_output = self._run_analyzers(email)
        intel_result = self._run_intel_sources(email)

        all_signals = analyzer_output.signals + intel_result.output.signals
        blind_spots = structural_blind_spots + analyzer_output.blind_spots + intel_result.output.blind_spots

        report = score_signals(all_signals)
        verdict = classify_verdict(report.final_score)
        top_signals = _pick_top_signals(report.scored_signals, count=3)

        scope = AnalysisScope(
            analyzers_run=tuple(a.name for a in self._analyzers),
            intel_sources_run=intel_result.sources_executed,
            has_html=bool(email.body_html),
            has_attachments=bool(email.attachments),
            has_auth_headers="authentication-results" in email.headers,
        )

        explanation = self._explain(verdict, top_signals, blind_spots)

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

    def _run_intel_sources(self, email: EmailData) -> IntelRunResult:
        signals: list[Signal] = []
        blind_spots: list[BlindSpot] = []
        executed_source_types: list[IntelSourceType] = []

        for source in self._intel_sources:
            if not source.is_available():
                blind_spots.append(
                    blind_spot_catalog.intel_source_not_configured(source.source_type)
                )
                continue
            try:
                intel_output = source.query(email)
            except Exception:
                logger.exception("Intel source crashed: %s", source.source_type.value)
                blind_spots.append(
                    blind_spot_catalog.intel_source_failed(source.source_type)
                )
                continue
            signals.extend(intel_output.signals)
            blind_spots.extend(intel_output.blind_spots)
            executed_source_types.append(source.source_type)

        return IntelRunResult(
            output=AnalysisOutput(signals=tuple(signals), blind_spots=tuple(blind_spots)),
            sources_executed=tuple(executed_source_types),
        )

    def _explain(
        self,
        verdict: Verdict,
        top_signals: tuple[ScoredSignal, ...],
        blind_spots: tuple[BlindSpot, ...],
    ) -> str:
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

        categories = {scored.signal.category.value for scored in top_signals}
        category_note = (
            f"Evidence spans {len(categories)} categor{'y' if len(categories) == 1 else 'ies'}."
            if categories
            else ""
        )

        blind_note = (
            f" {len(blind_spots)} area(s) could not be inspected."
            if blind_spots
            else ""
        )

        return f"{header}\n{findings}\n{category_note}{blind_note}"


def _pick_top_signals(
    scored_signals: tuple[ScoredSignal, ...], count: int
) -> tuple[ScoredSignal, ...]:
    by_contribution = sorted(scored_signals, key=lambda scored: scored.contribution, reverse=True)
    return tuple(by_contribution[:count])
