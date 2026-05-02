from __future__ import annotations

import logging
from collections.abc import Sequence

from detection_engine.analyzers.base import BaseAnalyzer
from detection_engine.domain.email import EmailData
from detection_engine.domain.enums import (
    BlindSpotArea,
    IntelSourceType,
    SignalCategory,
    Verdict,
)
from detection_engine.domain.signals import BlindSpot, Signal
from detection_engine.domain.verdict import AnalysisResult, ScopeInfo
from detection_engine.intel_sources.base import ThreatIntelSource
from detection_engine.scoring import classify, score

logger = logging.getLogger(__name__)

_THREAD_HISTORY_BLIND_SPOT = BlindSpot(
    area=BlindSpotArea.THREAD_HISTORY,
    reason="Single-email analysis only",
    risk_note="Thread context may reveal social engineering patterns",
)

_CATEGORY_CRASH_BLIND_SPOT_AREA: dict[SignalCategory, BlindSpotArea] = {
    SignalCategory.AUTHENTICATION: BlindSpotArea.AUTHENTICATION_HEADERS,
    SignalCategory.SENDER_IDENTITY: BlindSpotArea.AUTHENTICATION_HEADERS,
    SignalCategory.URL_REPUTATION: BlindSpotArea.URL_DESTINATION,
    SignalCategory.CONTENT: BlindSpotArea.HTML_RENDERING,
    SignalCategory.ATTACHMENT: BlindSpotArea.ATTACHMENT_CONTENT,
}


class DetectionEngine:
    """Orchestrates analyzers and intel sources to produce an AnalysisResult.

    Constructor takes lists of analyzers and intel sources (both injected).
    Single public method: analyze(email) -> AnalysisResult."""

    def __init__(
        self,
        analyzers: Sequence[BaseAnalyzer] = (),
        intel_sources: Sequence[ThreatIntelSource] = (),
    ) -> None:
        self._analyzers = tuple(analyzers)
        self._intel_sources = tuple(intel_sources)

    def analyze(self, email: EmailData) -> AnalysisResult:
        collected_signals: list[Signal] = []
        collected_blind_spots: list[BlindSpot] = [_THREAD_HISTORY_BLIND_SPOT]

        self._run_analyzers(email, collected_signals, collected_blind_spots)
        intel_sources_executed = self._run_intel_sources(email, collected_signals, collected_blind_spots)

        final_score, active_categories = score(collected_signals)
        verdict = classify(final_score)

        top_signals = _pick_top_signals(collected_signals, count=3)
        signals = tuple(collected_signals)
        blind_spots = tuple(collected_blind_spots)

        scope = ScopeInfo(
            analyzers_run=tuple(a.name for a in self._analyzers),
            intel_sources_run=tuple(intel_sources_executed),
            has_html=bool(email.body_html),
            has_attachments=bool(email.attachments),
            has_auth_headers="authentication-results" in email.headers,
        )

        explanation = self._explain(verdict, top_signals, blind_spots)

        return AnalysisResult(
            verdict=verdict,
            score=final_score,
            signals=signals,
            top_signals=top_signals,
            categories_active=active_categories,
            blind_spots=blind_spots,
            scope=scope,
            explanation=explanation,
        )

    def _run_analyzers(
        self,
        email: EmailData,
        signals: list[Signal],
        blind_spots: list[BlindSpot],
    ) -> None:
        for analyzer in self._analyzers:
            try:
                analyzer_output = analyzer.analyze(email)
            except Exception:
                logger.exception("Analyzer crashed: %s", analyzer.name)
                blind_spots.append(
                    BlindSpot(
                        area=_CATEGORY_CRASH_BLIND_SPOT_AREA[analyzer.category],
                        reason=f"Analyzer '{analyzer.name}' crashed",
                        risk_note=f"Coverage gap in {analyzer.category.value} detection",
                    )
                )
                continue
            signals.extend(analyzer_output.signals)
            blind_spots.extend(analyzer_output.blind_spots)

    def _run_intel_sources(
        self,
        email: EmailData,
        signals: list[Signal],
        blind_spots: list[BlindSpot],
    ) -> list[IntelSourceType]:
        executed_source_types = []
        for source in self._intel_sources:
            if not source.is_available():
                blind_spots.append(
                    BlindSpot(
                        area=BlindSpotArea.INTEL_SOURCE_UNAVAILABLE,
                        reason=f"{source.source_type.value} not configured",
                        risk_note="Threat intelligence not consulted — URLs and "
                        "hashes were not checked against reputation databases",
                    )
                )
                continue
            try:
                intel_output = source.query(email)
            except Exception:
                logger.exception("Intel source crashed: %s", source.source_type.value)
                blind_spots.append(
                    BlindSpot(
                        area=BlindSpotArea.INTEL_SOURCE_UNAVAILABLE,
                        reason=f"{source.source_type.value} query failed",
                        risk_note="Threat intelligence not consulted — URLs and "
                        "hashes were not checked against reputation databases",
                    )
                )
                continue
            signals.extend(intel_output.signals)
            blind_spots.extend(intel_output.blind_spots)
            executed_source_types.append(source.source_type)
        return executed_source_types

    def _explain(
        self,
        verdict: Verdict,
        top_signals: tuple[Signal, ...],
        blind_spots: tuple[BlindSpot, ...],
    ) -> str:
        if not top_signals:
            if blind_spots:
                return (
                    f"Verdict: {verdict.value}. No threat signals detected, "
                    f"but {len(blind_spots)} area(s) could not be inspected."
                )
            return f"Verdict: {verdict.value}. No threat signals detected."

        findings = "; ".join(
            f"{s.category.value}: {s.evidence} ({s.severity.value}, "
            f"+{s.score_contribution:.1f} pts)"
            for s in top_signals
        )

        categories = {s.category.value for s in top_signals}
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

        return f"Verdict: {verdict.value}. {findings}. {category_note}{blind_note}"


def _pick_top_signals(signals: list[Signal], count: int) -> tuple[Signal, ...]:
    signals_by_contribution = sorted(signals, key=lambda signal: signal.score_contribution, reverse=True)
    return tuple(signals_by_contribution[:count])
