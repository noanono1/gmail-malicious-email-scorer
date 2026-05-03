from __future__ import annotations

import re
from collections.abc import Sequence
from logging import getLogger

from detection_engine.analyzers.base import BaseAnalyzer
from detection_engine.domain.email import EmailData
from detection_engine.domain.enums import (
    BlindSpotArea,
    IntelSourceType,
    Verdict,
)
from detection_engine.domain.exceptions import AnalyzerCrashed
from detection_engine.domain.signals import BlindSpot, Signal
from detection_engine.domain.verdict import AnalysisResult, AnalysisScope
from detection_engine.intel_sources.base import ThreatIntelSource
from detection_engine.scoring import classify_verdict, score_signals

logger = getLogger(__name__)

_THREAD_HISTORY_BLIND_SPOT = BlindSpot(
    area=BlindSpotArea.THREAD_HISTORY,
    reason="Single-email analysis only",
    risk_note="Thread context may reveal social engineering patterns",
)

# TODO: HTML_RENDERING blind spot is defined in BlindSpotArea but never emitted.
# It should be reported when email.body_html is non-empty, warning that CSS tricks,
# hidden elements, and JS-based redirects are not detected because we parse HTML
# structure but don't render it. Decision needed: emit it here in the engine
# (alongside EMBEDDED_IMAGE/QR_CODE — a structural check on the email) or inside
# BodyContentAnalyzer (which already processes the HTML body for forms/content).
# Engine-level is more consistent with how EMBEDDED_IMAGE works, and avoids coupling
# the blind spot to an analyzer that might not run.
_IMG_TAG_PATTERN = re.compile(r"<img\b", re.IGNORECASE)

_EMBEDDED_IMAGE_BLIND_SPOT = BlindSpot(
    area=BlindSpotArea.EMBEDDED_IMAGE,
    reason="Embedded images not analyzed",
    risk_note="Images may contain text, QR codes, or visual phishing undetectable by text analysis",
)

_QR_CODE_BLIND_SPOT = BlindSpot(
    area=BlindSpotArea.QR_CODE,
    reason="QR code detection not available",
    risk_note="QR codes in images can encode phishing URLs — cannot be inspected without image processing",
)


def _email_contains_images(email: EmailData) -> bool:
    if email.body_html and _IMG_TAG_PATTERN.search(email.body_html):
        return True
    return any(a.mime_type.startswith("image/") for a in email.attachments)


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

        if _email_contains_images(email):
            collected_blind_spots.append(_EMBEDDED_IMAGE_BLIND_SPOT)
            collected_blind_spots.append(_QR_CODE_BLIND_SPOT)

        self._run_analyzers(email, collected_signals, collected_blind_spots)
        intel_sources_executed = self._run_intel_sources(email, collected_signals, collected_blind_spots)

        final_score, active_categories = score_signals(collected_signals)
        verdict = classify_verdict(final_score)

        top_signals = _pick_top_signals(collected_signals, count=3)
        signals = tuple(collected_signals)
        blind_spots = tuple(collected_blind_spots)

        scope = AnalysisScope(
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
            active_categories=active_categories,
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
            except Exception as exc:
                raise AnalyzerCrashed(analyzer.name, exc) from exc
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
                        risk_note=f"Threat intelligence not consulted — "
                        f"{source.source_type.value} was not queried",
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
                        risk_note=f"Threat intelligence not consulted — "
                        f"{source.source_type.value} was not queried",
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

        header = f"Verdict: {verdict.value}."

        findings = "\n".join(
            f"• {s.category.value}: {s.evidence} "
            f"({s.severity.value}, +{s.score_contribution:.1f} pts)"
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

        return f"{header}\n{findings}\n{category_note}{blind_note}"


def _pick_top_signals(signals: list[Signal], count: int) -> tuple[Signal, ...]:
    signals_by_contribution = sorted(signals, key=lambda signal: signal.score_contribution, reverse=True)
    return tuple(signals_by_contribution[:count])
