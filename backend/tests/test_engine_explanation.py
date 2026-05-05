"""Engine explanation generation.

The category count in the explanation must come from `active_categories`
(the canonical scoring output) and not from the categories visible in the
top-3 displayed signals — those can disagree when signals exist outside
the top 3 by contribution."""

from __future__ import annotations

from detection_engine import (
    DetectionEngine,
    EmailData,
    EmailHeaders,
    SignalCategory,
    SignalSeverity,
)
from detection_engine.analyzers.base import BaseAnalyzer
from detection_engine.domain.blind_spot_catalog import LANGUAGE_ASSESSMENT_UNAVAILABLE
from detection_engine.domain.enums import Verdict
from detection_engine.domain.signals import AnalysisOutput, BlindSpot, Signal


def _empty_email() -> EmailData:
    return EmailData(
        message_id="explanation-test",
        sender_address="a@b.com",
        sender_display_name="",
        recipient="c@d.com",
        subject="",
        body_text="",
        body_html="",
        headers=EmailHeaders([]),
    )


class _FakeAnalyzer(BaseAnalyzer):
    """Test double that emits a fixed set of signals and blind spots."""

    def __init__(
        self,
        name: str,
        signals: tuple[Signal, ...],
        blind_spots: tuple[BlindSpot, ...] = (),
    ) -> None:
        self._name = name
        self._signals = signals
        self._blind_spots = blind_spots

    @property
    def name(self) -> str:
        return self._name

    def analyze(self, email: EmailData) -> AnalysisOutput:
        return AnalysisOutput(signals=self._signals, blind_spots=self._blind_spots)


def _signal(
    category: SignalCategory,
    severity: SignalSeverity,
    signal_id: str,
    confidence: float = 1.0,
) -> Signal:
    return Signal(
        id=signal_id,
        category=category,
        severity=severity,
        summary=f"{signal_id} summary",
        confidence=confidence,
    )


def _engine_with(*signals: Signal) -> DetectionEngine:
    return DetectionEngine(
        analyzers=[_FakeAnalyzer("fake", tuple(signals))],
    )


class TestExplanationWithoutSignals:
    def test_no_threat_signals_phrasing(self):
        engine = DetectionEngine(analyzers=[])
        result = engine.analyze(_empty_email())
        assert "No threat signals detected" in result.explanation


class TestExplanationCategoryCount:
    def test_single_category_uses_singular_form(self):
        result = _engine_with(
            _signal(SignalCategory.AUTHENTICATION, SignalSeverity.HIGH, "auth1"),
            _signal(SignalCategory.AUTHENTICATION, SignalSeverity.MEDIUM, "auth2"),
        ).analyze(_empty_email())
        assert "Evidence spans 1 category." in result.explanation

    def test_two_categories_uses_plural_form(self):
        result = _engine_with(
            _signal(SignalCategory.AUTHENTICATION, SignalSeverity.CRITICAL, "auth1"),
            _signal(SignalCategory.SENDER_IDENTITY, SignalSeverity.CRITICAL, "sender1"),
        ).analyze(_empty_email())
        assert "Evidence spans 2 categories." in result.explanation

    def test_count_uses_active_categories_not_top_three_categories(self):
        # Four categories are active. The fourth (BODY_CONTENT, LOW=5pts) is
        # not in the top-3 by contribution. The explanation must still report
        # 4 categories — derived from active_categories, not from the top-3.
        result = _engine_with(
            _signal(SignalCategory.SENDER_IDENTITY, SignalSeverity.CRITICAL, "sender1"),
            _signal(SignalCategory.AUTHENTICATION, SignalSeverity.CRITICAL, "auth1"),
            _signal(SignalCategory.URL_STRUCTURE, SignalSeverity.HIGH, "url1"),
            _signal(SignalCategory.BODY_CONTENT, SignalSeverity.LOW, "body1"),
        ).analyze(_empty_email())

        assert len(result.top_signals) == 3
        top_three_categories = {scored.signal.category for scored in result.top_signals}
        assert SignalCategory.BODY_CONTENT not in top_three_categories
        assert len(result.active_categories) == 4
        assert "Evidence spans 4 categories." in result.explanation


class TestVerdictFloorOnInspectionGap:
    """When the language analyzer cannot run, an email with zero signals
    must not be reported as SAFE — the body was never assessed at all.
    The floor routes to INCONCLUSIVE rather than SUSPICIOUS so a score
    of 0 alongside the verdict reads as 'not scored', not as a bug."""

    def test_language_assessment_blind_spot_floors_safe_to_inconclusive(self):
        engine = DetectionEngine(
            analyzers=[_FakeAnalyzer(
                "fake", signals=(), blind_spots=(LANGUAGE_ASSESSMENT_UNAVAILABLE,),
            )],
        )
        result = engine.analyze(_empty_email())

        assert result.verdict == Verdict.INCONCLUSIVE
        assert result.score == 0
        assert "could not be inspected" in result.explanation
        assert "not enough coverage to judge" in result.explanation

    def test_routine_blind_spots_alone_do_not_floor_verdict(self):
        # Empty engine still emits the structural THREAD_HISTORY blind
        # spot. That alone (no LANGUAGE_ASSESSMENT) must keep verdict SAFE.
        engine = DetectionEngine(analyzers=[])
        result = engine.analyze(_empty_email())

        assert result.verdict == Verdict.SAFE
        assert "No threat signals detected" in result.explanation

    def test_floor_does_not_downgrade_existing_signal_verdict(self):
        # When real signals fire, the floor must not touch the verdict —
        # the score-driven classification already reflects evidence.
        engine = DetectionEngine(
            analyzers=[_FakeAnalyzer(
                "fake",
                signals=(_signal(SignalCategory.SENDER_IDENTITY, SignalSeverity.CRITICAL, "s1"),),
                blind_spots=(LANGUAGE_ASSESSMENT_UNAVAILABLE,),
            )],
        )
        result = engine.analyze(_empty_email())

        assert result.verdict in (
            Verdict.SUSPICIOUS, Verdict.LIKELY_MALICIOUS, Verdict.MALICIOUS,
        )
        assert result.score > 0
