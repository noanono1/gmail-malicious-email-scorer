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
from detection_engine.domain.signals import AnalysisOutput, Signal


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
    """Test double that emits a fixed set of signals."""

    def __init__(self, name: str, signals: tuple[Signal, ...]) -> None:
        self._name = name
        self._signals = signals

    @property
    def name(self) -> str:
        return self._name

    def analyze(self, email: EmailData) -> AnalysisOutput:
        return AnalysisOutput(signals=self._signals, blind_spots=())


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
        intel_sources=[],
    )


class TestExplanationWithoutSignals:
    def test_no_threat_signals_phrasing(self):
        engine = DetectionEngine(analyzers=[], intel_sources=[])
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
