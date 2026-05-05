from __future__ import annotations

import html as html_module
import re
from typing import Protocol

from detection_engine.analyzers.base import BaseAnalyzer
from detection_engine.domain.blind_spot_catalog import LANGUAGE_ASSESSMENT_UNAVAILABLE
from detection_engine.domain.email import EmailData
from detection_engine.domain.enums import SignalCategory, SignalSeverity
from detection_engine.domain.language_assessment import (
    LanguageAssessment,
    ManipulationTactic,
    PressureLevel,
    RequestedAction,
)
from detection_engine.domain.signals import AnalysisOutput, Signal


# Below this confidence the SLM verdict is too uncertain to cite as a
# user-facing finding.
_MIN_CONFIDENCE_TO_FIRE = 0.6


# Risk weights per axis. Tuned so:
#   sensitive ask alone (provide_secrets) → MEDIUM
#   sensitive ask + severe pressure + tactics → HIGH
#   marketing / benign → below LOW
_ACTION_RISK: dict[RequestedAction, int] = {
    RequestedAction.PROVIDE_SECRETS:           4,
    RequestedAction.PROVIDE_PAYMENT:           3,
    RequestedAction.PROVIDE_PERSONAL_INFO:     3,
    RequestedAction.INSTALL_SOFTWARE:          3,
    RequestedAction.LOGIN_OR_VERIFY_IDENTITY:  2,
    RequestedAction.CONTACT_OFF_CHANNEL:       2,
    RequestedAction.OPEN_ATTACHMENT:           1,
    RequestedAction.CLICK_LINK:                1,
    RequestedAction.NONE:                      0,
}

_PRESSURE_RISK: dict[PressureLevel, int] = {
    PressureLevel.NONE:     0,
    PressureLevel.MILD:     1,
    PressureLevel.MODERATE: 2,
    PressureLevel.SEVERE:   3,
}

_TACTIC_POINTS: int = 1   # schema caps the tactic list at 3

# Tactics that legitimate marketing copy uses constantly ("today only!",
# "save 30% — limited offer", "don't miss out"). They are diagnostic only
# in combination with a sensitive ask or escalated pressure — counting
# them on a routine sale email lands a LOW signal on every newsletter.
# The remaining tactics — secrecy_pressure ("don't tell IT"),
# unusual_channel ("text me on WhatsApp"), out_of_band_verification
# ("call this number to confirm") — carry standalone weight: marketing
# does not say those things.
_BENIGN_PERSUASION_TACTICS: frozenset[ManipulationTactic] = frozenset({
    ManipulationTactic.FEAR_OF_LOSS,
    ManipulationTactic.REWARD_LURE,
    ManipulationTactic.TIME_CONSTRAINT,
})

# Action levels indistinguishable from routine marketing on their own.
# When the ask is at this level *and* pressure is at most MILD, benign-
# persuasion tactics are discounted. As soon as either dimension
# escalates (login_or_verify_identity+, moderate pressure+) every
# tactic counts again.
_MARKETING_GRADE_ACTIONS: frozenset[RequestedAction] = frozenset({
    RequestedAction.NONE,
    RequestedAction.CLICK_LINK,
    RequestedAction.OPEN_ATTACHMENT,
})

_LIGHT_PRESSURE_LEVELS: frozenset[PressureLevel] = frozenset({
    PressureLevel.NONE,
    PressureLevel.MILD,
})


_SEVERITY_BUCKETS: tuple[tuple[int, SignalSeverity], ...] = (
    (7, SignalSeverity.HIGH),
    (4, SignalSeverity.MEDIUM),
    (3, SignalSeverity.LOW),
)


# Strip <script>/<style> *contents* before tags. A naive `<[^>]+>` sub
# would only delete the tags and pass the JS/CSS payload to the SLM as if
# it were body text — biasing the assessment and consuming the body-char
# budget. DOTALL so the body of a multi-line script block is captured.
_SCRIPT_OR_STYLE_PATTERN = re.compile(
    r"<(script|style)\b[^>]*>.*?</\1\s*>", re.IGNORECASE | re.DOTALL,
)
_HTML_TAG_PATTERN = re.compile(r"<[^>]+>")


def _html_to_plaintext(html_body: str) -> str:
    """Strip HTML to readable text safely for SLM consumption.

    Drops script/style payloads, removes remaining tags, and decodes
    entities (so quote-grounding sees the same text the recipient does)."""
    without_executable = _SCRIPT_OR_STYLE_PATTERN.sub(" ", html_body)
    without_tags = _HTML_TAG_PATTERN.sub(" ", without_executable)
    return html_module.unescape(without_tags)


class LlmService(Protocol):
    def is_available(self) -> bool: ...
    def assess(self, subject: str, body: str) -> LanguageAssessment | None: ...


class LanguageAssessmentAnalyzer(BaseAnalyzer):
    """Assesses social-engineering language in the email.

    Language intent is semantic — literal phrase matches miss paraphrased
    variants and over-flag legitimate copy. This analyzer wraps a constrained
    SLM extractor that decomposes the body into structured fields, validates
    evidence quotes against the source, and maps the combination to one
    BODY_CONTENT signal (LOW–HIGH).

    Architectural note: the only analyzer with a networked dependency. The
    LLM is injected via the ``LlmService`` port; the provider returns
    ``None`` on any transport, parse, or grounding failure and the
    analyzer turns that into a LANGUAGE_ASSESSMENT blind spot — never
    raises. A degraded SLM is a coverage gap, not a crash."""

    def __init__(self, llm: LlmService) -> None:
        self._llm = llm

    @property
    def name(self) -> str:
        return "language_assessment_analyzer"

    def analyze(self, email: EmailData) -> AnalysisOutput:
        body = self._effective_body(email)
        if not body and not email.subject:
            return AnalysisOutput.empty()

        if not self._llm.is_available():
            return AnalysisOutput(
                signals=(),
                blind_spots=(LANGUAGE_ASSESSMENT_UNAVAILABLE,),
            )

        assessment = self._llm.assess(email.subject, body)
        if assessment is None:
            return AnalysisOutput(
                signals=(),
                blind_spots=(LANGUAGE_ASSESSMENT_UNAVAILABLE,),
            )

        signal = _signal_from(assessment)
        return AnalysisOutput(
            signals=(signal,) if signal is not None else (),
            blind_spots=(),
        )

    @staticmethod
    def _effective_body(email: EmailData) -> str:
        if email.body_text:
            return email.body_text
        if email.body_html:
            return _html_to_plaintext(email.body_html)
        return ""


def _signal_from(assessment: LanguageAssessment) -> Signal | None:
    if assessment.confidence < _MIN_CONFIDENCE_TO_FIRE:
        return None

    severity = _severity_for(assessment)
    if severity is None:
        return None

    return Signal(
        id="manipulative_language",
        category=SignalCategory.BODY_CONTENT,
        severity=severity,
        confidence=assessment.confidence,
        summary=_render_summary(assessment),
    )


def _severity_for(assessment: LanguageAssessment) -> SignalSeverity | None:
    scoring_tactics = _scoring_tactics(assessment)
    points = (
        _ACTION_RISK[assessment.requested_action]
        + _PRESSURE_RISK[assessment.pressure_level]
        + _TACTIC_POINTS * len(scoring_tactics)
    )
    for threshold, severity in _SEVERITY_BUCKETS:
        if points >= threshold:
            return severity
    return None


def _scoring_tactics(
    assessment: LanguageAssessment,
) -> tuple[ManipulationTactic, ...]:
    """Tactics that count toward the risk score for this assessment.

    Marketing-style persuasion (urgency, reward lures, fear-of-loss) is
    discounted when the ask is light (none / click / attachment) and
    pressure is at most MILD. The hard tactics — secrecy, unusual
    channel, out-of-band verification — always count: they have no
    legitimate marketing analogue."""
    is_marketing_shaped = (
        assessment.requested_action in _MARKETING_GRADE_ACTIONS
        and assessment.pressure_level in _LIGHT_PRESSURE_LEVELS
    )
    if not is_marketing_shaped:
        return tuple(assessment.manipulation_tactics)
    return tuple(
        t for t in assessment.manipulation_tactics
        if t not in _BENIGN_PERSUASION_TACTICS
    )


def _render_summary(assessment: LanguageAssessment) -> str:
    """Build an evidence-grounded user-facing summary.

    Composes structured fields into prose and appends one verbatim quote —
    never echoes free-form model text."""
    fragments: list[str] = []
    if assessment.requested_action != RequestedAction.NONE:
        action_phrase = assessment.requested_action.value.replace("_", " ")
        fragments.append(f"asks recipient to {action_phrase}")
    if assessment.pressure_level != PressureLevel.NONE:
        fragments.append(f"{assessment.pressure_level.value} pressure")
    if assessment.manipulation_tactics:
        tactics = ", ".join(t.value for t in assessment.manipulation_tactics)
        fragments.append(f"tactics: {tactics}")

    description = "Body language: " + "; ".join(fragments)
    if assessment.evidence_quotes:
        description = f'{description} — quote: "{assessment.evidence_quotes[0]}"'
    return description
