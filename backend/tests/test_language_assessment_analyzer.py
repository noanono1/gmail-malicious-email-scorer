"""Unit tests for LanguageAssessmentAnalyzer.

The SLM service is replaced with a hand-written fake so tests stay
deterministic and never touch the network. The fake exposes the same
two-method surface the analyzer relies on (``is_available``, ``assess``)
and returns whatever the test configures."""

from __future__ import annotations

import pytest

from detection_engine.analyzers.language_assessment import LanguageAssessmentAnalyzer
from detection_engine.domain.email import EmailData, EmailHeaders
from detection_engine.domain.enums import (
    BlindSpotArea,
    SignalCategory,
    SignalSeverity,
)
from detection_engine.domain.language_assessment import (
    LanguageAssessment,
    ManipulationTactic,
    PressureLevel,
    RequestedAction,
)


class _FakeSlm:
    def __init__(
        self,
        *,
        available: bool = True,
        assessment: LanguageAssessment | None = None,
    ) -> None:
        self._available = available
        self._assessment = assessment
        self.calls: list[tuple[str, str]] = []

    def is_available(self) -> bool:
        return self._available

    def assess(self, subject: str, body: str) -> LanguageAssessment | None:
        self.calls.append((subject, body))
        return self._assessment


def _make_email(
    subject: str = "Test",
    body_text: str = "",
    body_html: str = "",
) -> EmailData:
    return EmailData(
        message_id="test-001",
        sender_address="test@example.com",
        sender_display_name="",
        recipient="user@example.com",
        subject=subject,
        body_text=body_text,
        body_html=body_html,
        headers=EmailHeaders([("From", "test@example.com")]),
    )


def _assessment(
    *,
    requested_action: RequestedAction = RequestedAction.NONE,
    pressure_level: PressureLevel = PressureLevel.NONE,
    manipulation_tactics: list[ManipulationTactic] | None = None,
    confidence: float = 0.9,
    evidence_quotes: list[str] | None = None,
) -> LanguageAssessment:
    return LanguageAssessment(
        requested_action=requested_action,
        pressure_level=pressure_level,
        manipulation_tactics=manipulation_tactics or [],
        evidence_quotes=evidence_quotes or [],
        confidence=confidence,
    )


# ---------------------------------------------------------------------------
# Risk-mapping table — the seven worked examples from the design doc
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("assessment", "expected_severity"),
    [
        # action=2 + pressure=0 + tactics=0 → 2 → no signal
        (
            _assessment(
                requested_action=RequestedAction.LOGIN_OR_VERIFY_IDENTITY,
                evidence_quotes=["verify it's you"],
            ),
            None,
        ),
        # action=2 + severe=3 + 2 tactics → 7 → HIGH
        (
            _assessment(
                requested_action=RequestedAction.LOGIN_OR_VERIFY_IDENTITY,
                pressure_level=PressureLevel.SEVERE,
                manipulation_tactics=[
                    ManipulationTactic.FEAR_OF_LOSS,
                    ManipulationTactic.TIME_CONSTRAINT,
                ],
                evidence_quotes=["suspended in 24 hours"],
            ),
            SignalSeverity.HIGH,
        ),
        # action=4 + 0 + 0 → 4 → MEDIUM
        (
            _assessment(
                requested_action=RequestedAction.PROVIDE_SECRETS,
                evidence_quotes=["reply with your password"],
            ),
            SignalSeverity.MEDIUM,
        ),
        # action=4 + severe=3 + 2 tactics → 9 → HIGH
        (
            _assessment(
                requested_action=RequestedAction.PROVIDE_SECRETS,
                pressure_level=PressureLevel.SEVERE,
                manipulation_tactics=[
                    ManipulationTactic.FEAR_OF_LOSS,
                    ManipulationTactic.TIME_CONSTRAINT,
                ],
                evidence_quotes=["send your password now"],
            ),
            SignalSeverity.HIGH,
        ),
        # action=3 + moderate=2 + 2 tactics → 7 → HIGH
        (
            _assessment(
                requested_action=RequestedAction.PROVIDE_PAYMENT,
                pressure_level=PressureLevel.MODERATE,
                manipulation_tactics=[
                    ManipulationTactic.FEAR_OF_LOSS,
                    ManipulationTactic.TIME_CONSTRAINT,
                ],
                evidence_quotes=["pay $4,890 within 48 hours"],
            ),
            SignalSeverity.HIGH,
        ),
        # action=1 + mild=1 + 0 → 2 → no signal
        (
            _assessment(
                requested_action=RequestedAction.CLICK_LINK,
                pressure_level=PressureLevel.MILD,
                evidence_quotes=["shop our weekend sale"],
            ),
            None,
        ),
        # Marketing with soft tactics (reward_lure + time_constraint) is
        # the FP scenario: pre-discount this would total 1+1+2 = 4 →
        # MEDIUM. Discounting soft tactics under marketing-shape leaves
        # 1+1+0 = 2 → no signal.
        (
            _assessment(
                requested_action=RequestedAction.CLICK_LINK,
                pressure_level=PressureLevel.MILD,
                manipulation_tactics=[
                    ManipulationTactic.REWARD_LURE,
                    ManipulationTactic.TIME_CONSTRAINT,
                ],
                evidence_quotes=["save 30% — today only"],
            ),
            None,
        ),
        # Hard tactics (secrecy/unusual_channel/oob) keep their weight
        # even under marketing-shape: "click here, don't tell IT" is
        # never marketing copy. 1+1+1 = 3 → LOW.
        (
            _assessment(
                requested_action=RequestedAction.CLICK_LINK,
                pressure_level=PressureLevel.MILD,
                manipulation_tactics=[ManipulationTactic.SECRECY_PRESSURE],
                evidence_quotes=["click and don't loop in IT"],
            ),
            SignalSeverity.LOW,
        ),
        # Escalating either dimension (action ≥ login_or_verify, or
        # pressure ≥ moderate) un-discounts soft tactics. Here pressure
        # is MODERATE, so reward_lure counts: 1+2+1 = 4 → MEDIUM.
        (
            _assessment(
                requested_action=RequestedAction.CLICK_LINK,
                pressure_level=PressureLevel.MODERATE,
                manipulation_tactics=[ManipulationTactic.REWARD_LURE],
                evidence_quotes=["claim your prize before it expires"],
            ),
            SignalSeverity.MEDIUM,
        ),
        # 0 + 0 + 0 → 0 → no signal
        (
            _assessment(),
            None,
        ),
    ],
    ids=[
        "legit_security_notice_no_signal",
        "phishing_identity_verify_high",
        "pure_secrets_ask_medium",
        "phishing_secrets_high",
        "invoice_scam_high",
        "marketing_no_signal",
        "marketing_with_soft_tactics_no_signal",
        "marketing_with_hard_tactic_low",
        "click_with_moderate_pressure_medium",
        "all_default_no_signal",
    ],
)
def test_assessment_maps_to_expected_severity(
    assessment: LanguageAssessment,
    expected_severity: SignalSeverity | None,
) -> None:
    output = LanguageAssessmentAnalyzer(
        _FakeSlm(assessment=assessment),
    ).analyze(_make_email(body_text="hello"))

    if expected_severity is None:
        assert output.signals == ()
    else:
        assert len(output.signals) == 1
        signal = output.signals[0]
        assert signal.id == "manipulative_language"
        assert signal.category == SignalCategory.BODY_CONTENT
        assert signal.severity == expected_severity

    # The analyzer never emits a blind spot when the SLM returned a
    # validated assessment — the assessment itself is the signal source.
    assert output.blind_spots == ()


# ---------------------------------------------------------------------------
# Confidence floor
# ---------------------------------------------------------------------------


def test_low_confidence_does_not_fire_even_when_severity_would() -> None:
    """Below the confidence floor we treat the assessment as too weak to
    cite, even if the structured fields would otherwise score HIGH."""
    a = _assessment(
        requested_action=RequestedAction.PROVIDE_SECRETS,
        pressure_level=PressureLevel.SEVERE,
        manipulation_tactics=[ManipulationTactic.FEAR_OF_LOSS],
        evidence_quotes=["send your password"],
        confidence=0.4,
    )
    output = LanguageAssessmentAnalyzer(_FakeSlm(assessment=a)).analyze(
        _make_email(body_text="hi"),
    )

    assert output.signals == ()
    assert output.blind_spots == ()


# ---------------------------------------------------------------------------
# Failure modes degrade to a blind spot, never an exception
# ---------------------------------------------------------------------------


def test_slm_unavailable_emits_blind_spot() -> None:
    output = LanguageAssessmentAnalyzer(_FakeSlm(available=False)).analyze(
        _make_email(body_text="hi"),
    )

    assert output.signals == ()
    assert len(output.blind_spots) == 1
    assert output.blind_spots[0].area == BlindSpotArea.LANGUAGE_ASSESSMENT


def test_slm_returns_none_emits_blind_spot() -> None:
    """The SLM service uses None to signal any unrecoverable failure
    (transport, schema, grounding). The analyzer surfaces it as a blind
    spot — it does not distinguish among the underlying causes."""
    output = LanguageAssessmentAnalyzer(_FakeSlm(assessment=None)).analyze(
        _make_email(body_text="hi"),
    )

    assert output.signals == ()
    assert len(output.blind_spots) == 1
    assert output.blind_spots[0].area == BlindSpotArea.LANGUAGE_ASSESSMENT


# ---------------------------------------------------------------------------
# Signal content
# ---------------------------------------------------------------------------


def test_signal_summary_includes_evidence_quote_and_structured_fields() -> None:
    a = _assessment(
        requested_action=RequestedAction.PROVIDE_SECRETS,
        pressure_level=PressureLevel.SEVERE,
        manipulation_tactics=[ManipulationTactic.FEAR_OF_LOSS],
        evidence_quotes=["send your password right now"],
    )
    output = LanguageAssessmentAnalyzer(_FakeSlm(assessment=a)).analyze(
        _make_email(body_text="hi"),
    )

    assert len(output.signals) == 1
    summary = output.signals[0].summary
    assert "send your password right now" in summary
    assert "provide secrets" in summary
    assert "severe pressure" in summary
    assert "fear_of_loss" in summary


# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------


def test_empty_email_skips_slm_entirely() -> None:
    slm = _FakeSlm(assessment=_assessment())
    output = LanguageAssessmentAnalyzer(slm).analyze(
        _make_email(subject="", body_text="", body_html=""),
    )

    assert output.signals == ()
    assert output.blind_spots == ()
    assert slm.calls == []


def test_html_only_body_is_passed_to_slm_as_text() -> None:
    slm = _FakeSlm(assessment=_assessment())
    LanguageAssessmentAnalyzer(slm).analyze(
        _make_email(body_html="<p>Hello <b>world</b></p>"),
    )

    assert len(slm.calls) == 1
    body_passed = slm.calls[0][1]
    assert "<p>" not in body_passed
    assert "Hello" in body_passed and "world" in body_passed
