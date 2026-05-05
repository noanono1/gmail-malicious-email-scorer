"""Schema for the LLM-based social-engineering language assessment.

The port contract between the detection engine and any language-analysis
backend. Concrete providers live under ``infrastructure/llm/``.

Each enum below carries scoring weight: ``RequestedAction`` and
``PressureLevel`` are weighted directly, ``ManipulationTactic`` is
counted (one point per tactic, capped at 3). Fields that did not earn
their weight (descriptive ``message_purpose``, identity-claim
``claimed_authority``) were removed — they had no effect on the verdict
and added prompt surface for the SLM to fill in."""

from __future__ import annotations

from enum import Enum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field


class RequestedAction(str, Enum):
    """What the sender is trying to make the recipient do.

    The split between ``login_or_verify_identity`` (legitimate services
    routinely do this), ``provide_secrets`` (passwords / MFA codes —
    near-zero legitimate use), and ``provide_personal_info`` (SSN, ID
    upload — strict-PII collection rarely happens by email) is deliberate:
    these carry very different base risk and were previously collapsed
    into one label."""

    NONE                     = "none"
    CLICK_LINK               = "click_link"
    OPEN_ATTACHMENT          = "open_attachment"
    LOGIN_OR_VERIFY_IDENTITY = "login_or_verify_identity"
    PROVIDE_SECRETS          = "provide_secrets"
    PROVIDE_PERSONAL_INFO    = "provide_personal_info"
    PROVIDE_PAYMENT          = "provide_payment"
    INSTALL_SOFTWARE         = "install_software"
    CONTACT_OFF_CHANNEL      = "contact_off_channel"


class PressureLevel(str, Enum):
    """Intensity of urgency or coercion in the message language."""

    NONE     = "none"
    MILD     = "mild"
    MODERATE = "moderate"
    SEVERE   = "severe"


class ManipulationTactic(str, Enum):
    """Itemized social-engineering tactics observed in the message."""

    FEAR_OF_LOSS             = "fear_of_loss"
    REWARD_LURE              = "reward_lure"
    SECRECY_PRESSURE         = "secrecy_pressure"
    UNUSUAL_CHANNEL          = "unusual_channel"
    TIME_CONSTRAINT          = "time_constraint"
    OUT_OF_BAND_VERIFICATION = "out_of_band_verification"


_MAX_TACTICS         = 3
_MAX_QUOTES          = 3
_MAX_QUOTE_CHARS     = 120


class LanguageAssessment(BaseModel):
    """One model output describing the social-engineering language of an email.

    Field-level constraints here are the *transport-level* guarantees
    (lengths, ranges, enum membership). Higher-level coherence (evidence
    required when findings are non-default; quotes must appear in the
    source text) is enforced by ``infrastructure.llm._prompt`` before
    the assessment leaves the provider port."""

    model_config = ConfigDict(extra="forbid")

    requested_action:     RequestedAction
    pressure_level:       PressureLevel
    manipulation_tactics: Annotated[list[ManipulationTactic], Field(max_length=_MAX_TACTICS)]
    evidence_quotes:      Annotated[
        list[Annotated[str, Field(max_length=_MAX_QUOTE_CHARS)]],
        Field(max_length=_MAX_QUOTES),
    ]
    confidence:           float = Field(ge=0.0, le=1.0)

    def is_all_default(self) -> bool:
        """True when no accusatory finding is present.

        Used to distinguish a genuine negative finding (no signal, no
        blind spot) from a missing-evidence failure (blind spot)."""
        return (
            self.requested_action      == RequestedAction.NONE
            and self.pressure_level    == PressureLevel.NONE
            and not self.manipulation_tactics
        )
