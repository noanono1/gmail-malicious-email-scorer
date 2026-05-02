# --- Pydantic Schemas: API boundary validation & serialization ---
#
# TWO WORLDS, ONE BRIDGE:
# The outside world (HTTP/JSON) speaks Pydantic models.
# The inside world (engine) speaks pure Python dataclasses.
# This file defines both sides and the conversion between them.
#
# WHY SEPARATE FROM DOMAIN MODELS:
# Domain models (detection_engine/) are pure Python — no Pydantic, no FastAPI.
# That keeps the engine testable and framework-independent.
# Pydantic models here handle: JSON parsing, validation (max_length, ge/le),
# serialization (enums → strings), and HTTP-specific concerns.
#
# VALIDATION AT THE BOUNDARY:
# Every field that comes from the outside has constraints (max_length, ge, le).
# This is our first line of defense — malformed/oversized input is rejected
# with 422 BEFORE it reaches the engine. The engine trusts its inputs because
# the API layer already validated them.

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from detection_engine import (
    AnalysisResult,
    Attachment,
    BlindSpotArea,
    EmailData,
    EmailHeaders,
    IntelSourceType,
    Signal,
    SignalCategory,
    SignalSeverity,
    Verdict,
)


# ---------------------------------------------------------------------------
# Request models — what the Add-on sends us
# ---------------------------------------------------------------------------


class HeaderEntry(BaseModel):
    """Single email header. Gmail API returns headers as a list of
    {name, value} objects — repeated headers (Received,
    Authentication-Results) appear as separate entries, not overwritten."""

    name: str = Field(max_length=256, description="Header field name")
    # 16KB per header value — generous but bounded. Some headers (DKIM sigs) are long.
    value: str = Field(max_length=16_384, description="Header field value")


class AttachmentRequest(BaseModel):
    filename: str = Field(max_length=512)
    mime_type: str = Field(max_length=256)
    size_bytes: int = Field(ge=0)  # ge=0 → "greater or equal to 0", rejects negatives
    # Exactly 64 hex chars — SHA-256 hash of the attachment content
    sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")


class AnalyzeRequest(BaseModel):
    """The JSON body the Gmail Add-on sends to POST /analyze.
    Each field has validation constraints — Pydantic rejects violations as 422."""

    message_id: str = Field(max_length=256)
    sender: str = Field(max_length=512)
    recipient: str = Field(max_length=512)
    subject: str = Field(max_length=2048)
    body_text: str = Field(default="", max_length=262_144)   # 256KB limit
    body_html: str = Field(default="", max_length=262_144)   # 256KB limit
    headers: list[HeaderEntry] = Field(
        default_factory=list,
        max_length=200,  # max 200 headers — prevents abuse
        description="Email headers as name-value pairs (matches Gmail API format)",
    )
    attachments: list[AttachmentRequest] = Field(default_factory=list, max_length=20)
    date: datetime | None = None

    def to_domain(self) -> EmailData:
        """Convert Pydantic model → domain dataclass.
        This is the boundary crossing: from HTTP-validated data to pure domain types.
        After this, the engine works only with domain types — no Pydantic."""
        return EmailData(
            message_id=self.message_id,
            sender=self.sender,
            recipient=self.recipient,
            subject=self.subject,
            body_text=self.body_text,
            body_html=self.body_html,
            # EmailHeaders expects list of (name, value) tuples — preserves repeated headers
            headers=EmailHeaders([(header.name, header.value) for header in self.headers]),
            # tuple, not list — domain models are immutable (frozen dataclasses)
            attachments=tuple(
                Attachment(
                    filename=attachment.filename,
                    mime_type=attachment.mime_type,
                    size_bytes=attachment.size_bytes,
                    sha256=attachment.sha256,
                )
                for attachment in self.attachments
            ),
            date=self.date,
        )


# ---------------------------------------------------------------------------
# Response models — what we send back to the Add-on
# ---------------------------------------------------------------------------
# These mirror the domain types but as Pydantic models, so FastAPI
# auto-serializes them to JSON. Enums become their string values automatically
# because our domain enums inherit from (str, Enum).


class SignalResponse(BaseModel):
    id: str
    category: SignalCategory
    severity: SignalSeverity
    evidence: str
    confidence: float
    score_contribution: float


class BlindSpotResponse(BaseModel):
    area: BlindSpotArea
    reason: str
    risk_note: str


class ScopeResponse(BaseModel):
    analyzers_run: list[str]
    intel_sources_run: list[IntelSourceType]
    has_html: bool
    has_attachments: bool
    has_auth_headers: bool


class AnalyzeResponse(BaseModel):
    verdict: Verdict
    score: float
    explanation: str
    signals: list[SignalResponse]
    top_signals: list[SignalResponse]
    categories_active: list[SignalCategory]
    blind_spots: list[BlindSpotResponse]
    scope: ScopeResponse

    @classmethod
    def from_domain(cls, analysis_result: AnalysisResult) -> AnalyzeResponse:
        """Convert domain AnalysisResult → Pydantic response model.
        Reverse of to_domain() — from engine output back to HTTP/JSON."""

        def _signal_to_response(signal: Signal) -> SignalResponse:
            return SignalResponse(
                id=signal.id,
                category=signal.category,
                severity=signal.severity,
                evidence=signal.evidence,
                confidence=signal.confidence,
                score_contribution=signal.score_contribution,
            )

        return cls(
            verdict=analysis_result.verdict,
            score=analysis_result.score,
            explanation=analysis_result.explanation,
            signals=[_signal_to_response(signal) for signal in analysis_result.signals],
            top_signals=[_signal_to_response(signal) for signal in analysis_result.top_signals],
            # frozenset → list for JSON serialization (JSON has no set type)
            categories_active=list(analysis_result.categories_active),
            blind_spots=[
                BlindSpotResponse(
                    area=blind_spot.area,
                    reason=blind_spot.reason,
                    risk_note=blind_spot.risk_note,
                )
                for blind_spot in analysis_result.blind_spots
            ],
            scope=ScopeResponse(
                analyzers_run=list(analysis_result.scope.analyzers_run),
                intel_sources_run=list(analysis_result.scope.intel_sources_run),
                has_html=analysis_result.scope.has_html,
                has_attachments=analysis_result.scope.has_attachments,
                has_auth_headers=analysis_result.scope.has_auth_headers,
            ),
        )
