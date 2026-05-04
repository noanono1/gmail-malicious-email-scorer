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
    ScoredSignal,
    SignalCategory,
    SignalSeverity,
    Verdict,
)

# DTOs / API schemas

# ---------------------------------------------------------------------------
# Request models — what the Add-on sends us
# ---------------------------------------------------------------------------


class HeaderEntry(BaseModel):
    """Single email header as {name, value} — matches Gmail API format."""

    name: str = Field(max_length=256, description="Header field name")
    value: str = Field(max_length=16_384, description="Header field value")


# Sanity bound on reported attachment size. Gmail caps individual attachments
# at 25 MB; 25 MiB gives us byte-aligned headroom while still rejecting absurd
# values (e.g. a malicious client claiming a 100 GB attachment).
_MAX_ATTACHMENT_SIZE_BYTES = 26_214_400


class AttachmentRequest(BaseModel):
    filename: str = Field(max_length=512)
    mime_type: str = Field(max_length=256)
    size_bytes: int = Field(ge=0, le=_MAX_ATTACHMENT_SIZE_BYTES)
    sha256: str | None = Field(
        default=None, min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$",
    )


class AnalyzeRequest(BaseModel):
    """POST /analyze request body from the Gmail Add-on."""

    message_id: str = Field(max_length=256)
    sender_address: str = Field(max_length=256)
    sender_display_name: str = Field(default="", max_length=512)
    recipient: str = Field(max_length=512)
    subject: str = Field(max_length=2048)
    body_text: str = Field(default="", max_length=262_144)   # 256KB limit
    body_html: str = Field(default="", max_length=262_144)   # 256KB limit
    reply_to_address: str = Field(default="", max_length=256)
    return_path_address: str = Field(default="", max_length=256)
    headers: list[HeaderEntry] = Field(
        default_factory=list,
        max_length=200,
        description="Email headers as name-value pairs (matches Gmail API format)",
    )
    attachments: list[AttachmentRequest] = Field(default_factory=list, max_length=20)
    date: datetime | None = None

    def to_domain(self) -> EmailData:
        """Convert to domain dataclass for the engine."""
        return EmailData(
            message_id=self.message_id,
            sender_address=self.sender_address,
            sender_display_name=self.sender_display_name,
            recipient=self.recipient,
            subject=self.subject,
            body_text=self.body_text,
            body_html=self.body_html,
            reply_to_address=self.reply_to_address,
            return_path_address=self.return_path_address,
            headers=EmailHeaders([(header.name, header.value) for header in self.headers]),
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


class SignalResponse(BaseModel):
    """Wire shape for a scored signal — flattens ScoredSignal for the addon."""

    id: str
    category: SignalCategory
    severity: SignalSeverity
    summary: str
    confidence: float
    score_contribution: float


class BlindSpotResponse(BaseModel):
    area: BlindSpotArea
    reason: str
    risk_note: str


class AnalysisScopeResponse(BaseModel):
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
    active_categories: list[SignalCategory]
    blind_spots: list[BlindSpotResponse]
    scope: AnalysisScopeResponse

    @classmethod
    def from_domain(cls, analysis_result: AnalysisResult) -> AnalyzeResponse:
        """Convert domain AnalysisResult to API response."""

        def _scored_to_response(scored: ScoredSignal) -> SignalResponse:
            return SignalResponse(
                id=scored.signal.id,
                category=scored.signal.category,
                severity=scored.signal.severity,
                summary=scored.signal.summary,
                confidence=scored.signal.confidence,
                score_contribution=scored.contribution,
            )

        return cls(
            verdict=analysis_result.verdict,
            score=analysis_result.score,
            explanation=analysis_result.explanation,
            signals=[_scored_to_response(scored) for scored in analysis_result.signals],
            top_signals=[_scored_to_response(scored) for scored in analysis_result.top_signals],
            active_categories=sorted(analysis_result.active_categories, key=lambda c: c.value),
            blind_spots=[
                BlindSpotResponse(
                    area=blind_spot.area,
                    reason=blind_spot.reason,
                    risk_note=blind_spot.risk_note,
                )
                for blind_spot in analysis_result.blind_spots
            ],
            scope=AnalysisScopeResponse(
                analyzers_run=analysis_result.scope.analyzers_run,
                intel_sources_run=analysis_result.scope.intel_sources_run,
                has_html=analysis_result.scope.has_html,
                has_attachments=analysis_result.scope.has_attachments,
                has_auth_headers=analysis_result.scope.has_auth_headers,
            ),
        )
