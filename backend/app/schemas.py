from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from detection_engine.domain.email import Attachment, EmailData, EmailHeaders


class AttachmentRequest(BaseModel):
    filename: str = Field(max_length=512)
    mime_type: str = Field(max_length=256)
    size_bytes: int = Field(ge=0)
    sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")


class AnalyzeRequest(BaseModel):
    message_id: str = Field(max_length=256)
    sender: str = Field(max_length=512)
    recipient: str = Field(max_length=512)
    subject: str = Field(max_length=2048)
    body_text: str = Field(default="", max_length=262_144)
    body_html: str = Field(default="", max_length=262_144)
    headers: dict[str, str] = Field(default_factory=dict, max_length=100)
    attachments: list[AttachmentRequest] = Field(default_factory=list, max_length=20)
    date: datetime | None = None

    def to_domain(self) -> EmailData:
        return EmailData(
            message_id=self.message_id,
            sender=self.sender,
            recipient=self.recipient,
            subject=self.subject,
            body_text=self.body_text,
            body_html=self.body_html,
            headers=EmailHeaders(self.headers),
            attachments=tuple(
                Attachment(
                    filename=a.filename,
                    mime_type=a.mime_type,
                    size_bytes=a.size_bytes,
                    sha256=a.sha256,
                )
                for a in self.attachments
            ),
            date=self.date,
        )


class AnalyzeResponse(BaseModel):
    verdict: str
    score: float
    explanation: str
    signals: list = Field(default_factory=list)
    blind_spots: list = Field(default_factory=list)
