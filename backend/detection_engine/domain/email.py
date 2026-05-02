from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator, Optional


@dataclass(frozen=True)
class Attachment:
    filename: str
    mime_type: str
    size_bytes: int
    sha256: str

    def __post_init__(self) -> None:
        if self.size_bytes < 0:
            raise ValueError("size_bytes must be non-negative")
        if len(self.sha256) != 64:
            raise ValueError("sha256 must be a 64-char hex digest")


class EmailHeaders(Mapping[str, str]):
    """Case-insensitive header map (RFC 2822 -- header field names are
    case-insensitive). Stores keys lowercased; lookup is case-insensitive."""

    def __init__(self, raw: Mapping[str, str]) -> None:
        self._data: dict[str, str] = {k.lower(): v for k, v in raw.items()}

    def __getitem__(self, key: str) -> str:
        return self._data[key.lower()]

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def get(self, key: str, default: str | None = None) -> str | None:
        return self._data.get(key.lower(), default)


@dataclass(frozen=True)
class EmailData:
    message_id: str
    sender: str
    recipient: str
    subject: str
    body_text: str
    body_html: str
    headers: EmailHeaders
    attachments: tuple[Attachment, ...] = ()
    date: Optional[datetime] = None
