from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime

_SHA256_HEX_PATTERN = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class Attachment:
    filename: str
    mime_type: str
    size_bytes: int
    sha256: str | None = None

    def __post_init__(self) -> None:
        if self.size_bytes < 0:
            raise ValueError("size_bytes must be non-negative")
        if self.sha256 is not None and not _SHA256_HEX_PATTERN.match(self.sha256):
            raise ValueError("sha256 must be a 64-char lowercase hex digest")


class EmailHeaders:
    """Case-insensitive, multi-value header map.

    Email headers are case-insensitive per RFC 2822 and may repeat
    (e.g. Received, Authentication-Results). All values for a given
    header name are preserved in insertion order.

    Single-value access (``__getitem__``, ``get``) returns the first value.
    Use ``get_all`` when the header may repeat."""

    def __init__(self, header_pairs: Sequence[tuple[str, str]]) -> None:
        self._data: dict[str, tuple[str, ...]] = {}
        for name, value in header_pairs:
            normalized_name = name.lower()
            existing_values = self._data.get(normalized_name, ())
            self._data[normalized_name] = (*existing_values, value)

    def __getitem__(self, key: str) -> str:
        return self._data[key.lower()][0]

    def __contains__(self, key: object) -> bool:
        if not isinstance(key, str):
            return False
        return key.lower() in self._data

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def get(self, key: str, default: str | None = None) -> str | None:
        header_values = self._data.get(key.lower())
        return header_values[0] if header_values else default

    def get_all(self, key: str) -> tuple[str, ...]:
        """All values for *key*, preserving insertion order. Empty tuple if absent."""
        return self._data.get(key.lower(), ())


@dataclass(frozen=True)
class EmailData:
    message_id: str
    sender_address: str
    sender_display_name: str
    recipient: str
    subject: str
    body_text: str
    body_html: str
    headers: EmailHeaders
    reply_to_address: str = ""
    return_path_address: str = ""
    attachments: tuple[Attachment, ...] = ()
    date: datetime | None = None
