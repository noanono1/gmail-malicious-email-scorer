from __future__ import annotations

import re
from html.parser import HTMLParser

from detection_engine.analyzers.base import BaseAnalyzer
from detection_engine.domain.email import EmailData
from detection_engine.domain.enums import SignalCategory, SignalSeverity
from detection_engine.domain.signals import AnalysisOutput, Signal

# Exact-match phrase lists work while the list stays under ~50 entries per
# category. Beyond that, migrate to compiled regex patterns or a lightweight
# scoring model to keep maintenance and runtime cost manageable.

_URGENCY_PHRASES: tuple[str, ...] = (
    "account will be suspended",
    "account will be closed",
    "account will be permanently closed",
    "account will be terminated",
    "account has been limited",
    "account has been compromised",
    "immediate action required",
    "immediate attention required",
    "action required within",
    "suspended within 24 hours",
    "within 24 hours",
    "within 48 hours",
    "unauthorized activity",
    "unusual activity",
    "verify your identity immediately",
    "failure to respond will result",
    "failure to remit payment",
    "your account will be locked",
    "service interruption",
    "service suspension",
    "time-sensitive",
    "time sensitive",
    "respond immediately",
)

_SENSITIVE_DATA_PHRASES: tuple[str, ...] = (
    "verify your password",
    "confirm your password",
    "enter your password",
    "update your password",
    "verify your account",
    "confirm your identity",
    "verify your identity",
    "confirm your ssn",
    "social security number",
    "update your payment",
    "update payment information",
    "verify your payment",
    "confirm your credit card",
    "enter your credit card",
    "bank account details",
    "routing number",
    "update your billing",
    "verify your billing",
)

_FORM_PATTERN = re.compile(
    r"<form\b[^>]*>.*?<input\b", re.IGNORECASE | re.DOTALL
)


_INVISIBLE_TAGS = frozenset({"script", "style"})


class _HtmlTextExtractor(HTMLParser):

    def __init__(self) -> None:
        super().__init__()
        self._parts: list[str] = []
        self._skip_depth: int = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _INVISIBLE_TAGS:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in _INVISIBLE_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._skip_depth == 0:
            self._parts.append(data)

    def get_text(self) -> str:
        return " ".join(self._parts)


def _strip_html_tags(html: str) -> str:
    extractor = _HtmlTextExtractor()
    extractor.feed(html)
    return extractor.get_text()


class BodyContentAnalyzer(BaseAnalyzer):

    @property
    def name(self) -> str:
        return "body_content_analyzer"

    def analyze(self, email: EmailData) -> AnalysisOutput:
        html_text = _strip_html_tags(email.body_html) if email.body_html else ""
        text = f"{email.subject} {email.body_text} {html_text}".lower()
        signals: list[Signal] = []

        self._check_urgency(text, signals)
        self._check_sensitive_data_request(text, signals)
        self._check_html_form(email.body_html, signals)

        return AnalysisOutput(signals=tuple(signals), blind_spots=())

    def _check_urgency(self, text: str, signals: list[Signal]) -> None:
        matched = [phrase for phrase in _URGENCY_PHRASES if phrase in text]
        if not matched:
            return

        signals.append(
            Signal(
                id="urgency_language",
                category=SignalCategory.BODY_CONTENT,
                severity=SignalSeverity.MEDIUM,
                confidence=min(0.5 + 0.15 * len(matched), 1.0),
                summary=f"Urgency/threat language detected: {', '.join(repr(p) for p in matched)}",
            )
        )

    def _check_sensitive_data_request(
        self, text: str, signals: list[Signal]
    ) -> None:
        matched = [phrase for phrase in _SENSITIVE_DATA_PHRASES if phrase in text]
        if not matched:
            return

        signals.append(
            Signal(
                id="sensitive_data_request",
                category=SignalCategory.BODY_CONTENT,
                severity=SignalSeverity.HIGH,
                confidence=min(0.6 + 0.2 * len(matched), 1.0),
                summary=f"Sensitive data request detected: {', '.join(repr(p) for p in matched)}",
            )
        )

    def _check_html_form(self, html: str, signals: list[Signal]) -> None:
        if not html:
            return

        if _FORM_PATTERN.search(html):
            signals.append(
                Signal(
                    id="html_form_in_body",
                    category=SignalCategory.BODY_CONTENT,
                    severity=SignalSeverity.CRITICAL,
                    confidence=1.0,
                    summary="HTML <form> with input fields found in email body",
                )
            )
