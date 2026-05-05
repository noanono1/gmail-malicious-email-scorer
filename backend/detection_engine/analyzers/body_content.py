from __future__ import annotations

import re

from detection_engine.analyzers.base import BaseAnalyzer
from detection_engine.domain.email import EmailData
from detection_engine.domain.enums import SignalCategory, SignalSeverity
from detection_engine.domain.signals import AnalysisOutput, Signal


# Structural HTML-form detection only. Linguistic signals (urgency,
# credential solicitation) are owned by LanguageAssessmentAnalyzer —
# keyword lists were noisy and missed paraphrases.
_FORM_PATTERN = re.compile(
    r"<form\b[^>]*>.*?<input\b", re.IGNORECASE | re.DOTALL
)


class BodyContentAnalyzer(BaseAnalyzer):

    @property
    def name(self) -> str:
        return "body_content_analyzer"

    def analyze(self, email: EmailData) -> AnalysisOutput:
        signal = self._html_form_signal(email.body_html)
        return AnalysisOutput(
            signals=(signal,) if signal is not None else (),
            blind_spots=(),
        )

    def _html_form_signal(self, html: str) -> Signal | None:
        if not html or not _FORM_PATTERN.search(html):
            return None
        return Signal(
            id="html_form_in_body",
            category=SignalCategory.BODY_CONTENT,
            severity=SignalSeverity.CRITICAL,
            confidence=1.0,
            summary="HTML <form> with input fields found in email body",
        )
