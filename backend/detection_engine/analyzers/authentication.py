from __future__ import annotations

import logging
import re

from detection_engine.analyzers.base import BaseAnalyzer
from detection_engine.domain.email import EmailData
from detection_engine.domain.enums import (
    BlindSpotArea,
    SignalCategory,
    SignalSeverity,
)
from detection_engine.domain.signals import BlindSpot, AnalysisOutput, Signal

logger = logging.getLogger(__name__)

_AUTH_METHODS = ("spf", "dkim", "dmarc")

_RESULT_PATTERN = re.compile(
    r"(?:^|;\s*){method}=(pass|fail|softfail|none|neutral|temperror|permerror)"
)

_SEVERITY: dict[str, SignalSeverity] = {
    "spf": SignalSeverity.HIGH,
    "dkim": SignalSeverity.HIGH,
    "dmarc": SignalSeverity.CRITICAL,
}

_CONFIDENCE: dict[str, float] = {
    "fail": 1.0,
    "softfail": 0.7,
    "none": 0.8,
}

_EVIDENCE_TEMPLATES: dict[str, str] = {
    "spf": "SPF check returned '{result}' for sender domain",
    "dkim": "DKIM verification returned '{result}' for sender domain",
    "dmarc": "DMARC policy returned '{result}' for sender domain",
}


class AuthenticationAnalyzer(BaseAnalyzer):

    @property
    def name(self) -> str:
        return "authentication_analyzer"

    @property
    def category(self) -> SignalCategory:
        return SignalCategory.AUTHENTICATION

    def analyze(self, email: EmailData) -> AnalysisOutput:
        header_value = email.headers.get("authentication-results")

        if header_value is None:
            return AnalysisOutput(
                signals=(),
                blind_spots=(
                    BlindSpot(
                        area=BlindSpotArea.AUTHENTICATION_HEADERS,
                        reason="No Authentication-Results header present",
                        risk_note=(
                            "Email authentication status unknown — "
                            "SPF, DKIM, and DMARC could not be evaluated"
                        ),
                    ),
                ),
            )

        signals: list[Signal] = []
        for method in _AUTH_METHODS:
            signal = self._check_method(header_value, method)
            if signal is not None:
                signals.append(signal)

        return AnalysisOutput(signals=tuple(signals), blind_spots=())

    def _check_method(self, header_value: str, method: str) -> Signal | None:
        pattern = re.compile(
            rf"(?:^|;\s*){method}=(pass|fail|softfail|none|neutral|temperror|permerror)"
        )
        match = pattern.search(header_value)
        if match is None:
            return None

        result = match.group(1)

        if result not in _CONFIDENCE:
            return None

        return Signal(
            id=f"{method}_{result}",
            category=SignalCategory.AUTHENTICATION,
            severity=_SEVERITY[method],
            confidence=_CONFIDENCE[result],
            evidence=_EVIDENCE_TEMPLATES[method].format(result=result),
        )
