from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from detection_engine.analyzers.base import BaseAnalyzer
from detection_engine.domain.blind_spot_catalog import (
    AUTHENTICATION_HEADERS_MISSING,
    authentication_unenforceable,
)
from detection_engine.domain.email import EmailData
from detection_engine.domain.enums import SignalCategory, SignalSeverity
from detection_engine.domain.signals import AnalysisOutput, BlindSpot, Signal


class _AuthMethod(str, Enum):
    """RFC 7601 authentication methods this analyzer evaluates."""

    SPF = "spf"
    DKIM = "dkim"
    DMARC = "dmarc"


# Per RFC 7601 each (method, result) pair maps to one or two outcomes:
#   benign       : pass / neutral — no signal, no blind spot
#   blind spot   : temperror — transient noise, never carries score
#   blind spot + : none — coverage gap AND a weak risk indicator
#     weak signal
#   signal       : fail / softfail / permerror / policy — verification ran
# Unknown results are treated as benign.

_BENIGN_RESULTS = frozenset({"pass", "neutral"})
_BLIND_SPOT_RESULTS = frozenset({"none", "temperror"})


@dataclass(frozen=True)
class _SignalPolicy:
    severity: SignalSeverity
    confidence: float


_SIGNAL_POLICY: dict[tuple[_AuthMethod, str], _SignalPolicy] = {
    (_AuthMethod.SPF,   "fail"):      _SignalPolicy(SignalSeverity.HIGH,     1.0),
    (_AuthMethod.SPF,   "softfail"):  _SignalPolicy(SignalSeverity.HIGH,     0.7),
    (_AuthMethod.SPF,   "permerror"): _SignalPolicy(SignalSeverity.LOW,      0.4),
    (_AuthMethod.SPF,   "none"):      _SignalPolicy(SignalSeverity.LOW,      0.5),
    (_AuthMethod.DKIM,  "fail"):      _SignalPolicy(SignalSeverity.HIGH,     1.0),
    (_AuthMethod.DKIM,  "permerror"): _SignalPolicy(SignalSeverity.LOW,      0.4),
    (_AuthMethod.DKIM,  "policy"):    _SignalPolicy(SignalSeverity.MEDIUM,   0.6),
    (_AuthMethod.DKIM,  "none"):      _SignalPolicy(SignalSeverity.LOW,      0.5),
    (_AuthMethod.DMARC, "fail"):      _SignalPolicy(SignalSeverity.CRITICAL, 1.0),
    (_AuthMethod.DMARC, "permerror"): _SignalPolicy(SignalSeverity.LOW,      0.4),
    (_AuthMethod.DMARC, "none"):      _SignalPolicy(SignalSeverity.MEDIUM,   0.6),
}

_EVIDENCE_TEMPLATES: dict[_AuthMethod, str] = {
    _AuthMethod.SPF:   "SPF check returned '{result}' for sender domain",
    _AuthMethod.DKIM:  "DKIM verification returned '{result}' for sender domain",
    _AuthMethod.DMARC: "DMARC policy returned '{result}' for sender domain",
}

# Match every "method=result" token, case-insensitive. Parenthesized
# comments are stripped before matching.
_RESULT_TOKEN_PATTERN = re.compile(
    rf"\b(?P<auth_method>{'|'.join(m.value for m in _AuthMethod)})\s*=\s*(?P<result>[a-z]+)",
    re.IGNORECASE,
)
_PAREN_COMMENT_PATTERN = re.compile(r"\([^)]*\)")


class AuthenticationAnalyzer(BaseAnalyzer):

    @property
    def name(self) -> str:
        return "authentication_analyzer"

    def analyze(self, email: EmailData) -> AnalysisOutput:
        all_header_values = email.headers.get_all("authentication-results")
        if not all_header_values:
            return AnalysisOutput(
                signals=(),
                blind_spots=(AUTHENTICATION_HEADERS_MISSING,),
            )

        auth_method_results = self._parse_auth_method_results(all_header_values)

        signals: list[Signal] = []
        blind_spots: list[BlindSpot] = []
        for auth_method, result in auth_method_results.items():
            if result in _BENIGN_RESULTS:
                continue
            # `none` deliberately lives in both — coverage gap AND weak
            # indicator. `temperror` is transient-only.
            if result in _BLIND_SPOT_RESULTS:
                blind_spots.append(authentication_unenforceable(auth_method.value, result))
            policy = _SIGNAL_POLICY.get((auth_method, result))
            if policy is not None:
                signals.append(self._build_signal(auth_method, result, policy))

        return AnalysisOutput(signals=tuple(signals), blind_spots=tuple(blind_spots))

    def _parse_auth_method_results(
        self, header_values: tuple[str, ...]
    ) -> dict[_AuthMethod, str]:
        """Parse Authentication-Results headers into a {method: result} map.

        First occurrence wins: the trusted receiving MTA (Mail Transfer Agent, like Gmail) prepends its own
        header; later headers from upstream relays cannot be trusted.
        """
        results: dict[_AuthMethod, str] = {}
        for header_value in header_values:
            cleaned = _PAREN_COMMENT_PATTERN.sub(" ", header_value)
            for match in _RESULT_TOKEN_PATTERN.finditer(cleaned):
                auth_method = _AuthMethod(match.group("auth_method").lower())
                if auth_method not in results:
                    results[auth_method] = match.group("result").lower()
        return results

    def _build_signal(self, auth_method: _AuthMethod, result: str, policy: _SignalPolicy) -> Signal:
        return Signal(
            id=f"{auth_method.value}_{result}",
            category=SignalCategory.AUTHENTICATION,
            severity=policy.severity,
            confidence=policy.confidence,
            summary=_EVIDENCE_TEMPLATES[auth_method].format(result=result),
        )
