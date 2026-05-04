from __future__ import annotations

from abc import ABC, abstractmethod

from detection_engine.domain.email import EmailData
from detection_engine.domain.signals import AnalysisOutput


class BaseAnalyzer(ABC):
    """A pure, deterministic, offline named source of findings.

    Each analyzer inspects an EmailData and emits Signals (which carry their
    own SignalCategory). Multiple analyzers may emit signals in the same
    category — the analyzer's identity is its `name`, not its category.

    Each analyzer owns its own blind spots — only it knows what it could not
    check for a given email. Analyzers never make network calls; they inspect
    the EmailData they receive and nothing else."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Stable identifier, e.g. 'authentication_analyzer'. Used in AnalysisScope."""

    @abstractmethod
    def analyze(self, email: EmailData) -> AnalysisOutput:
        """Inspect the email and return signals and blind spots.

        Pure function. No I/O. No exceptions on malformed input — return
        AnalysisOutput.empty() and (optionally) a BlindSpot describing what
        could not be checked."""
