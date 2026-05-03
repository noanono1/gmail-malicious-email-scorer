from __future__ import annotations

from abc import ABC, abstractmethod

from detection_engine.domain.email import EmailData
from detection_engine.domain.enums import SignalCategory
from detection_engine.domain.signals import AnalysisOutput


class BaseAnalyzer(ABC):
    """A pure, deterministic, offline analyzer for one signal category.

    Each analyzer owns its own blind spots — only it knows what it could not
    check for a given email. Analyzers never make network calls; they inspect
    the EmailData they receive and nothing else."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Stable identifier, e.g. 'authentication_analyzer'. Used in AnalysisScope."""

    @property
    @abstractmethod
    def category(self) -> SignalCategory:
        """The signal category this analyzer produces."""

    @abstractmethod
    def analyze(self, email: EmailData) -> AnalysisOutput:
        """Inspect the email and return signals and blind spots.

        Pure function. No I/O. No exceptions on malformed input — return
        AnalysisOutput.empty() and (optionally) a BlindSpot describing what
        could not be checked."""
