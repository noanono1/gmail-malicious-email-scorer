from __future__ import annotations

from abc import ABC, abstractmethod

from detection_engine.domain.email import EmailData
from detection_engine.domain.signals import AnalysisOutput


class BaseAnalyzer(ABC):
    """A named source of findings derived from an EmailData.

    Each analyzer inspects an EmailData and emits Signals (carrying their
    SignalCategory) and its own blind spots. Multiple analyzers may emit
    in the same category — identity is ``name``, not category.

    Most analyzers are pure and deterministic. The language-assessment
    analyzer is the explicit exception: it depends on an injected LLM
    service that handles its own transport errors and surfaces failures
    as a blind spot. Uncaught exceptions are still bugs and propagate as
    ``AnalyzerCrashed``."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Stable identifier, e.g. 'authentication_analyzer'."""

    @abstractmethod
    def analyze(self, email: EmailData) -> AnalysisOutput:
        """Inspect the email and return signals and blind spots.

        Pure. No exceptions on malformed input — return
        AnalysisOutput.empty() and optionally a BlindSpot."""
