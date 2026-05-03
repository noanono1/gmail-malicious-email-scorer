from __future__ import annotations

from abc import ABC, abstractmethod

from detection_engine.domain.email import EmailData
from detection_engine.domain.enums import IntelSourceType
from detection_engine.domain.signals import AnalysisOutput


class ThreatIntelSource(ABC):
    """Encapsulates one external lookup (Safe Browsing, VirusTotal, ...).

    The single channel through which the engine touches the network.
    Implementations live in infrastructure/, not in detection_engine/."""

    @property
    @abstractmethod
    def source_type(self) -> IntelSourceType:
        """Identifies this source for AnalysisScope and blind-spot reporting."""

    @abstractmethod
    def is_available(self) -> bool:
        """Whether this source can be queried (API key configured, etc.).

        Called by the engine before query() to decide whether to record
        an INTEL_SOURCE_UNAVAILABLE blind spot."""

    @abstractmethod
    def query(self, email: EmailData) -> AnalysisOutput:
        """Run the external lookup. Network calls are permitted here, and only here.

        Must time out. Must catch its own transport errors and return
        AnalysisOutput with an INTEL_SOURCE_UNAVAILABLE blind spot
        rather than raising."""
