from __future__ import annotations

from dataclasses import dataclass

from detection_engine.domain.enums import (
    IntelSourceType,
    SignalCategory,
    Verdict,
)
from detection_engine.domain.signals import BlindSpot, Signal


@dataclass(frozen=True)
class AnalysisScope:
    """What ran and what was present."""

    analyzers_run: tuple[str, ...]
    intel_sources_run: tuple[IntelSourceType, ...]
    has_html: bool
    has_attachments: bool
    has_auth_headers: bool


@dataclass(frozen=True)
class AnalysisResult:
    verdict: Verdict
    score: float
    signals: tuple[Signal, ...]
    top_signals: tuple[Signal, ...]
    active_categories: frozenset[SignalCategory]
    blind_spots: tuple[BlindSpot, ...]
    scope: AnalysisScope
    explanation: str

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 100.0:
            raise ValueError(f"score must be in [0,100], got {self.score}")
