from __future__ import annotations

from dataclasses import dataclass

from detection_engine.domain.enums import (
    BlindSpotArea,
    SignalCategory,
    SignalSeverity,
)


@dataclass
class Signal:
    id: str
    category: SignalCategory
    severity: SignalSeverity
    evidence: str
    confidence: float
    score_contribution: float = 0.0

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0,1], got {self.confidence}")
        if self.score_contribution < 0.0:
            raise ValueError("score_contribution must be non-negative")


@dataclass(frozen=True)
class BlindSpot:
    area: BlindSpotArea
    reason: str
    risk_note: str


@dataclass(frozen=True)
class AnalysisOutput:
    """Returned by every analyzer and every threat intel source."""

    signals: tuple[Signal, ...]
    blind_spots: tuple[BlindSpot, ...]

    @classmethod
    def empty(cls) -> AnalysisOutput:
        return cls(signals=(), blind_spots=())
