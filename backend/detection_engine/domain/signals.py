from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from detection_engine.domain.email import EmailData
from detection_engine.domain.enums import (
    BlindSpotArea,
    SignalCategory,
    SignalSeverity,
)


@dataclass(frozen=True)
class Signal:
    """An interpreted finding emitted by an analyzer or intel source.

    A Signal is a graded accusation: category, severity, and confidence are
    already decided by the time the engine sees it. The `summary` is a
    human-readable description of what was observed, not raw evidence —
    keep it short and renderable as-is.

    Signals are immutable. Per-run scoring data lives on ScoredSignal."""

    id: str
    category: SignalCategory
    severity: SignalSeverity
    summary: str
    confidence: float


@dataclass(frozen=True)
class ScoredSignal:
    """A Signal paired with its contribution from one scoring run.

    Contribution depends on what other signals were present (attenuation,
    category cap, cross-category boost), so it is a property of the run,
    not of the signal."""

    signal: Signal
    contribution: float


@dataclass(frozen=True)
class BlindSpot:
    area: BlindSpotArea
    reason: str
    risk_note: str
    applies: Callable[[EmailData], bool] | None = None


@dataclass(frozen=True)
class AnalysisOutput:
    """Returned by every analyzer and every threat intel source."""

    signals: tuple[Signal, ...]
    blind_spots: tuple[BlindSpot, ...]

    @classmethod
    def empty(cls) -> AnalysisOutput:
        return cls(signals=(), blind_spots=())
