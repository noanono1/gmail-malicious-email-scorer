from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from detection_engine import DetectionEngine
from detection_engine.analyzers.header import HeaderAnalyzer


def _get_detection_engine() -> DetectionEngine:
    """Wire analyzers and intel sources here as they are built."""
    return DetectionEngine(analyzers=[HeaderAnalyzer()], intel_sources=[])


DetectionEngineDependency = Annotated[DetectionEngine, Depends(_get_detection_engine)]
