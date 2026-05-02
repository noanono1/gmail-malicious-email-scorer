from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from detection_engine import DetectionEngine


def _get_detection_engine() -> DetectionEngine:
    """Wire analyzers and intel sources here as they are built."""
    return DetectionEngine(analyzers=[], intel_sources=[])


DetectionEngineDependency = Annotated[DetectionEngine, Depends(_get_detection_engine)]
