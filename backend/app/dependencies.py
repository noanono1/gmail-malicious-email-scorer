from __future__ import annotations

from functools import lru_cache
from typing import Annotated

from fastapi import Depends

from detection_engine import DetectionEngine
from detection_engine.analyzers.attachment import AttachmentAnalyzer
from detection_engine.analyzers.body_content import BodyContentAnalyzer
from detection_engine.analyzers.authentication import AuthenticationAnalyzer
from detection_engine.analyzers.sender import SenderAnalyzer
from detection_engine.analyzers.url_structure import UrlStructureAnalyzer


@lru_cache(maxsize=1)
def _get_detection_engine() -> DetectionEngine:
    """Wire analyzers and intel sources here as they are built."""
    return DetectionEngine(
        analyzers=[
            AuthenticationAnalyzer(),
            SenderAnalyzer(),
            BodyContentAnalyzer(),
            UrlStructureAnalyzer(),
            AttachmentAnalyzer(),
        ],
        intel_sources=[],
    )


DetectionEngineDependency = Annotated[DetectionEngine, Depends(_get_detection_engine)]
