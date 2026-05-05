from __future__ import annotations

from functools import lru_cache
from logging import getLogger
from typing import Annotated

from fastapi import Depends

from app import config
from detection_engine import DetectionEngine
from detection_engine.analyzers.attachment import AttachmentAnalyzer
from detection_engine.analyzers.base import BaseAnalyzer
from detection_engine.analyzers.body_content import BodyContentAnalyzer
from detection_engine.analyzers.authentication import AuthenticationAnalyzer
from detection_engine.analyzers.language_assessment import (
    LanguageAssessmentAnalyzer,
    LlmService,
)
from detection_engine.analyzers.sender import SenderAnalyzer
from detection_engine.analyzers.url_structure import UrlStructureAnalyzer
from infrastructure.llm import LocalSlm, OpenAiLlm

logger = getLogger(__name__)


def _build_llm() -> LlmService | None:
    """Construct the configured LLM provider, or None if it cannot be wired.

    None disables the analyzer for this process (no blind spot — analyzer
    is not registered). A registered provider that fails at request time
    yields the blind spot: misconfiguration vs. degraded runtime."""
    if config.LANGUAGE_PROVIDER == "openai":
        if not config.OPENAI_API_KEY:
            logger.warning(
                "LANGUAGE_PROVIDER=openai but OPENAI_API_KEY is empty — "
                "language analyzer disabled",
            )
            return None
        return OpenAiLlm(
            api_key=config.OPENAI_API_KEY,
            model=config.OPENAI_MODEL,
            timeout_seconds=config.OPENAI_TIMEOUT,
        )
    if config.LANGUAGE_PROVIDER == "local":
        return LocalSlm(
            host=config.LLM_HOST,
            model=config.LLM_MODEL,
            timeout_seconds=config.LLM_TIMEOUT,
        )
    logger.warning(
        "Unknown LANGUAGE_PROVIDER=%r — language analyzer disabled",
        config.LANGUAGE_PROVIDER,
    )
    return None


@lru_cache(maxsize=1)
def _get_detection_engine() -> DetectionEngine:
    analyzers: list[BaseAnalyzer] = [
        AuthenticationAnalyzer(),
        SenderAnalyzer(),
        BodyContentAnalyzer(),
        UrlStructureAnalyzer(),
        AttachmentAnalyzer(),
    ]
    if config.LANGUAGE_ANALYZER_ENABLED:
        llm = _build_llm()
        if llm is not None:
            analyzers.append(LanguageAssessmentAnalyzer(llm))
    return DetectionEngine(analyzers=analyzers)


DetectionEngineDependency = Annotated[DetectionEngine, Depends(_get_detection_engine)]
