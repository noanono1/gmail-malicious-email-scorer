# --- Dependency Injection ---
#
# WHAT IS DEPENDENCY INJECTION (DI):
# Instead of a route handler creating its own engine (engine = DetectionEngine()),
# FastAPI "injects" it via a function parameter. The route just declares
# "I need an engine" and FastAPI provides one.
#
# WHY THIS MATTERS:
# 1. Swappability — Tier 0 has zero analyzers. Tier 1 adds them here.
#    The route code doesn't change at all.
# 2. Testability — tests can inject a mock engine without patching imports.
# 3. Lifecycle control — we could make the engine a singleton, add caching,
#    or wire up different configs per environment, all in this one file.
#
# HOW FASTAPI DI WORKS:
# Depends(some_function) → FastAPI calls some_function() before the handler,
# and passes the return value as the parameter. Annotated[Type, Depends(...)]
# is the modern syntax that combines the type hint with the DI instruction.

from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from detection_engine import DetectionEngine


def _get_detection_engine() -> DetectionEngine:
    """Factory function called by FastAPI on every request.

    Tier 0: no analyzers, no intel sources — engine returns SAFE / score 0.
    Tier 1: add analyzers here. Tier 2: add intel sources."""
    return DetectionEngine(analyzers=[], intel_sources=[])


# Annotated[Type, Depends(factory)] — tells FastAPI:
#   "When a handler asks for DetectionEngineDependency, call _get_detection_engine()
#    and pass the result."
DetectionEngineDependency = Annotated[DetectionEngine, Depends(_get_detection_engine)]
