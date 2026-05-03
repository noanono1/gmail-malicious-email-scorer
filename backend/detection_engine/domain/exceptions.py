from __future__ import annotations


class AnalyzerCrashed(Exception):
    """Raised when an analyzer fails with an unhandled exception."""

    def __init__(self, analyzer_name: str, cause: Exception) -> None:
        self.analyzer_name = analyzer_name
        super().__init__(f"Analyzer '{analyzer_name}' crashed: {cause}")
