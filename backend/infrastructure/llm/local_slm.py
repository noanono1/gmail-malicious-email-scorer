from __future__ import annotations

import logging

import requests

from detection_engine.domain.language_assessment import LanguageAssessment
from infrastructure.llm._prompt import (
    build_prompt,
    parse_strict,
    validate_coherence,
)

logger = logging.getLogger(__name__)


_AVAILABILITY_CHECK_TIMEOUT_SECONDS = 2

# JSON Schema for the LanguageAssessment model. Computed once at import —
# the schema is constant across calls. Passed to Ollama's ``format`` field
# so the model's output is grammar-constrained at decode time.
_LANGUAGE_ASSESSMENT_SCHEMA: dict = LanguageAssessment.model_json_schema()


class LocalSlm:
    """Body-content language classifier backed by a local Ollama-compatible SLM.

    Returns a validated ``LanguageAssessment`` or ``None`` on any failure;
    never raises. The wrapping analyzer turns ``None`` into a blind spot.

    Provider-agnostic prompt-injection defenses (random per-request delimiter,
    Unicode hygiene, schema-strict parsing, evidence grounding) live in
    ``infrastructure/llm/_prompt.py``. This provider adds Ollama's ``format``
    field for grammar-constrained decoding against the ``LanguageAssessment``
    schema. ``temperature`` is deliberately not pinned so the two providers
    stay symmetric — see ``OpenAiLlm._call_openai``.
    """

    def __init__(self, *, host: str, model: str, timeout_seconds: int) -> None:
        self._host = host.rstrip("/")
        self._model = model
        self._timeout_seconds = timeout_seconds

    def is_available(self) -> bool:
        """Best-effort reachability check. Used by the analyzer to short-circuit
        and emit a blind spot rather than burn the full timeout per email."""
        try:
            response = requests.get(
                f"{self._host}/api/tags",
                timeout=_AVAILABILITY_CHECK_TIMEOUT_SECONDS,
            )
        except requests.RequestException:
            return False
        return response.status_code == 200

    def assess(self, subject: str, body: str) -> LanguageAssessment | None:
        """Classify the email's social-engineering language.

        Returns a validated and grounded assessment, or None on any
        transport, parse, schema, or grounding failure."""
        bundle = build_prompt(subject, body)
        raw_response = self._call_ollama(bundle.combined)
        if raw_response is None:
            return None
        parsed = parse_strict(raw_response)
        if parsed is None:
            return None
        return validate_coherence(parsed, subject, body)

    def _call_ollama(self, prompt: str) -> str | None:
        try:
            response = requests.post(
                f"{self._host}/api/generate",
                json={
                    "model": self._model,
                    "prompt": prompt,
                    "stream": False,
                    "format": _LANGUAGE_ASSESSMENT_SCHEMA,
                },
                timeout=self._timeout_seconds,
            )
        except requests.RequestException as exc:
            logger.warning("SLM transport error: %s", exc)
            return None
        if response.status_code != 200:
            logger.warning("SLM returned HTTP %s", response.status_code)
            return None
        try:
            return response.json().get("response", "")
        except ValueError:
            logger.warning("SLM returned non-JSON HTTP body")
            return None
