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

    Single responsibility: take subject+body, return a trustworthy
    LanguageAssessment or None on any failure. Never raises; the analyzer
    that wraps this service decides how to surface failures (a blind spot,
    in our case).

    The service applies seven minimal-but-real defenses against prompt
    injection and model failure modes:

    1. Truncation — caps subject and body length so a giant payload cannot
       bury the system prompt or exhaust the model's context.
    2. Random per-request delimiter — email content is wrapped in
       <email-{token}>...</email-{token}> with a fresh hex token per call.
       A literal close-tag embedded by an attacker cannot match the real
       wrapper because the token is unknowable in advance.
    3. Unicode hygiene — Cc (control) and Cf (format) characters are
       stripped from inputs before they reach the model, closing
       RLO/LRO, zero-width, BOM, and NULL-byte injection vectors.
    4. Delimiter-aware system prompt — the system prompt names the exact
       per-request delimiter and instructs the model to treat its contents
       as data, not instructions.
    5. Grammar-constrained output — Ollama's ``format`` parameter pins the
       response to the LanguageAssessment JSON Schema; values outside the
       enums are unreachable at decode time. We do not pin ``temperature``
       — the OpenAI provider cannot (newer reasoning-class models reject
       non-default values), and we keep the two providers symmetric so
       outputs stay comparable when switching backends.
    6. Schema-strict parsing — Pydantic with extra='forbid' rejects any
       additional fields and validates value ranges.
    7. Evidence grounding — non-default findings must include at least
       one verbatim quote from the (sanitized) subject or body. Ungrounded
       quotes invalidate the entire assessment, defending against
       hallucinated claims.

    Defenses 1-4, 6, and 7 are provider-agnostic and live in
    ``infrastructure/llm/_prompt.py`` so a new backend cannot forget them.
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
