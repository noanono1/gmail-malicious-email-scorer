from __future__ import annotations

import logging

from openai import APIError, OpenAI, OpenAIError

from detection_engine.domain.language_assessment import LanguageAssessment
from infrastructure.llm._prompt import build_prompt, validate_coherence

logger = logging.getLogger(__name__)


class OpenAiLlm:
    """Body-content language classifier backed by the OpenAI Chat Completions API.

    Drop-in alternative to :class:`infrastructure.llm.local_slm.LocalSlm`.
    Same contract (``is_available`` + ``assess``), same prompt-injection
    defenses (random per-request delimiter, Unicode hygiene, schema-strict
    parsing, evidence grounding) — see ``_prompt.py``. Differences are
    transport-only:

    * ``response_format=LanguageAssessment`` uses the SDK's structured
      output to parse the response into a Pydantic instance directly,
      replacing the JSON-Schema ``format`` field used by Ollama.
    * ``temperature`` is not sent — newer reasoning-class models
      (gpt-5-*, o-series) reject non-default values, and the structured
      output already constrains variability to the schema's enums.
    * Any SDK exception (auth, rate limit, transport, validation) is
      caught and mapped to ``None`` — the analyzer surfaces a blind spot.
      We do not retry: a failed call is a legitimate degraded state, not
      a soft error to paper over.

    Security posture: enabling this provider sends attacker-controlled
    email content to a third-party API. The default deployment keeps the
    local Ollama provider precisely so this tradeoff is opt-in. See the
    config comment for ``LANGUAGE_PROVIDER``.
    """

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        timeout_seconds: int,
    ) -> None:
        self._model = model
        self._timeout_seconds = timeout_seconds
        # ``timeout`` here applies per-request and is honored by the SDK's
        # underlying httpx client. We do not pass ``max_retries`` (default 2)
        # because retries would silently lengthen the user-visible wait that
        # the timeout is meant to bound; a stalled or rate-limited request
        # should fall back to the blind spot quickly.
        self._client = OpenAI(
            api_key=api_key,
            timeout=timeout_seconds,
            max_retries=0,
        )

    def is_available(self) -> bool:
        """True iff an API key is configured.

        We do not pre-flight the network here: a real call's failure mode
        already maps to ``None`` (and from there a blind spot). A separate
        reachability probe would just double the per-email request cost
        and the surface area for transient issues."""
        return bool(self._client.api_key)

    def assess(self, subject: str, body: str) -> LanguageAssessment | None:
        """Classify the email's social-engineering language.

        Returns a validated and grounded assessment, or None on any
        transport, parse, schema, or grounding failure."""
        bundle = build_prompt(subject, body)
        parsed = self._call_openai(bundle.system_prompt, bundle.user_message)
        if parsed is None:
            return None
        return validate_coherence(parsed, subject, body)

    def _call_openai(
        self, system_prompt: str, user_message: str,
    ) -> LanguageAssessment | None:
        # We do not send ``temperature``. Newer reasoning-class models
        # (gpt-5-*, o-series) reject any non-default value with HTTP 400,
        # and grammar-constrained decoding via ``response_format`` already
        # eliminates the worst variability — values outside the schema
        # are unreachable at decode time. Determinism on identical inputs
        # is not absolute, but the structured-output guarantee plus the
        # closed-set enums of ``LanguageAssessment`` keep the output band
        # narrow enough for the engine's downstream rules.
        try:
            response = self._client.beta.chat.completions.parse(
                model=self._model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_message},
                ],
                response_format=LanguageAssessment,
            )
        except (APIError, OpenAIError) as exc:
            logger.warning("OpenAI SLM transport error: %s", exc)
            return None
        # ``parse`` raises on schema violation rather than returning None
        # on most SDK versions, but newer versions still return ``None``
        # on a model refusal. Treat both as "no usable assessment".
        message = response.choices[0].message
        if getattr(message, "refusal", None):
            logger.warning("OpenAI SLM refused the request")
            return None
        return message.parsed
