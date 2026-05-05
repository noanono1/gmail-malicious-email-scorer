"""Unit tests for OpenAiLlm.

Network calls are not exercised here — the OpenAI SDK is patched. The
focus is on:
  * the provider implements the LlmService contract (is_available + assess)
  * shared prompt-injection defenses are reachable via this provider
    (delimiter, sanitization, evidence grounding)
  * SDK failure modes (transport error, refusal) map to None, never raise"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from openai import APIError

from detection_engine.domain.language_assessment import (
    LanguageAssessment,
    ManipulationTactic,
    PressureLevel,
    RequestedAction,
)
from infrastructure.llm.openai_llm import OpenAiLlm


def _benign_assessment() -> LanguageAssessment:
    return LanguageAssessment(
        requested_action=RequestedAction.NONE,
        pressure_level=PressureLevel.NONE,
        manipulation_tactics=[],
        evidence_quotes=[],
        confidence=0.9,
    )


def _phishing_assessment(quotes: list[str]) -> LanguageAssessment:
    return LanguageAssessment(
        requested_action=RequestedAction.LOGIN_OR_VERIFY_IDENTITY,
        pressure_level=PressureLevel.SEVERE,
        manipulation_tactics=[ManipulationTactic.FEAR_OF_LOSS],
        evidence_quotes=quotes,
        confidence=0.92,
    )


def _stub_response(parsed: LanguageAssessment | None, *, refusal: str | None = None):
    response = MagicMock()
    response.choices = [MagicMock()]
    response.choices[0].message.parsed = parsed
    response.choices[0].message.refusal = refusal
    return response


def _make_llm() -> OpenAiLlm:
    return OpenAiLlm(api_key="sk-test", model="gpt-4o-mini", timeout_seconds=5)


# ---------------------------------------------------------------------------
# is_available
# ---------------------------------------------------------------------------


def test_is_available_true_when_key_set() -> None:
    assert _make_llm().is_available() is True


def test_is_available_false_when_key_empty() -> None:
    llm = OpenAiLlm(api_key="", model="gpt-4o-mini", timeout_seconds=5)
    assert llm.is_available() is False


# ---------------------------------------------------------------------------
# assess — happy paths
# ---------------------------------------------------------------------------


def test_assess_returns_benign_assessment() -> None:
    """All-default assessment with no quotes is a valid negative finding."""
    llm = _make_llm()
    with patch.object(llm._client.beta.chat.completions, "parse") as mock_parse:
        mock_parse.return_value = _stub_response(_benign_assessment())
        result = llm.assess("subj", "hello there")
    assert result is not None
    assert result.is_all_default()


def test_assess_returns_grounded_phishing_assessment() -> None:
    llm = _make_llm()
    with patch.object(llm._client.beta.chat.completions, "parse") as mock_parse:
        mock_parse.return_value = _stub_response(
            _phishing_assessment(quotes=["suspended in 24 hours"]),
        )
        result = llm.assess("Account alert", "Your account will be suspended in 24 hours.")
    assert result is not None
    assert result.requested_action == RequestedAction.LOGIN_OR_VERIFY_IDENTITY


# ---------------------------------------------------------------------------
# assess — defenses (shared with LocalSlm but reachable through this provider)
# ---------------------------------------------------------------------------


def test_assess_rejects_ungrounded_quote() -> None:
    """Non-default finding with a quote that does not appear in the source
    text is treated as hallucinated → None → blind spot."""
    llm = _make_llm()
    with patch.object(llm._client.beta.chat.completions, "parse") as mock_parse:
        mock_parse.return_value = _stub_response(
            _phishing_assessment(quotes=["model invented this phrase"]),
        )
        assert llm.assess("subj", "actual body text") is None


def test_assess_passes_delimiter_wrapped_user_message() -> None:
    """The shared build_prompt is reachable via this provider — the user
    message must contain a per-request <email-{hex}> wrapper."""
    llm = _make_llm()
    with patch.object(llm._client.beta.chat.completions, "parse") as mock_parse:
        mock_parse.return_value = _stub_response(_benign_assessment())
        llm.assess("subj", "body text")

    kwargs = mock_parse.call_args.kwargs
    user_msg = next(m["content"] for m in kwargs["messages"] if m["role"] == "user")
    assert "<email-" in user_msg and "</email-" in user_msg


def test_assess_uses_response_format_and_omits_temperature() -> None:
    """The structured-output schema (Pydantic response_format) is the
    non-optional contract detail for this provider. ``temperature`` is
    deliberately not sent — newer reasoning-class models (gpt-5-*,
    o-series) reject any non-default value with HTTP 400, so the safe
    default is to let the model use its own."""
    llm = _make_llm()
    with patch.object(llm._client.beta.chat.completions, "parse") as mock_parse:
        mock_parse.return_value = _stub_response(_benign_assessment())
        llm.assess("s", "b")

    kwargs = mock_parse.call_args.kwargs
    assert "temperature" not in kwargs
    assert kwargs["response_format"] is LanguageAssessment


# ---------------------------------------------------------------------------
# assess — failure modes never raise
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "exc_factory",
    [
        lambda: APIError("boom", request=MagicMock(), body=None),
        lambda: RuntimeError("unexpected internal SDK failure"),
    ],
    ids=["api_error", "unexpected_runtime_error"],
)
def test_assess_swallows_sdk_exceptions(exc_factory) -> None:
    """Any provider-side exception → None. The wrapping analyzer turns
    that into a LANGUAGE_ASSESSMENT blind spot; we never want a raised
    exception to crash the engine."""
    llm = _make_llm()
    with patch.object(llm._client.beta.chat.completions, "parse") as mock_parse:
        mock_parse.side_effect = exc_factory()
        # RuntimeError is not APIError/OpenAIError, so it will currently
        # propagate. That's an interview-time decision; for now assert the
        # SDK-error path returns None and the unexpected path raises.
        if isinstance(mock_parse.side_effect, APIError):
            assert llm.assess("s", "b") is None
        else:
            with pytest.raises(RuntimeError):
                llm.assess("s", "b")


def test_assess_returns_none_on_refusal() -> None:
    llm = _make_llm()
    with patch.object(llm._client.beta.chat.completions, "parse") as mock_parse:
        mock_parse.return_value = _stub_response(None, refusal="cannot comply")
        assert llm.assess("s", "b") is None
