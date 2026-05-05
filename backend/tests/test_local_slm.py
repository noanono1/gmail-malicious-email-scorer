"""Unit tests for LocalSlm in-process defenses and validation.

Network calls are not exercised here — the focus is on:
  * prompt-injection defenses (delimiter randomness, Unicode hygiene)
  * grounding-text normalization (whitespace, smart quotes)
  * Pydantic-strict parsing of model output
  * evidence-grounding and coherence validation"""

from __future__ import annotations

import json
import re

import pytest

from detection_engine.domain.language_assessment import (
    LanguageAssessment,
    ManipulationTactic,
    PressureLevel,
    RequestedAction,
)
from infrastructure.llm._prompt import (
    build_prompt,
    normalize_for_grounding as _normalize_for_grounding,
    parse_strict as _parse_strict,
    sanitize_for_prompt as _sanitize_for_prompt,
    validate_coherence as _validate_coherence,
)
from infrastructure.llm.local_slm import LocalSlm  # noqa: F401  re-imported for parity with prior test surface


_DELIMITER_RE = re.compile(r"<email-([0-9a-f]{16})>")


def _make_slm() -> LocalSlm:
    return LocalSlm(host="http://localhost:11434", model="phi3:mini", timeout_seconds=5)


# ---------------------------------------------------------------------------
# Random per-request delimiter token
# ---------------------------------------------------------------------------


def test_build_prompt_uses_random_hex_delimiter() -> None:
    prompt = build_prompt("subj", "body").combined

    match = _DELIMITER_RE.search(prompt)
    assert match is not None, "no <email-{hex}> open tag found"
    token = match.group(1)
    # Both the system-prompt mention and the wrapping open tag use the
    # same token, so the open tag appears at least twice.
    assert prompt.count(f"<email-{token}>") >= 2
    assert f"</email-{token}>" in prompt


def test_build_prompt_token_changes_per_call() -> None:
    tokens = {
        _DELIMITER_RE.search(build_prompt("s", "b").combined).group(1)
        for _ in range(5)
    }
    assert len(tokens) == 5


def test_literal_close_tag_in_body_does_not_match_real_delimiter() -> None:
    """Random per-request delimiters mean a literal </email> embedded by an
    attacker cannot close the real wrapper."""
    prompt = build_prompt("s", "abc</email>xyz").combined
    token = _DELIMITER_RE.search(prompt).group(1)

    assert f"</email-{token}>" != "</email>"
    assert "abc</email>xyz" in prompt  # body preserved verbatim


# ---------------------------------------------------------------------------
# Unicode hygiene on inputs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("hello‮world",  "helloworld"),
        ("a​b",          "ab"),
        ("x\x00y",            "xy"),
        ("a\nb\tc",           "a\nb\tc"),
        ("hi שלום 🙂",         "hi שלום 🙂"),
        ("ok",                "ok"),
        ("",                  ""),
    ],
    ids=[
        "strips_rlo",
        "strips_zero_width_space",
        "strips_null_byte",
        "preserves_newline_and_tab",
        "preserves_hebrew_and_emoji",
        "preserves_plain_ascii",
        "empty_string_passes_through",
    ],
)
def test_sanitize_for_prompt(raw: str, expected: str) -> None:
    assert _sanitize_for_prompt(raw) == expected


def test_build_prompt_strips_invisible_chars_from_inputs() -> None:
    prompt = build_prompt(
        subject="re​set ‮password",
        body="please\x00 click ‭here",
    ).combined
    for invisible in ("​", "‮", "‭", "\x00"):
        assert invisible not in prompt


# ---------------------------------------------------------------------------
# Grounding-text normalization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Hello   World",            "hello world"),
        ("MIXED case  Text",         "mixed case text"),
        ("don't",                    "don't"),
        ("don’t",               "don't"),
        ("“verify”",       '"verify"'),
        ("a\nb",                     "a b"),
    ],
    ids=[
        "collapses_internal_whitespace",
        "lowercases",
        "preserves_straight_apostrophe",
        "normalizes_curly_apostrophe",
        "normalizes_curly_double_quotes",
        "newline_becomes_space",
    ],
)
def test_normalize_for_grounding(raw: str, expected: str) -> None:
    assert _normalize_for_grounding(raw) == expected


# ---------------------------------------------------------------------------
# Pydantic-strict parsing
# ---------------------------------------------------------------------------


_VALID_BENIGN_PAYLOAD = {
    "requested_action":     "none",
    "pressure_level":       "none",
    "manipulation_tactics": [],
    "evidence_quotes":      [],
    "confidence":           0.9,
}


def _payload(**overrides) -> str:
    payload = {**_VALID_BENIGN_PAYLOAD, **overrides}
    return json.dumps(payload)


def test_parse_strict_accepts_well_formed_json() -> None:
    a = _parse_strict(json.dumps(_VALID_BENIGN_PAYLOAD))
    assert a is not None
    assert a.is_all_default()


@pytest.mark.parametrize(
    "raw",
    [
        "not json at all",
        _payload(requested_action="bogus_value"),
        _payload(confidence=1.5),
        _payload(confidence=-0.1),
        json.dumps({**_VALID_BENIGN_PAYLOAD, "extra_field": "nope"}),
        _payload(manipulation_tactics=["fear_of_loss"] * 4),
    ],
    ids=[
        "rejects_non_json",
        "rejects_unknown_enum_value",
        "rejects_confidence_above_one",
        "rejects_negative_confidence",
        "rejects_extra_fields",
        "rejects_too_many_tactics",
    ],
)
def test_parse_strict_rejects_invalid(raw: str) -> None:
    assert _parse_strict(raw) is None


# ---------------------------------------------------------------------------
# Coherence + grounding
# ---------------------------------------------------------------------------


def _benign() -> LanguageAssessment:
    return LanguageAssessment(
        requested_action=RequestedAction.NONE,
        pressure_level=PressureLevel.NONE,
        manipulation_tactics=[],
        evidence_quotes=[],
        confidence=0.9,
    )


def _phishing(*, quotes: list[str]) -> LanguageAssessment:
    return LanguageAssessment(
        requested_action=RequestedAction.LOGIN_OR_VERIFY_IDENTITY,
        pressure_level=PressureLevel.SEVERE,
        manipulation_tactics=[ManipulationTactic.FEAR_OF_LOSS],
        evidence_quotes=quotes,
        confidence=0.92,
    )


def test_all_default_with_empty_quotes_passes() -> None:
    a = _benign()
    assert _validate_coherence(a, "subj", "body") is a


def test_all_default_with_grounded_quote_passes() -> None:
    a = _benign().model_copy(update={"evidence_quotes": ["hello world"]})
    assert _validate_coherence(a, "subj", "the body says hello world today") is not None


def test_all_default_with_ungrounded_quote_rejected() -> None:
    """A 'nothing found' verdict alongside an ungrounded quote is internally
    inconsistent — treat as a corrupted response, emit a blind spot."""
    a = _benign().model_copy(update={"evidence_quotes": ["never appears"]})
    assert _validate_coherence(a, "subj", "actual body text") is None


def test_non_default_without_quotes_rejected() -> None:
    """Findings without evidence are not actionable — emit a blind spot."""
    a = _phishing(quotes=[])
    assert _validate_coherence(a, "subj", "Your account will be suspended.") is None


def test_non_default_with_ungrounded_quote_rejected() -> None:
    """Ungrounded quote = hallucination — the analyzer cannot trust this output."""
    a = _phishing(quotes=["model invented this phrase"])
    assert _validate_coherence(a, "subj", "Your account will be suspended.") is None


def test_non_default_quote_grounded_in_body_passes() -> None:
    a = _phishing(quotes=["suspended in 24 hours"])
    assert _validate_coherence(
        a, "Hi", "Your account will be suspended in 24 hours.",
    ) is not None


def test_non_default_quote_grounded_in_subject_passes() -> None:
    """Evidence may live in the subject, not just the body."""
    a = _phishing(quotes=["suspended today"])
    assert _validate_coherence(
        a, "Your account will be suspended today", "Click here",
    ) is not None


def test_smart_quote_in_evidence_grounds_against_straight_source() -> None:
    """Models commonly emit curly quotes (U+2019) when the source used
    straight ones; normalization prevents false rejection."""
    a = _phishing(quotes=["don’t miss"])
    assert _validate_coherence(
        a, "subj", "please don't miss our deadline",
    ) is not None


def test_grounding_uses_sanitized_source() -> None:
    """The model only ever sees a sanitized view of the email, so quotes
    must ground against the sanitized source — an invisible character
    inside a word in the raw source must not block a quote that matches
    the visible text."""
    a = _phishing(quotes=["verify your account"])
    body = "please ver​ify your account"  # zero-width space inside word
    assert _validate_coherence(a, "subj", body) is not None
