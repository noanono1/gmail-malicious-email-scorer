"""Domain-object invariants for `Signal`.

Most of `Signal`'s shape is enforced by the type system; the one runtime
invariant is that `confidence` lies in [0.0, 1.0]. Invalid values must
raise at construction time rather than silently producing a bogus
contribution downstream in scoring."""

from __future__ import annotations

import math

import pytest

from detection_engine.domain.enums import SignalCategory, SignalSeverity
from detection_engine.domain.signals import Signal


def _build(confidence: float) -> Signal:
    return Signal(
        id="probe",
        category=SignalCategory.AUTHENTICATION,
        severity=SignalSeverity.HIGH,
        summary="probe",
        confidence=confidence,
    )


class TestConfidenceBounds:
    @pytest.mark.parametrize("valid", [0.0, 0.001, 0.5, 0.999, 1.0])
    def test_in_range_accepted(self, valid: float):
        assert _build(valid).confidence == valid

    @pytest.mark.parametrize(
        "invalid",
        [-0.0001, -1.0, 1.0001, 1.5, 2.0, math.nan, math.inf, -math.inf],
        ids=["just_below_zero", "negative", "just_above_one", "above_one", "two", "nan", "inf", "neg_inf"],
    )
    def test_out_of_range_raises(self, invalid: float):
        with pytest.raises(ValueError, match="confidence must be in"):
            _build(invalid)
