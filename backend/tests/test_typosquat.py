"""Unit tests for typosquat string-distance utilities."""

from __future__ import annotations

import pytest

from detection_engine.utils.typosquat import (
    levenshtein_distance,
    max_typosquat_distance,
    normalize_typosquat,
)


class TestLevenshteinDistance:
    @pytest.mark.parametrize(
        ("left", "right", "expected"),
        [
            ("paypal", "paypal", 0),
            ("paypal", "paypol", 1),
            ("paypal", "paypall", 1),
            ("arnazon", "amazon", 2),
            ("", "paypal", 6),
        ],
        ids=["identical", "one_substitution", "one_insertion", "arnazon_amazon", "empty_against_word"],
    )
    def test_distance(self, left, right, expected):
        assert levenshtein_distance(left, right) == expected

    def test_symmetric(self):
        assert levenshtein_distance("a", "abc") == levenshtein_distance("abc", "a")


class TestNormalizeTyposquat:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("paypa1", "paypal"),
            ("arnazon", "amazon"),
            ("g00gle", "google"),
            ("micro5oft", "microsoft"),
            ("vvalmart", "walmart"),
            ("PayPal", "paypal"),
        ],
        ids=["digit_one_to_l", "rn_to_m", "digit_zero_to_o", "digit_five_to_s", "vv_to_w", "lowercases"],
    )
    def test_normalize(self, raw, expected):
        assert normalize_typosquat(raw) == expected


class TestMaxTyposquatDistance:
    @pytest.mark.parametrize(
        ("token", "expected"),
        [
            ("ebay", 0),
            ("apple", 1),
            ("microsoft", 2),
        ],
        ids=["short_token_requires_exact_match", "medium_token_allows_one_edit", "long_token_allows_two_edits"],
    )
    def test_max_distance(self, token, expected):
        assert max_typosquat_distance(token) == expected
