"""String-distance utilities for typosquat detection.

Brand impersonators substitute visually similar characters (paypa1,
arnazon, g00gle) to evade exact-string matching. This module exposes:

  • ``normalize_typosquat`` — collapse common visual substitutions
    (1↔l, 0↔o, 5↔s, rn↔m, vv↔w, cl↔d) so 'paypa1' compares equal to
    'paypal'.
  • ``levenshtein_distance`` — minimum single-character edits between
    two strings.
  • ``max_typosquat_distance`` — sensible edit-distance budget for a
    token, scaled by length so short tokens still require exact match.

Pure functions, no I/O, no shared state."""

from __future__ import annotations


# Sequence substitutions are applied before the single-character map so
# that 'rn' collapses to 'm' before any character-level handling runs.
_SEQUENCE_SUBSTITUTIONS: tuple[tuple[str, str], ...] = (
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
)

_CHAR_SUBSTITUTIONS: dict[str, str] = {
    "1": "l",
    "0": "o",
    "5": "s",
}


def normalize_typosquat(text: str) -> str:
    """Lower-case *text* and collapse visually similar characters/sequences."""
    result = text.lower()
    for sequence, replacement in _SEQUENCE_SUBSTITUTIONS:
        result = result.replace(sequence, replacement)
    return "".join(_CHAR_SUBSTITUTIONS.get(c, c) for c in result)


def levenshtein_distance(a: str, b: str) -> int:
    """Minimum single-character edits to turn *a* into *b*."""
    if len(a) < len(b):
        return levenshtein_distance(b, a)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a):
        current = [i + 1]
        for j, char_b in enumerate(b):
            cost = 0 if char_a == char_b else 1
            current.append(min(previous[j + 1] + 1, current[j] + 1, previous[j] + cost))
        previous = current
    return previous[-1]


def max_typosquat_distance(token: str) -> int:
    """Edit-distance budget allowed for *token* to count as a typosquat.

    Short tokens require an exact match — a budget of even one edit
    would dominate the string and produce false positives. Long tokens
    tolerate up to two edits."""
    if len(token) >= 7:
        return 2
    if len(token) >= 5:
        return 1
    return 0
