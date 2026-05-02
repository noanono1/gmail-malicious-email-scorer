"""Tier 1 contract tests — define success before implementing analyzers.

These tests run sample emails through the full DetectionEngine with all
Tier 1 analyzers wired up. They encode the scoring contract from CLAUDE.md §13.

Run: python -m pytest tests/test_tier1_detection.py -v
"""

import pytest

from detection_engine import DetectionEngine, Verdict

from tests.email_fixtures import (
    ALL_FIXTURES,
    BEC_WIRE_TRANSFER,
    EMPTY_MINIMAL,
    LEGIT_AMAZON_ORDER,
    LEGIT_MARKETING,
    MALWARE_ATTACHMENT,
    MASS_PHISHING,
    SPEAR_PHISH_COUSIN_DOMAIN,
    build_email_data,
)


# ---------------------------------------------------------------------------
# Engine factory
# ---------------------------------------------------------------------------

def _build_engine() -> DetectionEngine:
    """Wire up all Tier 1 analyzers, no intel sources."""
    from detection_engine.analyzers.header import HeaderAnalyzer
    from detection_engine.analyzers.sender import SenderAnalyzer
    from detection_engine.analyzers.content import ContentAnalyzer

    return DetectionEngine(
        analyzers=[HeaderAnalyzer(), SenderAnalyzer(), ContentAnalyzer()],
    )


# ---------------------------------------------------------------------------
# Contract tests — one class per scenario
# ---------------------------------------------------------------------------

class TestMassPhishing:
    """Spoofed PayPal, auth failure, IP URL, urgency."""

    def test_score_reaches_malicious(self):
        result = _build_engine().analyze(build_email_data(MASS_PHISHING["email"]))
        assert result.score >= 65, (
            f"Phishing scored {result.score}, expected ≥65"
        )

    def test_verdict_is_malicious(self):
        result = _build_engine().analyze(build_email_data(MASS_PHISHING["email"]))
        assert result.verdict == Verdict.MALICIOUS


class TestLegitAmazonOrder:
    """Legitimate transactional email with valid authentication."""

    def test_score_stays_safe(self):
        result = _build_engine().analyze(build_email_data(LEGIT_AMAZON_ORDER["email"]))
        assert result.score < 15, (
            f"Legit Amazon scored {result.score}, expected <15"
        )

    def test_verdict_is_safe(self):
        result = _build_engine().analyze(build_email_data(LEGIT_AMAZON_ORDER["email"]))
        assert result.verdict == Verdict.SAFE


class TestBecWireTransfer:
    """BEC: freemail sender, urgency, wire transfer, secrecy, reply-to mismatch."""

    def test_score_in_suspicious_range(self):
        result = _build_engine().analyze(build_email_data(BEC_WIRE_TRANSFER["email"]))
        assert 15 <= result.score < 65, (
            f"BEC scored {result.score}, expected 15–64"
        )

    def test_verdict_is_at_least_suspicious(self):
        result = _build_engine().analyze(build_email_data(BEC_WIRE_TRANSFER["email"]))
        assert result.verdict in (Verdict.SUSPICIOUS, Verdict.LIKELY_MALICIOUS)


class TestSpearPhishCousinDomain:
    """Cousin domain (arnazon.com), auth passes, credential ask."""

    def test_score_reaches_likely_malicious(self):
        result = _build_engine().analyze(build_email_data(SPEAR_PHISH_COUSIN_DOMAIN["email"]))
        assert result.score >= 35, (
            f"Spear-phish scored {result.score}, expected ≥35"
        )

    def test_verdict_at_least_likely_malicious(self):
        result = _build_engine().analyze(build_email_data(SPEAR_PHISH_COUSIN_DOMAIN["email"]))
        assert result.verdict in (Verdict.LIKELY_MALICIOUS, Verdict.MALICIOUS)


class TestLegitMarketing:
    """ESP-sent marketing with valid auth and unsubscribe header."""

    def test_score_stays_safe(self):
        result = _build_engine().analyze(build_email_data(LEGIT_MARKETING["email"]))
        assert result.score < 15, (
            f"Legit marketing scored {result.score}, expected <15"
        )

    def test_verdict_is_safe(self):
        result = _build_engine().analyze(build_email_data(LEGIT_MARKETING["email"]))
        assert result.verdict == Verdict.SAFE


class TestMalwareAttachment:
    """Double extension .pdf.exe with urgency language."""

    def test_score_reaches_malicious(self):
        result = _build_engine().analyze(build_email_data(MALWARE_ATTACHMENT["email"]))
        assert result.score >= 65, (
            f"Malware email scored {result.score}, expected ≥65"
        )

    def test_verdict_is_malicious(self):
        result = _build_engine().analyze(build_email_data(MALWARE_ATTACHMENT["email"]))
        assert result.verdict == Verdict.MALICIOUS


class TestEmptyMinimal:
    """Empty email — no crash, no false positive."""

    def test_no_crash_and_safe(self):
        result = _build_engine().analyze(build_email_data(EMPTY_MINIMAL["email"]))
        assert result.score < 15, (
            f"Empty email scored {result.score}, expected <15"
        )

    def test_verdict_is_safe(self):
        result = _build_engine().analyze(build_email_data(EMPTY_MINIMAL["email"]))
        assert result.verdict == Verdict.SAFE
