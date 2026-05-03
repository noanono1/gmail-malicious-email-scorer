"""Unit tests for UrlStructureAnalyzer — href/display mismatch, IP URLs, shorteners, excessive links."""

from __future__ import annotations

import pytest

from detection_engine.analyzers.url_structure import UrlStructureAnalyzer
from detection_engine.domain.email import EmailData, EmailHeaders
from detection_engine.domain.enums import BlindSpotArea, SignalSeverity
from tests.email_fixtures import (
    EMPTY_MINIMAL,
    LEGIT_AMAZON_ORDER,
    MASS_PHISHING,
    PHISHING_HIDDEN_URL,
    build_email_data,
)


def _make_email(
    body_html: str = "",
    body_text: str = "",
) -> EmailData:
    return EmailData(
        message_id="test-url-001",
        sender_address="test@example.com",
        sender_display_name="",
        recipient="user@example.com",
        subject="Test",
        body_text=body_text,
        body_html=body_html,
        headers=EmailHeaders([("From", "test@example.com")]),
    )


@pytest.fixture
def analyzer() -> UrlStructureAnalyzer:
    return UrlStructureAnalyzer()


# ---------------------------------------------------------------------------
# URL-1: href/display text mismatch
# ---------------------------------------------------------------------------


class TestHrefDisplayMismatch:
    def test_mismatched_domains(self, analyzer: UrlStructureAnalyzer):
        html = '<a href="http://evil.com/steal">http://paypal.com/account</a>'
        output = analyzer.analyze(_make_email(body_html=html))
        signals = [s for s in output.signals if s.id == "url_href_display_mismatch"]
        assert len(signals) == 1
        assert signals[0].severity == SignalSeverity.CRITICAL
        assert signals[0].confidence == 1.0

    def test_matching_domains_not_flagged(self, analyzer: UrlStructureAnalyzer):
        html = '<a href="https://paypal.com/login">https://paypal.com/login</a>'
        output = analyzer.analyze(_make_email(body_html=html))
        assert not [s for s in output.signals if s.id == "url_href_display_mismatch"]

    def test_non_url_display_text_not_flagged(self, analyzer: UrlStructureAnalyzer):
        html = '<a href="https://example.com">Click here</a>'
        output = analyzer.analyze(_make_email(body_html=html))
        assert not [s for s in output.signals if s.id == "url_href_display_mismatch"]

    def test_www_stripped_before_comparison(self, analyzer: UrlStructureAnalyzer):
        html = '<a href="https://www.example.com/page">https://example.com/page</a>'
        output = analyzer.analyze(_make_email(body_html=html))
        assert not [s for s in output.signals if s.id == "url_href_display_mismatch"]


# ---------------------------------------------------------------------------
# URL-2: IP address in URL
# ---------------------------------------------------------------------------


class TestIpInUrl:
    def test_ipv4_flagged(self, analyzer: UrlStructureAnalyzer):
        html = '<a href="http://192.168.1.100/login">Log in</a>'
        output = analyzer.analyze(_make_email(body_html=html))
        signals = [s for s in output.signals if s.id == "ip_address_in_url"]
        assert len(signals) == 1
        assert signals[0].severity == SignalSeverity.HIGH

    def test_ipv6_bracket_not_detected(self, analyzer: UrlStructureAnalyzer):
        # urlparse strips brackets from IPv6 hosts, so _is_ip_address's bracket check
        # never triggers. This documents the current behavior (known limitation).
        html = '<a href="http://[::1]/login">Log in</a>'
        output = analyzer.analyze(_make_email(body_html=html))
        signals = [s for s in output.signals if s.id == "ip_address_in_url"]
        assert len(signals) == 0

    def test_normal_domain_not_flagged(self, analyzer: UrlStructureAnalyzer):
        html = '<a href="https://example.com">Example</a>'
        output = analyzer.analyze(_make_email(body_html=html))
        assert not [s for s in output.signals if s.id == "ip_address_in_url"]

    def test_bare_text_ip_url(self, analyzer: UrlStructureAnalyzer):
        output = analyzer.analyze(_make_email(body_text="Visit http://10.0.0.1/page"))
        signals = [s for s in output.signals if s.id == "ip_address_in_url"]
        assert len(signals) == 1


# ---------------------------------------------------------------------------
# URL-3: Shortened URLs
# ---------------------------------------------------------------------------


class TestShortenedUrls:
    def test_bit_ly_flagged(self, analyzer: UrlStructureAnalyzer):
        html = '<a href="https://bit.ly/abc123">Click</a>'
        output = analyzer.analyze(_make_email(body_html=html))
        signals = [s for s in output.signals if s.id == "shortened_url"]
        assert len(signals) == 1
        assert signals[0].severity == SignalSeverity.LOW

    def test_tinyurl_flagged(self, analyzer: UrlStructureAnalyzer):
        output = analyzer.analyze(_make_email(body_text="http://tinyurl.com/xyz"))
        assert [s for s in output.signals if s.id == "shortened_url"]

    def test_normal_url_not_flagged(self, analyzer: UrlStructureAnalyzer):
        html = '<a href="https://example.com/long/path">Click</a>'
        output = analyzer.analyze(_make_email(body_html=html))
        assert not [s for s in output.signals if s.id == "shortened_url"]


# ---------------------------------------------------------------------------
# URL-4: Excessive unique domains
# ---------------------------------------------------------------------------


class TestExcessiveUrls:
    def test_many_unique_domains_flagged(self, analyzer: UrlStructureAnalyzer):
        links = " ".join(f"https://domain{i}.com/page" for i in range(12))
        output = analyzer.analyze(_make_email(body_text=links))
        signals = [s for s in output.signals if s.id == "excessive_url_count"]
        assert len(signals) == 1
        assert signals[0].severity == SignalSeverity.INFO

    def test_few_domains_not_flagged(self, analyzer: UrlStructureAnalyzer):
        html = '<a href="https://a.com">A</a> <a href="https://b.com">B</a>'
        output = analyzer.analyze(_make_email(body_html=html))
        assert not [s for s in output.signals if s.id == "excessive_url_count"]


# ---------------------------------------------------------------------------
# Text-only URL extraction
# ---------------------------------------------------------------------------


class TestBareUrlExtraction:
    def test_text_urls_extracted(self, analyzer: UrlStructureAnalyzer):
        text = "Visit https://example.com/page for info"
        output = analyzer.analyze(_make_email(body_text=text))
        assert len(output.blind_spots) > 0

    def test_text_urls_deduped_against_html(self, analyzer: UrlStructureAnalyzer):
        url = "https://example.com/page"
        html = f'<a href="{url}">Link</a>'
        output = analyzer.analyze(_make_email(body_html=html, body_text=f"Visit {url}"))
        ip_signals = [s for s in output.signals if s.id == "ip_address_in_url"]
        assert len(ip_signals) == 0


# ---------------------------------------------------------------------------
# Blind spots and edge cases
# ---------------------------------------------------------------------------


class TestBlindSpotsAndEdgeCases:
    def test_url_destination_blind_spot_present(self, analyzer: UrlStructureAnalyzer):
        html = '<a href="https://example.com">Link</a>'
        output = analyzer.analyze(_make_email(body_html=html))
        areas = [bs.area for bs in output.blind_spots]
        assert BlindSpotArea.URL_DESTINATION in areas

    def test_no_links_returns_empty(self, analyzer: UrlStructureAnalyzer):
        output = analyzer.analyze(_make_email())
        assert len(output.signals) == 0
        assert len(output.blind_spots) == 0

    def test_empty_body_returns_empty(self, analyzer: UrlStructureAnalyzer):
        output = analyzer.analyze(_make_email(body_html="", body_text=""))
        assert len(output.signals) == 0

    def test_all_signals_have_zero_contribution(self, analyzer: UrlStructureAnalyzer):
        html = '<a href="http://192.168.1.1/x">https://paypal.com</a>'
        output = analyzer.analyze(_make_email(body_html=html))
        assert len(output.signals) > 0
        assert all(s.score_contribution == 0.0 for s in output.signals)


# ---------------------------------------------------------------------------
# Real fixtures
# ---------------------------------------------------------------------------


class TestRealFixtures:
    def test_mass_phishing_has_ip_url(self, analyzer: UrlStructureAnalyzer):
        email = build_email_data(MASS_PHISHING["email"])
        output = analyzer.analyze(email)
        ids = {s.id for s in output.signals}
        assert "ip_address_in_url" in ids

    def test_hidden_url_phishing(self, analyzer: UrlStructureAnalyzer):
        email = build_email_data(PHISHING_HIDDEN_URL["email"])
        output = analyzer.analyze(email)
        ids = {s.id for s in output.signals}
        assert "url_href_display_mismatch" in ids

    def test_legit_amazon_no_url_signals(self, analyzer: UrlStructureAnalyzer):
        email = build_email_data(LEGIT_AMAZON_ORDER["email"])
        output = analyzer.analyze(email)
        assert len(output.signals) == 0

    def test_empty_minimal(self, analyzer: UrlStructureAnalyzer):
        email = build_email_data(EMPTY_MINIMAL["email"])
        output = analyzer.analyze(email)
        assert len(output.signals) == 0
