"""Unit tests for UrlStructureAnalyzer — href/display mismatch and IP-literal hosts."""

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

    def test_ipv6_bracket_flagged(self, analyzer: UrlStructureAnalyzer):
        html = '<a href="http://[::1]/login">Log in</a>'
        output = analyzer.analyze(_make_email(body_html=html))
        signals = [s for s in output.signals if s.id == "ip_address_in_url"]
        assert len(signals) == 1
        assert signals[0].severity == SignalSeverity.HIGH

    def test_normal_domain_not_flagged(self, analyzer: UrlStructureAnalyzer):
        html = '<a href="https://example.com">Example</a>'
        output = analyzer.analyze(_make_email(body_html=html))
        assert not [s for s in output.signals if s.id == "ip_address_in_url"]

    def test_bare_text_ip_url(self, analyzer: UrlStructureAnalyzer):
        output = analyzer.analyze(_make_email(body_text="Visit http://10.0.0.1/page"))
        signals = [s for s in output.signals if s.id == "ip_address_in_url"]
        assert len(signals) == 1


# ---------------------------------------------------------------------------
# URL-3: dangerous URI scheme in href (data:, javascript:, file:, vbscript:)
# ---------------------------------------------------------------------------


class TestDangerousUriScheme:
    @pytest.mark.parametrize(
        ("html", "should_fire"),
        [
            ('<a href="data:text/html;base64,PGh0bWw+">Report</a>',  True),
            ('<a href="javascript:alert(1)">Click</a>',              True),
            ('<a href="file:///etc/passwd">Doc</a>',                 True),
            ('<a href="vbscript:msgbox(1)">Run</a>',                 True),
            ('<a href="DATA:text/html;base64,PGh0bWw+">X</a>',       True),
            ('<a href="https://example.com/page">Page</a>',          False),
            ('<a href="mailto:admin@example.com">Email</a>',         False),
            ('<a href="tel:+15551234567">Call</a>',                  False),
            ('<a href="/relative/path">Local</a>',                   False),
        ],
        ids=[
            "data_uri_fires",
            "javascript_fires",
            "file_fires",
            "vbscript_fires",
            "case_insensitive_fires",
            "https_does_not_fire",
            "mailto_does_not_fire",
            "tel_does_not_fire",
            "relative_path_does_not_fire",
        ],
    )
    def test_scheme_detection(
        self,
        analyzer: UrlStructureAnalyzer,
        html: str,
        should_fire: bool,
    ):
        output = analyzer.analyze(_make_email(body_html=html))
        fired = any(s.id == "dangerous_uri_scheme" for s in output.signals)
        assert fired is should_fire

    def test_severity_and_confidence(self, analyzer: UrlStructureAnalyzer):
        html = '<a href="data:text/html;base64,PGh0bWw+">Report</a>'
        output = analyzer.analyze(_make_email(body_html=html))
        signal = next(s for s in output.signals if s.id == "dangerous_uri_scheme")
        assert signal.severity == SignalSeverity.CRITICAL
        assert signal.confidence == 1.0


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
