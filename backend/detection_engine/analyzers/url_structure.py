from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urlparse

from detection_engine.analyzers.base import BaseAnalyzer
from detection_engine.domain.email import EmailData
from detection_engine.domain.enums import BlindSpotArea, SignalCategory, SignalSeverity
from detection_engine.domain.signals import BlindSpot, AnalysisOutput, Signal

_SHORTENER_DOMAINS: frozenset[str] = frozenset({
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
})

_IPV4_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

_EXCESSIVE_URL_THRESHOLD = 10

_BARE_URL_PATTERN = re.compile(r"https?://[^\s<>\"']+")


def _extract_bare_urls(text: str) -> list[tuple[str, str]]:
    """Extract bare URLs from plain text as (url, '') tuples — no display text."""
    return [(url, "") for url in _BARE_URL_PATTERN.findall(text)]


class _LinkExtractor(HTMLParser):

    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._current_href: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            href = dict(attrs).get("href", "")
            self._current_href = href or ""
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._current_href is not None:
            display_text = "".join(self._current_text).strip()
            self.links.append((self._current_href, display_text))
            self._current_href = None
            self._current_text = []


def _extract_domain(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname or ""
    return host.lower().removeprefix("www.")


def _looks_like_url(text: str) -> bool:
    return "." in text and " " not in text and len(text) > 3


def _is_ip_address(host: str) -> bool:
    if _IPV4_PATTERN.match(host):
        return True
    if host.startswith("[") and host.endswith("]"):
        return True
    return False


class UrlStructureAnalyzer(BaseAnalyzer):

    @property
    def name(self) -> str:
        return "url_structure_analyzer"

    @property
    def category(self) -> SignalCategory:
        return SignalCategory.URL_STRUCTURE

    def analyze(self, email: EmailData) -> AnalysisOutput:
        html_links: list[tuple[str, str]] = []
        if email.body_html:
            extractor = _LinkExtractor()
            extractor.feed(email.body_html)
            html_links = extractor.links

        text_links = _extract_bare_urls(email.body_text) if email.body_text else []

        seen_urls = {href for href, _ in html_links}
        unique_text_links = [(url, dt) for url, dt in text_links if url not in seen_urls]
        all_links = html_links + unique_text_links

        if not all_links:
            return AnalysisOutput.empty()

        signals: list[Signal] = []
        blind_spots: list[BlindSpot] = []

        self._check_href_display_mismatch(html_links, signals)
        self._check_ip_in_url(all_links, signals)
        self._check_shortened_urls(all_links, signals)
        self._check_excessive_urls(all_links, signals)

        blind_spots.append(
            BlindSpot(
                area=BlindSpotArea.URL_DESTINATION,
                reason="URLs found but not followed — cannot verify destination content",
                risk_note="A clean-looking domain could redirect to a phishing page",
            )
        )

        return AnalysisOutput(signals=tuple(signals), blind_spots=tuple(blind_spots))

    def _check_href_display_mismatch(
        self, links: list[tuple[str, str]], signals: list[Signal]
    ) -> None:
        mismatched: list[str] = []
        for href, display_text in links:
            if not _looks_like_url(display_text):
                continue
            href_domain = _extract_domain(href)
            display_domain = _extract_domain(display_text)
            if href_domain and display_domain and href_domain != display_domain:
                mismatched.append(f"displays '{display_text}' → links to '{href_domain}'")

        if mismatched:
            signals.append(
                Signal(
                    id="url_href_display_mismatch",
                    category=SignalCategory.URL_STRUCTURE,
                    severity=SignalSeverity.CRITICAL,
                    confidence=1.0,
                    evidence=f"Link text mismatches href: {'; '.join(mismatched[:3])}",
                )
            )

    def _check_ip_in_url(
        self, links: list[tuple[str, str]], signals: list[Signal]
    ) -> None:
        ip_urls: list[str] = []
        for href, _ in links:
            parsed = urlparse(href)
            host = parsed.hostname or ""
            if _is_ip_address(host):
                ip_urls.append(href)

        if ip_urls:
            signals.append(
                Signal(
                    id="ip_address_in_url",
                    category=SignalCategory.URL_STRUCTURE,
                    severity=SignalSeverity.HIGH,
                    confidence=0.9,
                    evidence=f"URL contains IP address: {ip_urls[0]}",
                )
            )

    def _check_shortened_urls(
        self, links: list[tuple[str, str]], signals: list[Signal]
    ) -> None:
        shortened: list[str] = []
        for href, _ in links:
            domain = _extract_domain(href)
            if domain in _SHORTENER_DOMAINS:
                shortened.append(href)

        if shortened:
            signals.append(
                Signal(
                    id="shortened_url",
                    category=SignalCategory.URL_STRUCTURE,
                    severity=SignalSeverity.LOW,
                    confidence=0.7,
                    evidence=f"Shortened URL detected: {shortened[0]}",
                )
            )

    def _check_excessive_urls(
        self, links: list[tuple[str, str]], signals: list[Signal]
    ) -> None:
        unique_domains = {_extract_domain(href) for href, _ in links} - {""}
        if len(unique_domains) >= _EXCESSIVE_URL_THRESHOLD:
            signals.append(
                Signal(
                    id="excessive_url_count",
                    category=SignalCategory.URL_STRUCTURE,
                    severity=SignalSeverity.INFO,
                    confidence=0.5,
                    evidence=f"{len(unique_domains)} unique external domains linked",
                )
            )
