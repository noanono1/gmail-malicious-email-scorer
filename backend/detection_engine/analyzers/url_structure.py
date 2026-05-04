from __future__ import annotations

import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import urlparse

from detection_engine.analyzers.base import BaseAnalyzer
from detection_engine.domain.email import EmailData
from detection_engine.domain.blind_spot_catalog import URL_DESTINATION
from detection_engine.domain.enums import SignalCategory, SignalSeverity
from detection_engine.domain.signals import AnalysisOutput, Signal

_BARE_URL_PATTERN = re.compile(r"https?://[^\s<>\"']+")


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


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


class UrlStructureAnalyzer(BaseAnalyzer):
    """Detects deliberate URL deception: link text that lies about its destination,
    and hosts that name a raw IP instead of a domain. Both are low-FP, high-signal
    indicators of phishing infrastructure. Weaker URL heuristics (shorteners, link
    counts) are intentionally excluded — see docs/detection-policy.md."""

    @property
    def name(self) -> str:
        return "url_structure_analyzer"

    def analyze(self, email: EmailData) -> AnalysisOutput:
        html_links = self._extract_html_links(email.body_html)
        text_only_links = self._extract_text_only_links(email.body_text, html_links)
        all_links = html_links + text_only_links

        if not all_links:
            return AnalysisOutput.empty()

        signals = [
            signal
            for signal in (
                self._href_display_mismatch_signal(html_links),
                self._ip_literal_host_signal(all_links),
            )
            if signal is not None
        ]

        return AnalysisOutput(signals=tuple(signals), blind_spots=(URL_DESTINATION,))

    def _extract_html_links(self, body_html: str) -> list[tuple[str, str]]:
        if not body_html:
            return []
        extractor = _LinkExtractor()
        extractor.feed(body_html)
        return extractor.links

    def _extract_text_only_links(
        self, body_text: str, html_links: list[tuple[str, str]]
    ) -> list[tuple[str, str]]:
        if not body_text:
            return []
        already_seen = {href for href, _ in html_links}
        return [
            (url, "")
            for url in _BARE_URL_PATTERN.findall(body_text)
            if url not in already_seen
        ]

    def _href_display_mismatch_signal(
        self, html_links: list[tuple[str, str]]
    ) -> Signal | None:
        mismatches: list[str] = []
        for href, display_text in html_links:
            if not _looks_like_url(display_text):
                continue
            href_domain = _extract_domain(href)
            display_domain = _extract_domain(display_text)
            if href_domain and display_domain and href_domain != display_domain:
                mismatches.append(f"displays '{display_text}' → links to '{href_domain}'")

        if not mismatches:
            return None
        return Signal(
            id="url_href_display_mismatch",
            category=SignalCategory.URL_STRUCTURE,
            severity=SignalSeverity.CRITICAL,
            confidence=1.0,
            summary=f"Link text mismatches href: {'; '.join(mismatches[:3])}",
        )

    def _ip_literal_host_signal(
        self, links: list[tuple[str, str]]
    ) -> Signal | None:
        ip_urls = [
            href
            for href, _ in links
            if _is_ip_literal(urlparse(href).hostname or "")
        ]
        if not ip_urls:
            return None
        return Signal(
            id="ip_address_in_url",
            category=SignalCategory.URL_STRUCTURE,
            severity=SignalSeverity.HIGH,
            confidence=0.9,
            summary=f"URL contains IP address: {ip_urls[0]}",
        )
