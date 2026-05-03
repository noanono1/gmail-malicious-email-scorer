from __future__ import annotations

import logging
import re

from detection_engine.analyzers.base import BaseAnalyzer
from detection_engine.domain.email import EmailData
from detection_engine.domain.enums import SignalCategory, SignalSeverity
from detection_engine.domain.signals import AnalysisOutput, Signal

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Brand intelligence — name → legitimate domains owned by that brand
# ---------------------------------------------------------------------------

_BRANDS: dict[str, frozenset[str]] = {
    "paypal": frozenset({"paypal.com"}),
    "amazon": frozenset({"amazon.com", "amazon.co.uk", "amazon.de", "amazon.co.jp"}),
    "apple": frozenset({"apple.com"}),
    "microsoft": frozenset({"microsoft.com"}),
    "google": frozenset({"google.com"}),
    "netflix": frozenset({"netflix.com"}),
    "facebook": frozenset({"facebook.com", "meta.com"}),
    "instagram": frozenset({"instagram.com"}),
    "linkedin": frozenset({"linkedin.com"}),
    "dropbox": frozenset({"dropbox.com"}),
    "adobe": frozenset({"adobe.com"}),
    "spotify": frozenset({"spotify.com"}),
    "walmart": frozenset({"walmart.com"}),
    "ebay": frozenset({"ebay.com"}),
    "chase": frozenset({"chase.com"}),
    "wellsfargo": frozenset({"wellsfargo.com"}),
    "citibank": frozenset({"citibank.com", "citi.com"}),
    "gmail": frozenset({"gmail.com"}),
    "outlook": frozenset({"outlook.com"}),
    "yahoo": frozenset({"yahoo.com", "yahoo.co.uk"}),
    "fedex": frozenset({"fedex.com"}),
    "twitter": frozenset({"twitter.com", "x.com"}),
}

_ALL_LEGITIMATE_DOMAINS: frozenset[str] = frozenset().union(*_BRANDS.values())

# ---------------------------------------------------------------------------
# Character substitution maps for cousin domain normalization
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Domain segment filtering
# ---------------------------------------------------------------------------

_TLDS: frozenset[str] = frozenset({
    "com", "net", "org", "io", "co", "uk", "de", "fr", "jp",
    "us", "info", "biz", "xyz", "me", "in", "ru", "edu", "gov",
})

# Common domain words that aren't brands — skip to avoid false positives
# against short brand names (e.g. "mail" is distance 1 from "gmail").
_IGNORED_SEGMENTS: frozenset[str] = frozenset({
    "mail", "email", "smtp", "web", "www", "app",
    "cloud", "host", "server", "online", "shop", "store",
    "help", "info", "news", "blog", "api", "dev", "auth",
    "login", "secure", "mobile", "beta", "pro", "pay",
})

# ---------------------------------------------------------------------------
# Freemail, ESP, and org-keyword lists
# ---------------------------------------------------------------------------

_FREEMAIL_DOMAINS: frozenset[str] = frozenset({
    "gmail.com", "yahoo.com", "yahoo.co.uk", "outlook.com", "hotmail.com",
    "aol.com", "protonmail.com", "proton.me", "icloud.com", "mail.com",
    "zoho.com", "yandex.com", "gmx.com", "gmx.de",
    "tutanota.com", "fastmail.com",
})

_ORG_KEYWORDS: frozenset[str] = frozenset({
    "bank", "security", "support", "helpdesk", "official",
    "team", "department", "dept", "corporate", "inc", "ltd",
    "foundation", "institute", "government", "federal",
})

_ESP_DOMAINS: frozenset[str] = frozenset({
    "sendgrid.net", "amazonses.com", "mailchimp.com", "mandrillapp.com",
    "mailgun.org", "postmarkapp.com", "sparkpostmail.com",
    "sailthru.com", "exacttarget.com", "responsys.com",
    "constantcontact.com", "sendinblue.com", "brevo.com",
    "mailjet.com", "hubspot.com",
})

# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _sender_domain(sender_address: str) -> str | None:
    _, sep, domain = sender_address.rpartition("@")
    if not sep:
        return None
    return domain.lower() if domain else None


def _is_legitimate_domain(domain: str) -> bool:
    if domain in _ALL_LEGITIMATE_DOMAINS:
        return True
    return any(domain.endswith(f".{legit}") for legit in _ALL_LEGITIMATE_DOMAINS)


def _is_esp_domain(domain: str) -> bool:
    return any(domain == esp or domain.endswith(f".{esp}") for esp in _ESP_DOMAINS)


def _domain_segments(domain: str) -> list[str]:
    parts = re.split(r"[.\-]", domain)
    return [
        p
        for p in parts
        if len(p) > 2 and p.lower() not in _TLDS and p.lower() not in _IGNORED_SEGMENTS
    ]


def _normalize(text: str) -> str:
    result = text.lower()
    for old, new in _SEQUENCE_SUBSTITUTIONS:
        result = result.replace(old, new)
    return "".join(_CHAR_SUBSTITUTIONS.get(c, c) for c in result)


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
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


def _max_distance_for_brand(brand: str) -> int:
    if len(brand) >= 7:
        return 2
    if len(brand) >= 5:
        return 1
    return 0


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


class SenderAnalyzer(BaseAnalyzer):

    @property
    def name(self) -> str:
        return "sender_analyzer"

    @property
    def category(self) -> SignalCategory:
        return SignalCategory.SENDER_IDENTITY

    def analyze(self, email: EmailData) -> AnalysisOutput:
        sender_domain = _sender_domain(email.sender_address)
        if sender_domain is None:
            return AnalysisOutput(signals=(), blind_spots=())

        signals: list[Signal] = []

        self._check_cousin_domain(sender_domain, signals)
        self._check_freemail_org_name(email, sender_domain, signals)
        self._check_reply_to_mismatch(email, sender_domain, signals)
        self._check_return_path_mismatch(email, sender_domain, signals)

        return AnalysisOutput(signals=tuple(signals), blind_spots=())

    def _check_cousin_domain(
        self, sender_domain: str, signals: list[Signal]
    ) -> None:
        if _is_legitimate_domain(sender_domain):
            return

        segments = _domain_segments(sender_domain)

        for segment in segments:
            normalized = _normalize(segment)
            for brand in _BRANDS:
                threshold = _max_distance_for_brand(brand)
                distance = _levenshtein(normalized, brand)

                if distance > threshold:
                    raw_distance = _levenshtein(segment.lower(), brand)
                    if raw_distance > threshold:
                        continue
                    distance = raw_distance

                confidence = 1.0 if distance == 0 else 0.9 if distance == 1 else 0.8
                signals.append(
                    Signal(
                        id="cousin_domain",
                        category=SignalCategory.SENDER_IDENTITY,
                        severity=SignalSeverity.CRITICAL,
                        confidence=confidence,
                        evidence=f"Sender domain '{sender_domain}' resembles brand '{brand}'",
                    )
                )
                return

    def _check_freemail_org_name(
        self, email: EmailData, sender_domain: str, signals: list[Signal]
    ) -> None:
        if sender_domain not in _FREEMAIL_DOMAINS:
            return

        display_name = email.sender_display_name
        if not display_name:
            return

        name_words = {w.lower() for w in re.split(r"[\s\-_]+", display_name)}
        if name_words & _ORG_KEYWORDS:
            signals.append(
                Signal(
                    id="freemail_org_name",
                    category=SignalCategory.SENDER_IDENTITY,
                    severity=SignalSeverity.MEDIUM,
                    confidence=0.7,
                    evidence=(
                        f"Freemail sender ({sender_domain}) with organizational "
                        f"display name '{display_name}'"
                    ),
                )
            )

    def _check_reply_to_mismatch(
        self, email: EmailData, sender_domain: str, signals: list[Signal]
    ) -> None:
        if not email.reply_to_address:
            return

        reply_domain = _sender_domain(email.reply_to_address)
        if reply_domain is None or reply_domain == sender_domain:
            return

        signals.append(
            Signal(
                id="reply_to_mismatch",
                category=SignalCategory.SENDER_IDENTITY,
                severity=SignalSeverity.HIGH,
                confidence=1.0,
                evidence=(
                    f"Reply-To domain ({reply_domain}) differs from "
                    f"sender domain ({sender_domain})"
                ),
            )
        )

    def _check_return_path_mismatch(
        self, email: EmailData, sender_domain: str, signals: list[Signal]
    ) -> None:
        if not email.return_path_address:
            return

        return_domain = _sender_domain(email.return_path_address)
        if return_domain is None or return_domain == sender_domain:
            return

        if _is_esp_domain(return_domain):
            return

        signals.append(
            Signal(
                id="return_path_mismatch",
                category=SignalCategory.SENDER_IDENTITY,
                severity=SignalSeverity.MEDIUM,
                confidence=0.8,
                evidence=(
                    f"Return-Path domain ({return_domain}) differs from "
                    f"sender domain ({sender_domain})"
                ),
            )
        )
