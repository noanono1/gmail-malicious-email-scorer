from __future__ import annotations

import re

import tldextract

_extractor = tldextract.TLDExtract(suffix_list_urls=())

from detection_engine.analyzers.base import BaseAnalyzer
from detection_engine.domain.email import EmailData
from detection_engine.domain.enums import SignalCategory, SignalSeverity
from detection_engine.domain.signals import AnalysisOutput, Signal

# ---------------------------------------------------------------------------
# Character substitution maps for typosquat normalization
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
# Display name brand-token filtering
# ---------------------------------------------------------------------------

_NON_BRAND_TOKENS: frozenset[str] = frozenset({
    "bank", "security", "support", "helpdesk", "official",
    "team", "department", "dept", "corporate", "inc", "ltd",
    "foundation", "institute", "government", "federal",
    "customer", "service", "services", "center", "centre",
    "notification", "notifications", "alert", "alerts",
    "account", "accounts", "billing", "admin", "administrator",
    "info", "information", "noreply", "reply", "mail", "email",
    "update", "updates", "verify", "verification", "confirm",
    "the", "from", "your", "our", "dear", "welcome", "new",
    "please", "important", "urgent", "action", "required",
    "mr", "mrs", "ms", "dr", "sir", "madam",
    "online", "secure", "system", "systems", "automated",
    "com", "org", "net", "edu", "gov",
})

# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _sender_domain(sender_address: str) -> str | None:
    _, sep, domain = sender_address.rpartition("@")
    if not sep:
        return None
    return domain.lower() if domain else None


def _registered_domain(domain: str) -> str:
    extracted = _extractor(domain)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return domain


def _same_organization(domain_a: str, domain_b: str) -> bool:
    return _registered_domain(domain_a) == _registered_domain(domain_b)


def _is_esp_domain(domain: str) -> bool:
    return any(domain == esp or domain.endswith(f".{esp}") for esp in _ESP_DOMAINS)


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


def _max_typosquat_distance(token: str) -> int:
    if len(token) >= 7:
        return 2
    if len(token) >= 5:
        return 1
    return 0


def _extract_brand_tokens(display_name: str) -> list[str]:
    raw_tokens = re.split(r"[\s\-_.,;:!?|/\\@()\[\]<>\"']+", display_name)
    return [
        t.lower()
        for t in raw_tokens
        if len(t) >= 3 and t.lower() not in _NON_BRAND_TOKENS
    ]


def _sender_domain_segments(sender_domain: str) -> list[str]:
    extracted = _extractor(sender_domain)
    if not extracted.domain:
        return []
    return [s for s in extracted.domain.split("-") if len(s) >= 3]


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

        self._check_display_name_mismatch(email, sender_domain, signals)
        self._check_freemail_org_name(email, sender_domain, signals)
        self._check_reply_to_mismatch(email, sender_domain, signals)
        self._check_return_path_mismatch(email, sender_domain, signals)

        return AnalysisOutput(signals=tuple(signals), blind_spots=())

    def _check_display_name_mismatch(
        self, email: EmailData, sender_domain: str, signals: list[Signal]
    ) -> None:
        display_name = email.sender_display_name
        if not display_name:
            return

        brand_tokens = _extract_brand_tokens(display_name)
        if not brand_tokens:
            return

        extracted = _extractor(sender_domain)
        registered_name = extracted.domain
        if not registered_name:
            return

        # Brand token IS the full registered domain name → legitimate
        for token in brand_tokens:
            if token == registered_name.lower():
                return

        # Segment-level typosquat detection (catches near-misses
        # AND brand names embedded in non-brand domains)
        sender_segments = [s for s in registered_name.split("-") if len(s) >= 3]
        for token in brand_tokens:
            normalized_token = _normalize(token)
            threshold = _max_typosquat_distance(token)
            for segment in sender_segments:
                normalized_segment = _normalize(segment.lower())
                distance = _levenshtein(normalized_token, normalized_segment)
                if distance <= threshold:
                    confidence = (
                        1.0 if distance == 0 else 0.9 if distance == 1 else 0.8
                    )
                    signals.append(
                        Signal(
                            id="cousin_domain",
                            category=SignalCategory.SENDER_IDENTITY,
                            severity=SignalSeverity.CRITICAL,
                            confidence=confidence,
                            evidence=(
                                f"Sender domain '{sender_domain}' resembles "
                                f"claimed identity '{token}' in display name"
                            ),
                        )
                    )
                    return

        # Complete mismatch — only flag with organizational context
        name_words = {w.lower() for w in re.split(r"[\s\-_]+", display_name)}
        if name_words & _ORG_KEYWORDS:
            signals.append(
                Signal(
                    id="display_name_mismatch",
                    category=SignalCategory.SENDER_IDENTITY,
                    severity=SignalSeverity.HIGH,
                    confidence=0.8,
                    evidence=(
                        f"Display name '{display_name}' implies brand "
                        f"'{brand_tokens[0]}' but sender domain is "
                        f"'{sender_domain}'"
                    ),
                )
            )

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

        if _same_organization(reply_domain, sender_domain):
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

        if _same_organization(return_domain, sender_domain):
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
