from __future__ import annotations

from detection_engine.analyzers.base import BaseAnalyzer
from detection_engine.domain.blind_spot_catalog import SENDER_ADDRESS_UNPARSEABLE
from detection_engine.domain.email import EmailData
from detection_engine.domain.enums import SignalCategory, SignalSeverity
from detection_engine.domain.signals import AnalysisOutput, Signal
from detection_engine.utils.domains import (
    domain_label,
    email_domain,
    public_suffix,
    same_organization,
)
from detection_engine.utils.typosquat import (
    levenshtein_distance,
    max_typosquat_distance,
    normalize_typosquat,
)

# Brand → legitimate domains owned by that brand. Built-in catalog for
# deterministic demo detection; production would source from external intel.
_BRAND_DOMAINS: dict[str, frozenset[str]] = {
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
    "fedex": frozenset({"fedex.com"}),
    "twitter": frozenset({"twitter.com", "x.com"}),
}

# Public suffixes legitimate global brands use for regional variants
# (paypal.fr, amazon.in). Fancy gTLDs (.xyz/.shop/.zip) stay out so
# `paypal.xyz` still trips the cousin-domain detector.
_TRUSTED_BRAND_SUFFIXES: frozenset[str] = frozenset({
    "com", "org", "net",
    "us", "uk", "ca", "au", "nz", "ie",
    "de", "fr", "it", "es", "nl", "be", "ch", "at",
    "se", "no", "dk", "fi", "pl", "pt",
    "ru", "jp", "kr", "cn", "hk", "tw",
    "in", "sg", "my", "id", "th",
    "br", "mx", "ar", "cl", "co",
    "za", "ae", "il", "tr",
    "co.uk", "co.jp", "co.in", "co.kr", "co.za", "co.nz", "co.il",
    "com.au", "com.br", "com.mx", "com.ar", "com.cn", "com.hk", "com.sg", "com.tr",
})

_FREEMAIL_DOMAINS: frozenset[str] = frozenset({
    "gmail.com", "yahoo.com", "yahoo.co.uk", "outlook.com", "hotmail.com",
    "aol.com", "protonmail.com", "proton.me", "icloud.com", "mail.com",
    "zoho.com", "yandex.com", "gmx.com", "gmx.de",
    "tutanota.com", "fastmail.com",
})

# ESPs that legitimately appear in Reply-To/Return-Path for brand mail.
_ESP_DOMAINS: frozenset[str] = frozenset({
    "sendgrid.net", "amazonses.com", "mailchimp.com", "mandrillapp.com",
    "mailgun.org", "postmarkapp.com", "sparkpostmail.com",
    "sailthru.com", "exacttarget.com", "responsys.com",
    "constantcontact.com", "sendinblue.com", "brevo.com",
    "mailjet.com", "hubspot.com",
})


def _is_legitimate_brand_domain(domain: str, brand: str) -> bool:
    """Match exact brand domain, subdomain, or regional variant
    (brand label on a trusted TLD — amazon.in, paypal.fr)."""
    legitimate_domains = _BRAND_DOMAINS.get(brand, frozenset())
    if domain in legitimate_domains:
        return True
    if any(domain.endswith(f".{legit}") for legit in legitimate_domains):
        return True
    return (
        domain_label(domain) == brand
        and public_suffix(domain) in _TRUSTED_BRAND_SUFFIXES
    )


def _matches_any_brand(domain: str) -> bool:
    return any(_is_legitimate_brand_domain(domain, brand) for brand in _BRAND_DOMAINS)


def _is_esp_domain(domain: str) -> bool:
    return any(domain == esp or domain.endswith(f".{esp}") for esp in _ESP_DOMAINS)


def _hyphenated_domain_segments(sender_domain: str) -> list[str]:
    """Hyphen-separated parts of the registered label (≥3 chars).

    Lets 'docs-google-verify.com' match 'google'. Sub-3-char segments
    can't carry a typosquat budget."""
    label = domain_label(sender_domain)
    if not label:
        return []
    return [segment for segment in label.split("-") if len(segment) >= 3]


def _build_cousin_domain_signal(sender_domain: str, brand: str, distance: int) -> Signal:
    confidence = 1.0 if distance == 0 else 0.9 if distance == 1 else 0.8
    return Signal(
        id="cousin_domain",
        category=SignalCategory.SENDER_IDENTITY,
        severity=SignalSeverity.CRITICAL,
        confidence=confidence,
        summary=f"Sender domain '{sender_domain}' resembles brand '{brand}'",
    )


class SenderAnalyzer(BaseAnalyzer):

    @property
    def name(self) -> str:
        return "sender_analyzer"

    def analyze(self, email: EmailData) -> AnalysisOutput:
        sender_domain = email_domain(email.sender_address)
        if sender_domain is None:
            # Surface as blind spot rather than letting the verdict look clean.
            return AnalysisOutput(
                signals=(),
                blind_spots=(SENDER_ADDRESS_UNPARSEABLE,),
            )

        candidates = (
            self._cousin_domain_signal(sender_domain),
            self._reply_to_mismatch_signal(email, sender_domain),
            self._return_path_mismatch_signal(email, sender_domain),
        )
        return AnalysisOutput(
            signals=tuple(signal for signal in candidates if signal is not None),
            blind_spots=(),
        )

    def _cousin_domain_signal(self, sender_domain: str) -> Signal | None:
        if _matches_any_brand(sender_domain):
            return None

        for segment in _hyphenated_domain_segments(sender_domain):
            normalized = normalize_typosquat(segment)
            for brand in _BRAND_DOMAINS:
                distance = levenshtein_distance(normalized, brand)
                if distance <= max_typosquat_distance(brand):
                    return _build_cousin_domain_signal(sender_domain, brand, distance)
        return None

    def _reply_to_mismatch_signal(
        self, email: EmailData, sender_domain: str
    ) -> Signal | None:
        if not email.reply_to_address:
            return None

        reply_domain = email_domain(email.reply_to_address)
        if reply_domain is None or reply_domain == sender_domain:
            return None
        if same_organization(reply_domain, sender_domain):
            return None
        if _is_esp_domain(reply_domain):
            return None
        # Freemail-to-anywhere reply-to is too noisy — users routinely set
        # a different reply address on personal mail.
        if sender_domain in _FREEMAIL_DOMAINS:
            return None

        return Signal(
            id="reply_to_mismatch",
            category=SignalCategory.SENDER_IDENTITY,
            severity=SignalSeverity.HIGH,
            confidence=1.0,
            summary=(
                f"Reply-To domain ({reply_domain}) differs from "
                f"sender domain ({sender_domain})"
            ),
        )

    def _return_path_mismatch_signal(self, email: EmailData, sender_domain: str) -> Signal | None:
        if not email.return_path_address:
            return None

        return_domain = email_domain(email.return_path_address)
        if return_domain is None or return_domain == sender_domain:
            return None
        if same_organization(return_domain, sender_domain):
            return None
        if _is_esp_domain(return_domain):
            return None

        return Signal(
            id="return_path_mismatch",
            category=SignalCategory.SENDER_IDENTITY,
            severity=SignalSeverity.MEDIUM,
            confidence=0.8,
            summary=(
                f"Return-Path domain ({return_domain}) differs from "
                f"sender domain ({sender_domain})"
            ),
        )
