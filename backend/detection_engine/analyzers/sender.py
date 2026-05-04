from __future__ import annotations

import re

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

# ---------------------------------------------------------------------------
# Sender-detection catalogs
# ---------------------------------------------------------------------------

# Known brand → legitimate domains owned by that brand. Used to recognise
# both legitimate brand mail (no signal) and impersonators (cousin/typosquat).
# This is a small built-in brand catalog for deterministic demo detection.
# In production, this should come from an external intel/config source.
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

# Public suffixes that legitimate global brands realistically use for
# regional variants (paypal.fr, amazon.in, ebay.co.uk). Restricted on
# purpose — fancy gTLDs like .xyz/.shop/.zip stay out so squatters such
# as `paypal.xyz` still hit the cousin-domain detector.
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

# Words that flag an organizational identity claim when paired with a
# freemail sender — a real org wouldn't mail you from gmail.com.
_ORG_KEYWORDS: frozenset[str] = frozenset({
    "bank", "security", "support", "helpdesk", "official",
    "team", "department", "dept", "corporate", "inc", "ltd",
    "foundation", "institute", "government", "federal",
})

# Email service providers that legitimately appear in Reply-To/Return-Path
# even when the sender domain belongs to the brand using them.
_ESP_DOMAINS: frozenset[str] = frozenset({
    "sendgrid.net", "amazonses.com", "mailchimp.com", "mandrillapp.com",
    "mailgun.org", "postmarkapp.com", "sparkpostmail.com",
    "sailthru.com", "exacttarget.com", "responsys.com",
    "constantcontact.com", "sendinblue.com", "brevo.com",
    "mailjet.com", "hubspot.com",
})

# Tokens that carry no identity information in a display name. Filtered
# out before checking the remaining tokens against the brand list, so
# 'IT Security Support' yields no candidate brand claims. Builds on
# _ORG_KEYWORDS so the two sets stay in sync — a word that flags an
# org-claim from freemail can never also count as a personal identity.
_NON_IDENTITY_TOKENS: frozenset[str] = _ORG_KEYWORDS | frozenset({
    "customer", "service", "services", "center", "centre",
    "notification", "notifications", "alert", "alerts",
    "account", "accounts", "billing", "admin", "administrator",
    "info", "information", "noreply", "reply", "mail", "email",
    "update", "updates", "verify", "verification", "confirm",
    "the", "from", "your", "our", "dear", "welcome", "new",
    "please", "important", "urgent", "action", "required",
    "mr", "mrs", "ms", "dr", "sir", "madam",
    "online", "secure", "system", "systems", "automated",
})

_DISPLAY_NAME_TOKEN_SPLIT = re.compile(r"[\s\-_.,;:!?|/\\@()\[\]<>\"']+")
_FREEMAIL_NAME_WORD_SPLIT = re.compile(r"[\s\-_]+")


# ---------------------------------------------------------------------------
# Sender-detection helpers
# ---------------------------------------------------------------------------


def _is_legitimate_brand_domain(domain: str, brand: str) -> bool:
    """True if *domain* is a legitimate domain owned by *brand*.

    Recognises three cases:
      • an exact known brand domain (paypal.com),
      • a subdomain of one (mail.paypal.com),
      • a regional variant — the brand label sitting on a trusted TLD
        (amazon.in, paypal.fr, ebay.co.uk).

    The third case prevents legitimate regional brand mail from being
    flagged as a cousin domain when the regional TLD is not enumerated."""
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


def _claimed_identity_tokens(display_name: str) -> list[str]:
    """Identity-bearing tokens in *display_name*, lower-cased.

    Drops generic words (titles, role nouns, mail-flow boilerplate) so
    only plausible identity claims like brand names or personal names
    survive."""
    raw_tokens = _DISPLAY_NAME_TOKEN_SPLIT.split(display_name)
    return [
        token.lower()
        for token in raw_tokens
        if len(token) >= 3 and token.lower() not in _NON_IDENTITY_TOKENS
    ]


def _hyphenated_domain_segments(sender_domain: str) -> list[str]:
    """The hyphen-separated parts of the registered label.

    Cousin-domain detection compares each segment against known brands so
    'docs-google-verify.com' matches 'google'. Segments under 3 chars
    are dropped because they can't carry a typosquat budget."""
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


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


class SenderAnalyzer(BaseAnalyzer):

    @property
    def name(self) -> str:
        return "sender_analyzer"

    def analyze(self, email: EmailData) -> AnalysisOutput:
        sender_domain = email_domain(email.sender_address)
        if sender_domain is None:
            # We cannot run any sender-identity check without a domain. Surface
            # this as a blind spot so the verdict explicitly records that
            # sender checks were skipped, rather than looking clean.
            return AnalysisOutput(
                signals=(),
                blind_spots=(SENDER_ADDRESS_UNPARSEABLE,),
            )

        cousin = self._cousin_domain_signal(sender_domain)
        display_imp = self._display_name_impersonation_signal(
            email, sender_domain, cousin_already_flagged=cousin is not None
        )

        candidates = (
            cousin,
            display_imp,
            self._freemail_org_name_signal(email, sender_domain),
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

    def _display_name_impersonation_signal(
        self,
        email: EmailData,
        sender_domain: str,
        *,
        cousin_already_flagged: bool,
    ) -> Signal | None:
        # A cousin-domain finding already covers the impersonation; emitting
        # both would double-count the same deception in one category.
        if cousin_already_flagged:
            return None

        display_name = email.sender_display_name
        if not display_name:
            return None

        claimed_brands = [
            normalized
            for token in _claimed_identity_tokens(display_name)
            if (normalized := normalize_typosquat(token)) in _BRAND_DOMAINS
        ]
        if not claimed_brands:
            return None

        # Legitimate if the sender domain matches *any* of the claimed
        # brands — avoids flagging "Microsoft Apple" from apple.com on
        # the wrong brand.
        if any(_is_legitimate_brand_domain(sender_domain, b) for b in claimed_brands):
            return None

        primary_claim = claimed_brands[0]
        return Signal(
            id="display_name_impersonation",
            category=SignalCategory.SENDER_IDENTITY,
            severity=SignalSeverity.HIGH,
            confidence=0.8,
            summary=(
                f"Display name claims '{primary_claim}' "
                f"but sender domain is '{sender_domain}'"
            ),
        )

    def _freemail_org_name_signal(
        self, email: EmailData, sender_domain: str
    ) -> Signal | None:
        if sender_domain not in _FREEMAIL_DOMAINS:
            return None

        display_name = email.sender_display_name
        if not display_name:
            return None

        name_words = {w.lower() for w in _FREEMAIL_NAME_WORD_SPLIT.split(display_name)}
        if not (name_words & _ORG_KEYWORDS):
            return None

        return Signal(
            id="freemail_org_name",
            category=SignalCategory.SENDER_IDENTITY,
            severity=SignalSeverity.MEDIUM,
            confidence=0.7,
            summary=(
                f"Freemail sender ({sender_domain}) with organizational "
                f"display name '{display_name}'"
            ),
        )

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
        # Freemail-to-anywhere reply-to is too noisy to flag here — real
        # users routinely set a different reply address on personal mail.
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
