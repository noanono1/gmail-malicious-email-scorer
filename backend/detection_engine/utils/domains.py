"""Domain-name parsing utilities shared by analyzers.

All functions are pure and deterministic. ``tldextract`` is configured
to use only its bundled public-suffix snapshot — no network fetches and
no on-disk cache — to honour the analyzer base contract that detection
performs no I/O.

Note: this module is named ``domains`` (plural) to distinguish it from
the ``detection_engine.domain`` package, which holds the domain *model*
(EmailData, Signal, Verdict, etc.)."""

from __future__ import annotations

import tldextract

_extractor = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=False)


def email_domain(address: str) -> str | None:
    """Lower-cased domain part of an email address, or None if missing.

    Returns None for inputs without an '@' so callers can short-circuit
    on malformed addresses without raising."""
    _, sep, domain = address.rpartition("@")
    if not sep:
        return None
    return domain.lower() if domain else None


def registered_domain(domain: str) -> str:
    """Public-suffix-aware registrable domain.

    Examples:
      ``mail.paypal.com`` → ``paypal.com``
      ``bounces.amazon.co.uk`` → ``amazon.co.uk``
    Falls back to *domain* unchanged if the public suffix can't be parsed."""
    extracted = _extractor(domain)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return domain


def domain_label(domain: str) -> str:
    """The brand-bearing label of a domain.

    Examples:
      ``mail.paypal.com`` → ``paypal``
      ``amazon.co.uk`` → ``amazon``
    Empty string if the domain has no recognisable label."""
    return _extractor(domain).domain


def public_suffix(domain: str) -> str:
    """The public suffix of a domain.

    Examples:
      ``paypal.com`` → ``com``
      ``amazon.co.uk`` → ``co.uk``
    Empty string if the suffix can't be parsed."""
    return _extractor(domain).suffix


def same_organization(domain_a: str, domain_b: str) -> bool:
    """True iff both domains share the same registered domain."""
    return registered_domain(domain_a) == registered_domain(domain_b)
