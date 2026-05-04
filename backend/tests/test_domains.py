"""Unit tests for the shared domain-name parsing utilities."""

from __future__ import annotations

import pytest

from detection_engine.utils.domains import (
    domain_label,
    email_domain,
    public_suffix,
    registered_domain,
    same_organization,
)


class TestEmailDomain:
    @pytest.mark.parametrize(
        ("address", "expected"),
        [
            ("user@example.com", "example.com"),
            ("user@Example.COM", "example.com"),
            ("not-an-email", None),
            ("@example.com", "example.com"),
            ("user@", None),
        ],
        ids=["simple", "lowercases", "no_at_returns_none", "empty_local_part", "empty_domain_returns_none"],
    )
    def test_email_domain(self, address, expected):
        assert email_domain(address) == expected


class TestRegisteredDomain:
    @pytest.mark.parametrize(
        ("domain", "expected"),
        [
            ("google.com", "google.com"),
            ("accounts.google.com", "google.com"),
            ("gaia.bounces.google.com", "google.com"),
            ("amazon.co.uk", "amazon.co.uk"),
            ("ses.amazon.co.uk", "amazon.co.uk"),
        ],
        ids=["simple", "subdomain", "deep_subdomain", "country_tld", "subdomain_on_country_tld"],
    )
    def test_registered_domain(self, domain, expected):
        assert registered_domain(domain) == expected


class TestDomainLabel:
    @pytest.mark.parametrize(
        ("domain", "expected"),
        [
            ("paypal.com", "paypal"),
            ("mail.paypal.com", "paypal"),
            ("amazon.co.uk", "amazon"),
        ],
        ids=["simple", "subdomain", "country_tld"],
    )
    def test_domain_label(self, domain, expected):
        assert domain_label(domain) == expected


class TestPublicSuffix:
    @pytest.mark.parametrize(
        ("domain", "expected"),
        [
            ("paypal.com", "com"),
            ("amazon.co.uk", "co.uk"),
            ("gaia.bounces.google.com", "com"),
        ],
        ids=["simple", "country_tld", "deep_subdomain_unchanged"],
    )
    def test_public_suffix(self, domain, expected):
        assert public_suffix(domain) == expected


class TestSameOrganization:
    @pytest.mark.parametrize(
        ("left", "right", "expected"),
        [
            ("bounces.google.com", "accounts.google.com", True),
            ("google.com", "attacker.com", False),
            ("ses.amazon.co.uk", "amazon.co.uk", True),
            ("paypal.com", "paypal.xyz", False),
        ],
        ids=["subdomains_match", "unrelated_domains_differ", "country_tld_subdomain_matches", "different_tlds_differ"],
    )
    def test_same_organization(self, left, right, expected):
        assert same_organization(left, right) is expected
