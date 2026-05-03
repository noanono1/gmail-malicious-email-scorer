"""Unit tests for SenderAnalyzer — cousin domain, display name impersonation,
freemail, reply-to, return-path."""

from __future__ import annotations

import pytest

from detection_engine.analyzers.sender import (
    SenderAnalyzer,
    _extract_claimed_identity_tokens,
    _levenshtein,
    _normalize,
    _registered_domain,
    _same_organization,
    _sender_domain,
    _sender_domain_segments,
)
from detection_engine.domain.email import EmailData, EmailHeaders
from detection_engine.domain.enums import SignalCategory, SignalSeverity
from tests.email_fixtures import (
    BEC_WIRE_TRANSFER,
    EMPTY_MINIMAL,
    LEGIT_AMAZON_ORDER,
    LEGIT_MARKETING,
    MALWARE_ATTACHMENT,
    MASS_PHISHING,
    SPEAR_PHISH_COUSIN_DOMAIN,
    build_email_data,
)


def _make_email(
    sender_address: str = "test@example.com",
    sender_display_name: str = "",
    reply_to_address: str = "",
    return_path_address: str = "",
    headers: list[tuple[str, str]] | None = None,
) -> EmailData:
    if headers is None:
        headers = [("From", sender_address), ("To", "user@example.com")]
    return EmailData(
        message_id="test-001",
        sender_address=sender_address,
        sender_display_name=sender_display_name,
        recipient="user@example.com",
        subject="Test",
        body_text="",
        body_html="",
        reply_to_address=reply_to_address,
        return_path_address=return_path_address,
        headers=EmailHeaders(headers),
    )


@pytest.fixture
def analyzer() -> SenderAnalyzer:
    return SenderAnalyzer()


# ---------------------------------------------------------------------------
# SENDER-1: Cousin domain (domain-driven, no display name needed)
# ---------------------------------------------------------------------------


class TestCousinDomain:
    def test_digit_substitution(self, analyzer: SenderAnalyzer):
        email = _make_email(sender_address="user@paypa1-support.com")
        output = analyzer.analyze(email)
        cousin = [s for s in output.signals if s.id == "cousin_domain"]
        assert len(cousin) == 1
        assert cousin[0].severity == SignalSeverity.CRITICAL
        assert "paypal" in cousin[0].evidence

    def test_rn_substitution(self, analyzer: SenderAnalyzer):
        email = _make_email(sender_address="user@arnazon.com")
        output = analyzer.analyze(email)
        cousin = [s for s in output.signals if s.id == "cousin_domain"]
        assert len(cousin) == 1
        assert "amazon" in cousin[0].evidence

    def test_brand_embedded_in_domain(self, analyzer: SenderAnalyzer):
        email = _make_email(sender_address="user@docs-google-verify.com")
        output = analyzer.analyze(email)
        cousin = [s for s in output.signals if s.id == "cousin_domain"]
        assert len(cousin) == 1
        assert cousin[0].severity == SignalSeverity.CRITICAL

    def test_legitimate_domain_not_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(sender_address="user@paypal.com")
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "cousin_domain"]

    def test_subdomain_of_legitimate_not_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(sender_address="user@mail.paypal.com")
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "cousin_domain"]

    def test_unrelated_domain_not_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(sender_address="user@random.com")
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "cousin_domain"]

    def test_confidence_exact_after_normalization(self, analyzer: SenderAnalyzer):
        email = _make_email(sender_address="user@paypa1.com")
        output = analyzer.analyze(email)
        signal = [s for s in output.signals if s.id == "cousin_domain"][0]
        assert signal.confidence == 1.0

    def test_only_one_signal_per_email(self, analyzer: SenderAnalyzer):
        email = _make_email(sender_address="user@paypa1.com")
        output = analyzer.analyze(email)
        assert len([s for s in output.signals if s.id == "cousin_domain"]) == 1


# ---------------------------------------------------------------------------
# SENDER-5: Display name impersonation (display name claims a brand the
# domain doesn't own)
# ---------------------------------------------------------------------------


class TestDisplayNameImpersonation:
    def test_brand_name_from_unrelated_domain(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender_address="user@random.com",
            sender_display_name="PayPal Security",
        )
        output = analyzer.analyze(email)
        imp = [s for s in output.signals if s.id == "display_name_impersonation"]
        assert len(imp) == 1
        assert imp[0].severity == SignalSeverity.HIGH
        assert "paypal" in imp[0].evidence

    def test_brand_name_from_freemail(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender_address="user@gmail.com",
            sender_display_name="Microsoft Support",
        )
        output = analyzer.analyze(email)
        imp = [s for s in output.signals if s.id == "display_name_impersonation"]
        assert len(imp) == 1
        assert "microsoft" in imp[0].evidence

    def test_brand_alone_sufficient(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender_address="user@random.com",
            sender_display_name="PayPal",
        )
        output = analyzer.analyze(email)
        imp = [s for s in output.signals if s.id == "display_name_impersonation"]
        assert len(imp) == 1

    def test_legitimate_domain_not_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender_address="user@paypal.com",
            sender_display_name="PayPal Security",
        )
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "display_name_impersonation"]

    def test_defers_to_cousin_domain(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender_address="user@paypa1.com",
            sender_display_name="PayPal Security",
        )
        output = analyzer.analyze(email)
        assert [s for s in output.signals if s.id == "cousin_domain"]
        assert not [s for s in output.signals if s.id == "display_name_impersonation"]

    def test_no_display_name_no_signal(self, analyzer: SenderAnalyzer):
        email = _make_email(sender_address="user@random.com")
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "display_name_impersonation"]

    def test_generic_display_name_no_signal(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender_address="user@random.com",
            sender_display_name="IT Support",
        )
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "display_name_impersonation"]

    def test_personal_name_no_signal(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender_address="alice@company.com",
            sender_display_name="Alice Johnson",
        )
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "display_name_impersonation"]

    def test_subdomain_of_brand_not_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender_address="user@mail.paypal.com",
            sender_display_name="PayPal",
        )
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "display_name_impersonation"]


# ---------------------------------------------------------------------------
# SENDER-2: Freemail with organizational display name
# ---------------------------------------------------------------------------


class TestFreemailOrgName:
    def test_freemail_with_org_keyword(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender_address="fake@gmail.com",
            sender_display_name="PayPal Security",
        )
        output = analyzer.analyze(email)
        freemail = [s for s in output.signals if s.id == "freemail_org_name"]
        assert len(freemail) == 1
        assert freemail[0].severity == SignalSeverity.MEDIUM

    def test_freemail_without_display_name(self, analyzer: SenderAnalyzer):
        email = _make_email(sender_address="user@gmail.com")
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "freemail_org_name"]

    def test_freemail_with_personal_name(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender_address="john@gmail.com",
            sender_display_name="John Smith",
        )
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "freemail_org_name"]

    def test_non_freemail_with_org_name(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender_address="user@company.com",
            sender_display_name="IT Security",
        )
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "freemail_org_name"]


# ---------------------------------------------------------------------------
# SENDER-3: Reply-To mismatch
# ---------------------------------------------------------------------------


class TestReplyToMismatch:
    def test_different_domain_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender_address="user@company.com",
            reply_to_address="secret@different.com",
        )
        output = analyzer.analyze(email)
        mismatch = [s for s in output.signals if s.id == "reply_to_mismatch"]
        assert len(mismatch) == 1
        assert mismatch[0].severity == SignalSeverity.HIGH

    def test_same_domain_not_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender_address="user@company.com",
            reply_to_address="other@company.com",
        )
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "reply_to_mismatch"]

    def test_subdomain_reply_to_not_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender_address="user@company.com",
            reply_to_address="support@mail.company.com",
        )
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "reply_to_mismatch"]

    def test_absent_reply_to_not_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(sender_address="user@company.com")
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "reply_to_mismatch"]

    def test_esp_reply_to_not_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender_address="user@company.com",
            reply_to_address="track@em.sendgrid.net",
        )
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "reply_to_mismatch"]

    def test_freemail_sender_reply_to_not_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender_address="john@gmail.com",
            reply_to_address="john.doe@yahoo.com",
        )
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "reply_to_mismatch"]

    def test_freemail_to_freemail_protonmail(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender_address="ceo@outlook.com",
            reply_to_address="ceo-payments@protonmail.com",
        )
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "reply_to_mismatch"]

    def test_non_freemail_to_freemail_still_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender_address="ceo@bigcorp.com",
            reply_to_address="secret@gmail.com",
        )
        output = analyzer.analyze(email)
        mismatch = [s for s in output.signals if s.id == "reply_to_mismatch"]
        assert len(mismatch) == 1


# ---------------------------------------------------------------------------
# SENDER-4: Return-Path mismatch (ESP-aware)
# ---------------------------------------------------------------------------


class TestReturnPathMismatch:
    def test_different_non_esp_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender_address="user@company.com",
            return_path_address="bounce@shady.xyz",
        )
        output = analyzer.analyze(email)
        rp = [s for s in output.signals if s.id == "return_path_mismatch"]
        assert len(rp) == 1
        assert rp[0].severity == SignalSeverity.MEDIUM

    def test_esp_return_path_not_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender_address="user@company.com",
            return_path_address="bounces@em.sendgrid.net",
        )
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "return_path_mismatch"]

    def test_amazonses_not_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender_address="user@amazon.com",
            return_path_address="bounce@amazonses.com",
        )
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "return_path_mismatch"]

    def test_same_domain_not_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender_address="user@company.com",
            return_path_address="noreply@company.com",
        )
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "return_path_mismatch"]

    def test_bounce_subdomain_not_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender_address="alerts@accounts.google.com",
            return_path_address="noreply@gaia.bounces.google.com",
        )
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "return_path_mismatch"]

    def test_country_tld_subdomain_not_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender_address="user@amazon.co.uk",
            return_path_address="bounce@ses.amazon.co.uk",
        )
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "return_path_mismatch"]

    def test_different_registered_domain_still_flagged(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender_address="ceo@company.com",
            return_path_address="bounce@attacker.com",
        )
        output = analyzer.analyze(email)
        rp = [s for s in output.signals if s.id == "return_path_mismatch"]
        assert len(rp) == 1


# ---------------------------------------------------------------------------
# Score contribution
# ---------------------------------------------------------------------------


class TestScoreContribution:
    def test_all_signals_have_zero_contribution(self, analyzer: SenderAnalyzer):
        email = _make_email(
            sender_address="user@paypa1.com",
            sender_display_name="PayPal Support",
            reply_to_address="secret@evil.com",
            return_path_address="bounce@shady.xyz",
        )
        output = analyzer.analyze(email)
        assert len(output.signals) > 0
        assert all(s.score_contribution == 0.0 for s in output.signals)


# ---------------------------------------------------------------------------
# Real fixtures
# ---------------------------------------------------------------------------


class TestRealFixtures:
    def test_mass_phishing(self, analyzer: SenderAnalyzer):
        email = build_email_data(MASS_PHISHING["email"])
        output = analyzer.analyze(email)
        ids = {s.id for s in output.signals}
        assert "cousin_domain" in ids
        assert "return_path_mismatch" in ids

    def test_legit_amazon(self, analyzer: SenderAnalyzer):
        email = build_email_data(LEGIT_AMAZON_ORDER["email"])
        output = analyzer.analyze(email)
        assert len(output.signals) == 0

    def test_bec_freemail_reply_to_suppressed(self, analyzer: SenderAnalyzer):
        email = build_email_data(BEC_WIRE_TRANSFER["email"])
        output = analyzer.analyze(email)
        assert not [s for s in output.signals if s.id == "reply_to_mismatch"]

    def test_spear_phish_cousin_domain(self, analyzer: SenderAnalyzer):
        email = build_email_data(SPEAR_PHISH_COUSIN_DOMAIN["email"])
        output = analyzer.analyze(email)
        ids = {s.id for s in output.signals}
        assert "cousin_domain" in ids

    def test_legit_marketing(self, analyzer: SenderAnalyzer):
        email = build_email_data(LEGIT_MARKETING["email"])
        output = analyzer.analyze(email)
        assert len(output.signals) == 0

    def test_malware_no_sender_signals(self, analyzer: SenderAnalyzer):
        email = build_email_data(MALWARE_ATTACHMENT["email"])
        output = analyzer.analyze(email)
        assert len(output.signals) == 0

    def test_empty_minimal(self, analyzer: SenderAnalyzer):
        email = build_email_data(EMPTY_MINIMAL["email"])
        output = analyzer.analyze(email)
        assert len(output.signals) == 0


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_sender_domain(self):
        assert _sender_domain("user@example.com") == "example.com"

    def test_sender_domain_empty(self):
        assert _sender_domain("not-an-email") is None

    def test_levenshtein_identical(self):
        assert _levenshtein("paypal", "paypal") == 0

    def test_levenshtein_one_substitution(self):
        assert _levenshtein("paypal", "paypol") == 1

    def test_levenshtein_one_insertion(self):
        assert _levenshtein("paypal", "paypall") == 1

    def test_levenshtein_arnazon_amazon(self):
        assert _levenshtein("arnazon", "amazon") == 2

    def test_normalize_digit_one(self):
        assert _normalize("paypa1") == "paypal"

    def test_normalize_rn_to_m(self):
        assert _normalize("arnazon") == "amazon"

    def test_normalize_digit_zero(self):
        assert _normalize("g00gle") == "google"

    def test_registered_domain_simple(self):
        assert _registered_domain("google.com") == "google.com"

    def test_registered_domain_subdomain(self):
        assert _registered_domain("accounts.google.com") == "google.com"

    def test_registered_domain_deep_subdomain(self):
        assert _registered_domain("gaia.bounces.google.com") == "google.com"

    def test_registered_domain_country_tld(self):
        assert _registered_domain("amazon.co.uk") == "amazon.co.uk"

    def test_same_organization_true(self):
        assert _same_organization("bounces.google.com", "accounts.google.com")

    def test_same_organization_false(self):
        assert not _same_organization("google.com", "attacker.com")

    def test_same_organization_country_tld(self):
        assert _same_organization("ses.amazon.co.uk", "amazon.co.uk")

    def test_extract_claimed_identity_tokens_filters_generic(self):
        assert _extract_claimed_identity_tokens("IT Security Support") == []

    def test_extract_claimed_identity_tokens_keeps_brand(self):
        assert _extract_claimed_identity_tokens("PayPal Security") == ["paypal"]

    def test_extract_claimed_identity_tokens_multiple(self):
        tokens = _extract_claimed_identity_tokens("Amazon Prime Service")
        assert "amazon" in tokens
        assert "prime" in tokens

    def test_extract_claimed_identity_tokens_short_filtered(self):
        assert _extract_claimed_identity_tokens("AT T") == []

    def test_sender_domain_segments_simple(self):
        assert _sender_domain_segments("paypal.com") == ["paypal"]

    def test_sender_domain_segments_hyphenated(self):
        assert _sender_domain_segments("paypa1-support.com") == ["paypa1", "support"]

    def test_sender_domain_segments_short_filtered(self):
        assert _sender_domain_segments("a-bc-def.com") == ["def"]
