"""Reusable test email fixtures with expected verdicts.

Each fixture is a dict mirroring the JSON the add-on sends, paired with
scoring expectations. Use ``build_email_data`` to convert a fixture dict
into an ``EmailData`` domain object for engine tests.
"""

from __future__ import annotations

from datetime import datetime, timezone
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
# Fixtures — each has "email" (raw dict) + "expected" (scoring contract)
# ---------------------------------------------------------------------------

MASS_PHISHING = {
    "label": "Mass phishing — spoofed PayPal, auth fail, IP URL, urgency",
    "expected": {
        "verdict": Verdict.MALICIOUS,
        "min_score": 65,
    },
    "email": {
        "message_id": "phish-001",
        "sender": "security@paypa1-support.com",
        "recipient": "victim@example.com",
        "subject": "Your account has been limited - Immediate action required",
        "date": "2026-05-01T10:00:00+00:00",
        "body_text": (
            "Dear Customer,\n\n"
            "We have detected unusual activity on your account. "
            "Your account will be suspended within 24 hours unless you verify "
            "your identity immediately.\n\n"
            "Click here to verify: http://192.168.1.100/verify-account\n\n"
            "If you do not respond, your account will be permanently closed.\n\n"
            "PayPal Security Team"
        ),
        "body_html": (
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
        "headers": [
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
    },
}

LEGIT_AMAZON_ORDER = {
    "label": "Legitimate Amazon order confirmation — valid auth, real domain",
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 15,
    },
    "email": {
        "message_id": "amazon-001",
        "sender": "ship-confirm@amazon.com",
        "recipient": "customer@gmail.com",
        "subject": "Your Amazon.com order #112-9876543-2109876 has shipped",
        "date": "2026-05-01T08:30:00+00:00",
        "body_text": (
            "Hello,\n\n"
            "Your order has shipped! Here are the details:\n\n"
            "Order #112-9876543-2109876\n"
            "Arriving Tuesday, May 5\n"
            "USB-C Charging Cable (2-Pack)\n\n"
            "Track your package: https://www.amazon.com/gp/your-account/order-history\n\n"
            "Thank you for shopping with us.\n"
            "Amazon.com"
        ),
        "body_html": "",
        "headers": [
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
    },
}

BEC_WIRE_TRANSFER = {
    "label": "BEC — freemail CEO impersonation, wire transfer, secrecy, reply-to mismatch",
    "expected": {
        "verdict_in": [Verdict.SUSPICIOUS, Verdict.LIKELY_MALICIOUS],
        "min_score": 15,
        "max_score": 65,
    },
    "email": {
        "message_id": "bec-001",
        "sender": "john.smith.ceo@gmail.com",
        "recipient": "finance@acmecorp.com",
        "subject": "Urgent wire transfer needed",
        "date": "2026-05-01T14:00:00+00:00",
        "body_text": (
            "Hi,\n\n"
            "I need you to process a wire transfer of $45,000 to a new vendor today. "
            "This is time-sensitive and confidential — please don't discuss it with "
            "anyone else until it's done.\n\n"
            "I'll send the account details shortly. Please confirm you can handle "
            "this right away.\n\n"
            "Thanks,\n"
            "John Smith\nCEO"
        ),
        "body_html": "",
        "headers": [
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
    },
}

SPEAR_PHISH_COUSIN_DOMAIN = {
    "label": "Spear-phish — cousin domain (arnazon.com), auth passes, credential ask",
    "expected": {
        "verdict_in": [Verdict.LIKELY_MALICIOUS, Verdict.MALICIOUS],
        "min_score": 35,
    },
    "email": {
        "message_id": "spear-001",
        "sender": "account-update@arnazon.com",
        "recipient": "employee@targetcorp.com",
        "subject": "Action required: verify your payment method",
        "date": "2026-05-01T11:15:00+00:00",
        "body_text": (
            "Dear valued customer,\n\n"
            "We were unable to process your most recent payment. "
            "To avoid service interruption, please update your payment "
            "information within 48 hours.\n\n"
            "Update now: https://arnazon.com/account/verify-payment\n\n"
            "If you believe this is an error, please contact our support team.\n\n"
            "Amazon Customer Service"
        ),
        "body_html": (
            "<html><body>"
            "<p>Dear valued customer,</p>"
            "<p>We were unable to process your most recent payment. "
            "To avoid service interruption, please update your payment "
            "information within <b>48 hours</b>.</p>"
            '<p><a href="https://arnazon.com/account/verify-payment">'
            "Update your payment method</a></p>"
            "</body></html>"
        ),
        "headers": [
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
    },
}

LEGIT_MARKETING = {
    "label": "Legitimate marketing — ESP return-path, valid auth, unsubscribe link",
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 15,
    },
    "email": {
        "message_id": "marketing-001",
        "sender": "deals@shop.example.com",
        "recipient": "subscriber@gmail.com",
        "subject": "Weekend sale — 20% off everything",
        "date": "2026-05-01T09:00:00+00:00",
        "body_text": (
            "Hi there!\n\n"
            "This weekend only, enjoy 20% off everything in our store.\n\n"
            "Shop now: https://shop.example.com/sale\n\n"
            "Unsubscribe: https://shop.example.com/unsubscribe?id=abc123\n"
        ),
        "body_html": "",
        "headers": [
            {"name": "From", "value": "deals@shop.example.com"},
            {"name": "To", "value": "subscriber@gmail.com"},
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
    },
}

MALWARE_ATTACHMENT = {
    "label": "Malware delivery — double extension .pdf.exe, urgency",
    "expected": {
        "verdict": Verdict.MALICIOUS,
        "min_score": 65,
    },
    "email": {
        "message_id": "malware-001",
        "sender": "invoices@billing-dept.xyz",
        "recipient": "accounts@targetcorp.com",
        "subject": "URGENT: Outstanding invoice #INV-2026-0451 attached",
        "date": "2026-05-01T16:45:00+00:00",
        "body_text": (
            "Please find attached the overdue invoice for immediate payment.\n\n"
            "This invoice is past due. Failure to remit payment within 24 hours "
            "may result in service suspension.\n\n"
            "Regards,\nBilling Department"
        ),
        "body_html": "",
        "headers": [
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
        "attachments": [
            {
                "filename": "invoice_2026_0451.pdf.exe",
                "mime_type": "application/x-msdownload",
                "size_bytes": 245760,
            },
        ],
    },
}

EMPTY_MINIMAL = {
    "label": "Empty / minimal email — no crash, no false positive",
    "expected": {
        "verdict": Verdict.SAFE,
        "max_score": 15,
    },
    "email": {
        "message_id": "empty-001",
        "sender": "someone@example.com",
        "recipient": "other@example.com",
        "subject": "",
        "body_text": "",
        "body_html": "",
        "headers": [
            {"name": "From", "value": "someone@example.com"},
            {"name": "To", "value": "other@example.com"},
        ],
    },
}


# ---------------------------------------------------------------------------
# All fixtures for parametrized tests
# ---------------------------------------------------------------------------

ALL_FIXTURES = [
    MASS_PHISHING,
    LEGIT_AMAZON_ORDER,
    BEC_WIRE_TRANSFER,
    SPEAR_PHISH_COUSIN_DOMAIN,
    LEGIT_MARKETING,
    MALWARE_ATTACHMENT,
    EMPTY_MINIMAL,
]
