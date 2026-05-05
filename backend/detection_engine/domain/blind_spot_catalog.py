from __future__ import annotations

import re

from detection_engine.domain.email import EmailData
from detection_engine.domain.enums import BlindSpotArea
from detection_engine.domain.signals import BlindSpot

# ── Predicates (closed set of conditions) ────────────────────────────

_IMG_TAG_PATTERN = re.compile(r"<img\b", re.IGNORECASE)


def _contains_images(email: EmailData) -> bool:
    if email.body_html and _IMG_TAG_PATTERN.search(email.body_html):
        return True
    return any(a.mime_type.startswith("image/") for a in email.attachments)


def _has_html_body(email: EmailData) -> bool:
    return bool(email.body_html)


# ── Structural blind spots ───────────────────────────────────────────
# Engine evaluates these generically against every email.
# To add a new structural blind spot, add one entry here — no engine changes needed.

STRUCTURAL: tuple[BlindSpot, ...] = (
    BlindSpot(
        area=BlindSpotArea.THREAD_HISTORY,
        reason="Single-email analysis only",
        risk_note="Only this email was analyzed — surrounding thread context was not considered.",
    ),
    BlindSpot(
        area=BlindSpotArea.EMBEDDED_IMAGE,
        reason="Embedded images not analyzed",
        risk_note="Image contents were not extracted — any text or QR codes inside images were not read.",
        applies=_contains_images,
    ),
    BlindSpot(
        area=BlindSpotArea.HTML_RENDERING,
        reason="HTML body not rendered — text extracted from raw markup",
        risk_note="The message was not rendered as a browser would display it, so CSS- or script-driven content was not evaluated.",
        applies=_has_html_body,
    ),
)

# ── Analyzer-reported ───────────────────────────────────────────────
# Conditions are analyzer-internal — the catalog provides the constant,
# the analyzer decides when to return it.

AUTHENTICATION_HEADERS_MISSING = BlindSpot(
    area=BlindSpotArea.AUTHENTICATION_HEADERS,
    reason="No Authentication-Results header present",
    risk_note="SPF, DKIM, and DMARC were not evaluated for this email.",
)

_AUTHENTICATION_UNENFORCEABLE_RISK_NOTES: dict[tuple[str, str], str] = {
    ("spf",   "none"):      "Sender domain publishes no SPF policy — the originating server cannot be verified",
    ("dkim",  "none"):      "Message was not DKIM-signed — message integrity cannot be verified",
    ("dmarc", "none"):      "Sender domain publishes no DMARC policy — domain alignment cannot be enforced",
    ("spf",   "temperror"): "SPF check failed transiently — origin server could not be verified for this delivery",
    ("dkim",  "temperror"): "DKIM check failed transiently — message integrity could not be verified for this delivery",
    ("dmarc", "temperror"): "DMARC check failed transiently — domain alignment could not be evaluated for this delivery",
}


def authentication_unenforceable(method: str, result: str) -> BlindSpot:
    return BlindSpot(
        area=BlindSpotArea.AUTHENTICATION_HEADERS,
        reason=f"{method.upper()} returned '{result}' — verification could not be performed",
        risk_note=_AUTHENTICATION_UNENFORCEABLE_RISK_NOTES[(method, result)],
    )

ATTACHMENT_CONTENT = BlindSpot(
    area=BlindSpotArea.ATTACHMENT_CONTENT,
    reason="Attachment content not inspected — metadata-only analysis",
    risk_note="Only attachment metadata (name, size, type) was checked — file contents were not opened or scanned.",
)

URL_DESTINATION = BlindSpot(
    area=BlindSpotArea.URL_DESTINATION,
    reason="URLs found but not followed — cannot verify destination content",
    risk_note="URLs were detected, but destination pages were not fetched or verified.",
)

SENDER_ADDRESS_UNPARSEABLE = BlindSpot(
    area=BlindSpotArea.SENDER_IDENTITY,
    reason="From address could not be parsed",
    risk_note=(
        "Sender identity checks (cousin domain, display-name impersonation, "
        "reply-to and return-path mismatch) were skipped"
    ),
)

LANGUAGE_ASSESSMENT_UNAVAILABLE = BlindSpot(
    area=BlindSpotArea.LANGUAGE_ASSESSMENT,
    reason="Language assessment unavailable — local SLM unreachable or its response failed validation",
    risk_note=(
        "Social-engineering language (paraphrased urgency, credential solicitation, "
        "authority impersonation, financial lure) could not be assessed for this email"
    ),
)
