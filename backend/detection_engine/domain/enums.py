from enum import Enum


class Verdict(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    LIKELY_MALICIOUS = "likely_malicious"
    MALICIOUS = "malicious"


class SignalSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SignalCategory(str, Enum):
    AUTHENTICATION = "authentication"
    SENDER_IDENTITY = "sender_identity"
    URL_STRUCTURE = "url_structure"
    BODY_CONTENT = "body_content"
    ATTACHMENT = "attachment"


class BlindSpotArea(str, Enum):
    ATTACHMENT_CONTENT = "attachment_content"
    EMBEDDED_IMAGE = "embedded_image"
    URL_DESTINATION = "url_destination"
    AUTHENTICATION_HEADERS = "authentication_headers"
    SENDER_IDENTITY = "sender_identity"
    INTEL_SOURCE_UNAVAILABLE = "intel_source_unavailable"
    QR_CODE = "qr_code"
    HTML_RENDERING = "html_rendering"
    THREAD_HISTORY = "thread_history"


class IntelSourceType(str, Enum):
    SAFE_BROWSING = "safe_browsing"
