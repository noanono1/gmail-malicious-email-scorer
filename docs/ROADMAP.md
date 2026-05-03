# Roadmap

Development plan for the Malicious Email Scorer.
Deadline: 2026-05-03 evening (Upwind Bootcamp submission).

---

## Tier 0 — Skeleton **[DONE]**

End-to-end wiring: Gmail Add-on → Backend → hardcoded SAFE → Card UI.

### What was built

| Component | Files | What it does |
|---|---|---|
| **Gmail Add-on** | `addon/Code.gs`, `EmailExtractor.gs`, `BackendClient.gs`, `CardBuilder.gs` | Extracts email payload (headers, body, attachments), HMAC-signs the request, POSTs to `/analyze`, renders the verdict card |
| **FastAPI adapter** | `app/main.py`, `routes/analyze.py`, `auth.py`, `config.py`, `schemas.py`, `dependencies.py`, `log_setup.py` | HTTP layer with HMAC auth, Pydantic input validation, structured logging, request middleware |
| **Detection engine skeleton** | `detection_engine/engine.py`, `scoring.py` | Orchestrator (runs analyzers → intel sources → scoring → verdict), scoring algorithm (severity points, attenuation, category cap, cross-category boost) |
| **Domain model** | `detection_engine/domain/` — `email.py`, `enums.py`, `signals.py`, `verdict.py` | Frozen dataclasses: `EmailData`, `EmailHeaders` (case-insensitive, multi-value), `Signal`, `BlindSpot`, `AnalysisOutput`, `AnalysisResult`, `AnalysisScope` |
| **ABCs** | `analyzers/base.py`, `intel_sources/base.py` | `BaseAnalyzer` (pure, offline, deterministic) and `ThreatIntelSource` (network-capable, timeout-required) |
| **Test scaffolding** | `tests/email_fixtures.py`, `tests/test_tier1_detection.py` | 7 email fixtures with scoring contracts, contract tests that import Tier 1 analyzers (will fail until implemented) |

### Key design decisions locked in

- `detection_engine/` has zero framework dependencies — importable standalone
- Analyzers never make network calls; intel sources are the only network channel
- Crashes produce blind spots, never cascade failures
- `EmailHeaders` constructed from `Sequence[tuple[str, str]]`, never `dict` (preserves repeated headers)
- Scoring: `Signal.score_contribution` is the one mutable field, written only by `scoring.score()`

---

## Tier 1 — Core Analyzers **[NEXT]**

Build three analyzers that cover the highest-value, lowest-FP-risk indicators.
Success criteria: mass phishing scores ≥65 (MALICIOUS), legitimate Amazon order scores <15 (SAFE).

### 1. AuthenticationAnalyzer

| | |
|---|---|
| **File** | `detection_engine/analyzers/header.py` |
| **Category** | AUTHENTICATION |
| **Signals** | AUTH-1 (SPF fail/none → HIGH), AUTH-2 (DKIM fail/none → HIGH), AUTH-3 (DMARC fail/none → CRITICAL) |
| **Input** | `Authentication-Results` header via `email.headers.get()` |
| **Complexity** | Low — single header parse yields all three signals |
| **Blind spot** | `AUTHENTICATION_HEADERS` when header is absent |

Implementation order: first, because it's the simplest and unlocks end-to-end scoring integration testing.

### 2. SenderAnalyzer

| | |
|---|---|
| **File** | `detection_engine/analyzers/sender.py` |
| **Category** | SENDER_IDENTITY |
| **Signals** | SENDER-1 (cousin/lookalike domain → CRITICAL), SENDER-2 (freemail with org name → MEDIUM), SENDER-3 (From ≠ Reply-To → HIGH), SENDER-4 (Return-Path ≠ From domain → MEDIUM) |
| **Complexity** | Highest in Tier 1 — cousin domain detection needs a curated brand list (~20-30 brands), Levenshtein distance (threshold ≤2), and character substitution map (1↔l, 0↔o, rn↔m) |
| **Blind spot** | None expected — sender info is always present |
| **FP risk** | SENDER-4 must whitelist known ESPs (SendGrid, SES, Mailchimp) to avoid flagging legitimate marketing |

Most interview-interesting analyzer: the cousin domain algorithm demonstrates deliberate design thinking.

### 3. BodyContentAnalyzer

| | |
|---|---|
| **File** | `detection_engine/analyzers/content.py` |
| **Category** | CONTENT |
| **Signals** | CONTENT-1 (urgency/threat language → MEDIUM), CONTENT-2 (sensitive data request → HIGH), CONTENT-3 (HTML form in body → CRITICAL) |
| **Complexity** | Low-moderate — pattern matching against curated dictionaries |
| **Key design constraint** | CONTENT-1 phrases must be specific ("account will be suspended") not generic ("expires") to avoid FP on legitimate deadline emails |

Good for demonstrating supporting-signal design: MEDIUM (12 pts) cannot cross SUSPICIOUS (15) alone.

### Wiring

Update `app/dependencies.py` to inject all three analyzers into `DetectionEngine`.

### Test contracts to satisfy

| Scenario | Fixture | Expected |
|---|---|---|
| Mass phishing (spoofed PayPal, auth fail, urgency) | `MASS_PHISHING` | ≥65, MALICIOUS |
| Legitimate Amazon order (valid auth, real domain) | `LEGIT_AMAZON_ORDER` | <15, SAFE |
| BEC wire transfer (freemail, reply-to mismatch, urgency) | `BEC_WIRE_TRANSFER` | 15–64, SUSPICIOUS or LIKELY_MALICIOUS |
| Spear-phish cousin domain (arnazon.com, auth passes) | `SPEAR_PHISH_COUSIN_DOMAIN` | ≥35, LIKELY_MALICIOUS or MALICIOUS |
| Legitimate marketing (ESP return-path, valid auth) | `LEGIT_MARKETING` | <15, SAFE |
| Empty email | `EMPTY_MINIMAL` | <15, SAFE, no crash |

Note: `MALWARE_ATTACHMENT` requires Tier 2's AttachmentAnalyzer — expected to fail until then.

---

## Tier 2 — Extended Analyzers + Polish **[NOT STARTED]**

Add URL and attachment analysis. Full test suite. Demo-ready.

### 4. UrlStructureAnalyzer

| | |
|---|---|
| **File** | `detection_engine/analyzers/url_structure.py` |
| **Category** | URL_STRUCTURE |
| **Signals** | URL-1 (href ≠ display text → CRITICAL), URL-2 (IP in URL → HIGH), URL-3 (shortened URL → LOW), URL-4 (excessive URL count → INFO) |
| **Requires** | HTML parsing (`html.parser` or BeautifulSoup) |
| **Key nuance** | URL-1 should only flag when display text looks like a URL (contains a dot, no spaces) — "click here" style links are normal |

Highest single-indicator value (URL-1 is CRITICAL). Requires HTML body parsing.

### 5. AttachmentAnalyzer

| | |
|---|---|
| **File** | `detection_engine/analyzers/attachment.py` |
| **Category** | ATTACHMENT |
| **Signals** | ATTACH-1 (dangerous extension → CRITICAL), ATTACH-2 (double extension → CRITICAL), ATTACH-3 (macro-enabled Office → HIGH), ATTACH-4 (password-protected archive + body hint → HIGH) |
| **Blind spot** | `ATTACHMENT_CONTENT` whenever attachments are present (metadata-only inspection) |

Unlocks the `MALWARE_ATTACHMENT` test fixture.

### Polish

- Wire all 5 analyzers in `dependencies.py`
- All 7 test scenarios green
- Demo emails prepared and sent to test Gmail account
- README finalized (screenshot, realistic API examples)
- `config.py`: restore `os.environ["HMAC_SECRET"]` before deploy
- Deploy backend to Railway

---

## Tier 3 — Intel Sources + Polish **[POST-MVP]**

Build if Tiers 0–2 are solid and time permits. Interview talking-point material.

### Safe Browsing intel source

| | |
|---|---|
| **File** | `infrastructure/threat_intel/safe_browsing.py` |
| **Implements** | `ThreatIntelSource` ABC |
| **Purpose** | Query extracted URLs against Google Safe Browsing v4 |
| **Fallback** | `INTEL_SOURCE_UNAVAILABLE` blind spot when API key is missing |

The ABC and wiring point (`dependencies.py`) already exist — this is plug-and-play.

### Blind spots fully wired

- Every analyzer reports what it couldn't check for the specific email
- `EMBEDDED_IMAGE` blind spot when `<img>` tags are present
- `ATTACHMENT_CONTENT` blind spot when attachments are present
- Card UI displays blind spots in a collapsible section

### Card UI polish

- Verdict colors (green/yellow/orange/red), sectioned layout with collapsible blind spots and analysis scope
- Error card for backend failures: "Analysis Unavailable — could not reach the backend. This does not mean the email is safe." + Retry
- Re-analyze button

---

## Tier 4 — Future Extensions **[OUT OF SCOPE]**

Documented for interview discussion ("what would you add next?").

### Detection extensions

| Extension | Value | Complexity | Notes |
|---|---|---|---|
| LLM-assisted social engineering detection | Catch manipulation patterns rule-based can't | High | LLM as a secondary analyzer feeding signals into the scoring engine — verdict remains the engine's, not the LLM's |
| OCR for image-only phishing | QR codes, image text | High | Requires Tesseract or vision API |
| Thread awareness | Conversation hijacking, BEC | High | Breaks single-email temporal boundary |
| Multi-language content patterns | Non-English urgency detection | Medium | Curate phrase lists per language |

### Intel source expansion

| Extension | Value | Complexity | Notes |
|---|---|---|---|
| VirusTotal / PhishTank | URL and file hash reputation | Low | Same `ThreatIntelSource` ABC |
| Domain age (WHOIS/RDAP) | New domain = suspicious | Medium | GDPR redaction makes results inconsistent, rate limits make demo flaky |

### Infrastructure extensions

| Extension | Value | Complexity | Notes |
|---|---|---|---|
| Result caching by message_id | Avoid re-analysis on re-open | Low | Currently stateless by design |
| "Report as phishing" UI action | Corpus building, Gmail spam report | Medium | Forward analysis to Gmail's spam reporting |
| Production rate limiting | Replace in-process demo counter | Medium | Distributed rate limiting for real deployment |
| Auto-updating threat lists | Keep brand/TLD/freemail lists current | Medium | Currently static lists |

---

## Current State Summary

```
Tier 0 — Skeleton               ██████████ DONE
Tier 1 — Core Analyzers         ░░░░░░░░░░ NEXT  (AuthenticationAnalyzer, SenderAnalyzer, BodyContentAnalyzer)
Tier 2 — Extended + Polish       ░░░░░░░░░░ TODO  (UrlStructureAnalyzer, AttachmentAnalyzer, tests, demo, deploy)
Tier 3 — Intel Sources           ░░░░░░░░░░ POST-MVP
Tier 4 — Future Extensions       ░░░░░░░░░░ OUT OF SCOPE
```

### Files that exist but need implementation

| File | Status |
|---|---|
| `analyzers/header.py` | Does not exist yet |
| `analyzers/sender.py` | Does not exist yet |
| `analyzers/content.py` | Does not exist yet |
| `analyzers/url_structure.py` | Does not exist yet |
| `analyzers/attachment.py` | Does not exist yet |
| `infrastructure/` | Directory does not exist yet |
| `app/dependencies.py` | Exists, wires empty analyzer list — needs real analyzers |
| `app/config.py` | Exists, has hardcoded HMAC secret — needs env var before deploy |
