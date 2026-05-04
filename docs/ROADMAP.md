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
| **Detection engine** | `detection_engine/engine.py`, `scoring.py` | Orchestrator (runs analyzers → intel sources → scoring → verdict), scoring algorithm (severity points, attenuation, category cap, cross-category boost) |
| **Domain model** | `detection_engine/domain/` — `email.py`, `enums.py`, `signals.py`, `verdict.py`, `exceptions.py` | Frozen dataclasses: `EmailData`, `EmailHeaders` (case-insensitive, multi-value), `Signal`, `BlindSpot`, `AnalysisOutput`, `AnalysisResult`, `AnalysisScope`. Exception: `AnalyzerCrashed` |
| **ABCs** | `analyzers/base.py`, `intel_sources/base.py` | `BaseAnalyzer` (pure, offline, deterministic) and `ThreatIntelSource` (network-capable, timeout-required) |
| **Test suite** | `tests/email_fixtures.py`, `tests/test_tier1_detection.py`, per-analyzer unit + integration tests | ~40 email fixtures with scoring contracts across phishing, BEC, malware, scams, evasion, and legitimate scenarios |

### Key design decisions locked in

- `detection_engine/` has zero framework dependencies — importable standalone
- Analyzers never make network calls; intel sources are the only network channel
- Analyzer crashes raise `AnalyzerCrashed` (fail-fast); intel source crashes degrade into blind spots
- `EmailHeaders` constructed from `Sequence[tuple[str, str]]`, never `dict` (preserves repeated headers)
- Scoring: `Signal` is immutable; `score_signals()` returns a `ScoringReport` with per-run `ScoredSignal(signal, contribution)` pairs

---

## Tier 1 — Core Analyzers **[DONE]**

Three analyzers covering the highest-value, lowest-FP-risk indicators.

### 1. AuthenticationAnalyzer

| | |
|---|---|
| **File** | `detection_engine/analyzers/authentication.py` |
| **Category** | AUTHENTICATION |
| **Signals** | AUTH-1 (SPF fail/none → HIGH), AUTH-2 (DKIM fail/none → HIGH), AUTH-3 (DMARC fail/none → CRITICAL) |
| **Input** | `Authentication-Results` header via `email.headers.get()` |
| **Blind spot** | `AUTHENTICATION_HEADERS` when header is absent |

### 2. SenderAnalyzer

| | |
|---|---|
| **File** | `detection_engine/analyzers/sender.py` |
| **Category** | SENDER_IDENTITY |
| **Signals** | SENDER-1 (cousin/lookalike domain → CRITICAL), SENDER-2 (freemail with org name → MEDIUM), SENDER-3 (From ≠ Reply-To → HIGH), SENDER-4 (Return-Path ≠ From domain → MEDIUM), SENDER-5 (display-name impersonation → HIGH) |
| **Notes** | Cousin domain: curated brand list, length-scaled Levenshtein budget, visual-substitution normalization (1↔l, 0↔o, 5↔s, rn↔m, vv↔w, cl↔d), trusted-public-suffix allowlist for legitimate regional brand mail. SENDER-3/4 suppress same-org pairs, known ESPs, and freemail→freemail reply-to. SENDER-5 defers to SENDER-1 to avoid double-counting one impersonation, and uses an "any claimed brand matches the domain" rule so multi-token names don't false-positive. |

### 3. BodyContentAnalyzer

| | |
|---|---|
| **File** | `detection_engine/analyzers/body_content.py` |
| **Category** | BODY_CONTENT |
| **Signals** | CONTENT-1 (urgency/threat language → MEDIUM), CONTENT-2 (sensitive data request → HIGH), CONTENT-3 (HTML form in body → CRITICAL) |
| **Notes** | CONTENT-1 uses 38 specific urgency phrases. Confidence scales with match count. |

---

## Tier 2 — Extended Analyzers + Polish **[DONE]**

URL and attachment analysis. Full test suite. All 5 analyzers wired.

### 4. UrlStructureAnalyzer

| | |
|---|---|
| **File** | `detection_engine/analyzers/url_structure.py` |
| **Category** | URL_STRUCTURE |
| **Signals** | URL-1 (href ≠ display text → CRITICAL), URL-2 (IP in URL → HIGH) |
| **Blind spot** | `URL_DESTINATION` whenever URLs are found in the email |
| **Notes** | URL-1 only flags when display text looks like a URL (contains a dot, no spaces). Reports first 3 mismatches. Shortened-URL detection and link-volume heuristics are intentionally out of scope — see `docs/detection-policy.md` "Deferred Indicators". |

### 5. AttachmentAnalyzer

| | |
|---|---|
| **File** | `detection_engine/analyzers/attachment.py` |
| **Category** | ATTACHMENT |
| **Signals** | ATTACH-1 (dangerous extension → CRITICAL), ATTACH-2 (double extension → CRITICAL), ATTACH-3 (macro-enabled Office → HIGH), ATTACH-4 (password-protected archive + body hint → HIGH) |
| **Blind spot** | `ATTACHMENT_CONTENT` whenever attachments are present (metadata-only inspection) |

### Wiring and tests

- All 5 analyzers wired in `dependencies.py`
- `config.py` reads `HMAC_SECRET` from environment
- ~40 email fixtures across 9 test files, ~120 test functions
- Card UI implemented with verdict colors, findings, blind spots, scope, re-analyze button

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

### Blind spots expansion

Currently emitted: `ATTACHMENT_CONTENT`, `URL_DESTINATION`, `AUTHENTICATION_HEADERS`, `THREAD_HISTORY`, `EMBEDDED_IMAGE`, `QR_CODE` (engine emits the last two when the email contains images). Not yet emitted: `HTML_RENDERING` — defined in the enum but not reported when the email has an HTML body.

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
| Stronger `/analyze` auth (session-bound, not just shared HMAC secret) | Anyone with the secret can call the endpoint today | Medium | Options: short-lived tokens issued per add-on session, HMAC tied to a per-user nonce from the Apps Script event object, or OAuth2 service-account auth instead of symmetric HMAC. Acceptable for demo (the secret is never exposed to a browser), not for production |

---

## Current State Summary

```
Tier 0 — Skeleton               ██████████ DONE
Tier 1 — Core Analyzers         ██████████ DONE  (AuthenticationAnalyzer, SenderAnalyzer, BodyContentAnalyzer)
Tier 2 — Extended + Polish       ██████████ DONE  (UrlStructureAnalyzer, AttachmentAnalyzer, tests, Card UI)
Tier 3 — Intel Sources           ░░░░░░░░░░ POST-MVP
Tier 4 — Future Extensions       ░░░░░░░░░░ OUT OF SCOPE
```

### What's next

| Item | Status |
|---|---|
| `infrastructure/` | Directory does not exist — needed for Safe Browsing intel source |
| Blind spot gaps | `EMBEDDED_IMAGE` and `QR_CODE` are emitted by the structural catalog when an email contains images. `HTML_RENDERING` is defined in the enum but not yet emitted on HTML-bodied mail. |
| Deploy backend | Railway deployment not yet done |
| Demo emails | Need to send to test Gmail account before interview |
