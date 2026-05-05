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
| **Detection engine** | `detection_engine/engine.py`, `scoring.py` | Orchestrator (runs analyzers → scoring → verdict), scoring algorithm (severity points, attenuation, category cap, cross-category boost) |
| **Domain model** | `detection_engine/domain/` — `email.py`, `enums.py`, `signals.py`, `verdict.py`, `exceptions.py` | Frozen dataclasses: `EmailData`, `EmailHeaders` (case-insensitive, multi-value), `Signal`, `BlindSpot`, `AnalysisOutput`, `AnalysisResult`, `AnalysisScope`. Exception: `AnalyzerCrashed` |
| **ABC** | `analyzers/base.py` | `BaseAnalyzer` (pure, offline, deterministic) |
| **Test suite** | `tests/email_fixtures.py`, `tests/test_tier1_detection.py`, per-analyzer unit + integration tests | ~40 email fixtures with scoring contracts across phishing, BEC, malware, scams, evasion, and legitimate scenarios |

### Key design decisions locked in

- `detection_engine/` has zero framework dependencies — importable standalone
- Deterministic analyzers never make network calls. The Language Assessment analyzer is the single networked seam, and routes through an injected `LlmService` port whose providers live in `infrastructure/llm/`.
- Analyzer crashes raise `AnalyzerCrashed` (fail-fast); LLM-backed analysis degrades to a `LANGUAGE_ASSESSMENT` blind spot rather than crashing
- `EmailHeaders` constructed from `Sequence[tuple[str, str]]`, never `dict` (preserves repeated headers)
- Scoring: `Signal` is immutable; `score_signals()` returns a `ScoringReport` with per-run `ScoredSignal(signal, contribution)` pairs

---

## Tier 1 — Core deterministic analyzers **[DONE]**

Three analyzers covering the highest-value, lowest-FP-risk deterministic indicators.

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
| **Signals** | SENDER-1 (cousin/lookalike domain → CRITICAL), SENDER-3 (From ≠ Reply-To → HIGH), SENDER-4 (Return-Path ≠ From domain → MEDIUM) |
| **Notes** | Cousin domain: curated brand list, length-scaled Levenshtein budget, visual-substitution normalization (1↔l, 0↔o, 5↔s, rn↔m, vv↔w, cl↔d), trusted-public-suffix allowlist for legitimate regional brand mail. SENDER-3/4 suppress same-org pairs, known ESPs, and freemail→freemail reply-to. Display-name impersonation was prototyped (SENDER-5) and removed — see "Deferred Indicators" in `docs/detection-policy.md`. |

### 3. BodyContentAnalyzer (structural)

| | |
|---|---|
| **File** | `detection_engine/analyzers/body_content.py` |
| **Category** | BODY_CONTENT |
| **Signals** | CONTENT-3 (HTML `<form>` with input fields → CRITICAL) |
| **Notes** | Structural-only since the move to "deterministic rules + one semantic extractor." Linguistic body checks (urgency, sensitive-data request) moved to the LanguageAssessmentAnalyzer (Tier 3) — keyword lists were brittle (over-flagged transactional copy, missed paraphrases) and double-counted with the language analyzer. |

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

## Tier 3 — Language Assessment analyzer **[DONE — opt-in]**

The semantic half of the engine. Off by default (`LANGUAGE_ANALYZER_ENABLED=false`); when off or the configured language model is unreachable, a `language_assessment` blind spot is emitted instead of silent under-coverage.

### LanguageAssessmentAnalyzer

| | |
|---|---|
| **Analyzer** | `detection_engine/analyzers/language_assessment.py` |
| **Schema** | `detection_engine/domain/language_assessment.py` (Pydantic, closed-set enums) |
| **LLM port** | `LlmService` Protocol; concrete providers under `infrastructure/llm/` (default: `LocalSlm` via Ollama; alternative: `OpenAiLlm`). Selected by `LANGUAGE_PROVIDER`. |
| **Category** | BODY_CONTENT |
| **Signals** | LANG-1 `manipulative_language` (LOW–HIGH, capped at HIGH) |
| **Blind spot** | `LANGUAGE_ASSESSMENT` when the analyzer is disabled, the configured provider is unreachable, or its response fails schema or evidence-grounding validation |
| **Defenses** | Closed-set Pydantic schema, structured-output / grammar-constrained decoding (Ollama `format` for the SLM, `response_format` for the OpenAI LLM), per-request random delimiter, Unicode Cc/Cf hygiene, evidence-quote grounding against the (sanitized) source text — non-default findings without grounded quotes are rejected. `temperature` is not pinned: newer OpenAI models reject non-default values, so providers stay symmetric on this point |

**Why HIGH ceiling**: Any language model — SLM or LLM — is probabilistic. Capping the analyzer's contribution at HIGH means it can amplify a verdict already supported by deterministic findings but cannot single-handedly drive an otherwise-clean email past LIKELY_MALICIOUS. CRITICAL stays reserved for findings provable from the artifact (cousin domain, HTML form, dangerous extension).

### Blind spots emitted today

`ATTACHMENT_CONTENT`, `URL_DESTINATION`, `AUTHENTICATION_HEADERS`, `SENDER_IDENTITY` (unparseable From), `THREAD_HISTORY`, `EMBEDDED_IMAGE`, `HTML_RENDERING`, `LANGUAGE_ASSESSMENT`. `QR_CODE` is defined in the enum and reserved for future image-content analysis.

---

## Tier 4 — Future Extensions **[OUT OF SCOPE]**

Documented for interview discussion ("what would you add next?").

### Detection extensions

| Extension | Value | Complexity | Notes |
|---|---|---|---|
| OCR for image-only phishing | QR codes, image text | High | Requires Tesseract or vision API |
| Thread awareness | Conversation hijacking, BEC | High | Breaks single-email temporal boundary |
| AuthorityAlignmentAnalyzer | Cross-check `claimed_authority` (from LanguageAssessment) against sender domain / DKIM / link domains | Medium | The schema already records `claimed_authority`; this analyzer wires it into a deterministic cross-correlation rule |
| Multi-language content patterns | Non-English manipulation detection | Medium | The Language Assessment SLM already handles many languages; targeted phrase coverage is a cheaper backstop |

### External threat intelligence

Out of scope for this build to keep the system static, deterministic, and free of third-party dependencies. The natural shape if added later is a small `ThreatIntelSource` port mirroring the `LlmService` port that `LanguageAssessmentAnalyzer` already uses — concrete clients live behind it in `infrastructure/threat_intel/`, and unavailability degrades to a blind spot rather than a crash.

| Extension | Value | Complexity | Notes |
|---|---|---|---|
| Google Safe Browsing | URL reputation against Google's blocklist | Low | The first source we'd wire in |
| VirusTotal / PhishTank | URL and file-hash reputation | Low | Slot into the same port |
| Domain age (WHOIS / RDAP) | New domain = suspicious | Medium | GDPR redaction makes results inconsistent, rate limits make demo flaky |

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
Tier 0 — Skeleton                 ██████████ DONE
Tier 1 — Core deterministic        ██████████ DONE  (AuthenticationAnalyzer, SenderAnalyzer, BodyContentAnalyzer)
Tier 2 — Extended deterministic    ██████████ DONE  (UrlStructureAnalyzer, AttachmentAnalyzer, tests, Card UI)
Tier 3 — Language Assessment       ██████████ DONE  (opt-in via LANGUAGE_ANALYZER_ENABLED)
Tier 4 — Future Extensions         ░░░░░░░░░░ OUT OF SCOPE
```

### What's next

| Item | Status |
|---|---|
| `infrastructure/llm/` | Built. Two providers behind `LlmService`: `LocalSlm` (Ollama, default) and `OpenAiLlm` (gpt-4o-mini class). Shared prompt-injection defenses live in `_prompt.py`. |
| External threat intelligence | Out of scope for this build — see Tier 4 / "External threat intelligence" for the planned shape. |
| Deploy backend | Railway deployment not yet done. The local provider needs Ollama on the host; the OpenAI provider works anywhere with a key, at the cost of sending content to a third-party API. |
| Demo emails | Need to send to test Gmail account before interview. |
