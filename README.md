# Malicious Email Scorer — Gmail Add-on

A Gmail Add-on that analyzes an opened email and produces a maliciousness score with an explainable verdict. The system reports what it checked, what it found, what it couldn't check, and why it reached its conclusion.

---

## Overview

Every result includes the analysis scope, specific findings with evidence, and a declaration of blind spots — what the system could not inspect for this particular email and what risks might remain there.

---

## Architecture

```
┌──────────────────────────────┐
│        Gmail Add-on          │
│       (Apps Script)          │
│                              │
│  Extract email data ──────┐ │
│  Render Card UI    ◄────┐ │ │
└─────────────────────────┼─┼─┘
                          │ │
                     POST │ │ JSON
                  /analyze│ │ response
                          │ │
┌─────────────────────────┼─┼─┘
│        Backend (FastAPI) ▼ │
│  ┌───────────────────────┐ │
│  │   Detection Engine    │ │
│  │  ┌─────────────────┐  │ │
│  │  │  Deterministic   │  │ │
│  │  │   analyzers:     │  │ │
│  │  │  Authentication  │  │ │
│  │  │  Sender          │  │ │
│  │  │  URL             │  │ │
│  │  │  Body (HTML form)│  │ │
│  │  │  Attachment      │  │ │
│  │  └─────────────────┘  │ │
│  │  ┌─────────────────┐  │ │
│  │  │ Semantic analyzer│  │ │
│  │  │ Language         │  │ │
│  │  │  assessment      │  │ │
│  │  │  (local SLM,     │  │ │
│  │  │   grounded)      │  │ │
│  │  └─────────────────┘  │ │
│  │  Scoring ─► Verdict   │ │
│  │  Coverage ─► Blind    │ │
│  │              Spots    │ │
│  └───────────────────────┘ │
└────────────────────────────┘
```

| Component | Role | Rationale |
|---|---|---|
| **Gmail Add-on** (Apps Script) | Thin client — extracts email data, calls the backend, renders the verdict card. | Apps Script has a 30-second execution limit, no package ecosystem, and limited debugging. Keeping it thin avoids fighting the platform. |
| **Backend** (Python / FastAPI) | Decision engine — all analysis, scoring, and explanation logic. | Python provides proper libraries, type safety, testability, and independent evolution of detection logic. |

The detection engine (`detection_engine/`) is a pure Python library with zero web framework dependencies. It can be imported from a CLI, a test suite, or a different web framework. The FastAPI layer (`app/`) is a thin HTTP adapter.

---

## Detection Capabilities

The engine splits analyzers along a deliberate seam: **rules where the artifact is structured** (headers, addresses, URLs, attachments, HTML structure), **a constrained semantic extractor where the artifact is language**. Linguistic intent is brittle to keyword rules — paraphrased phishing slips through, while legitimate transactional copy false-positives — so language understanding is isolated into one analyzer with a strict schema and grounded-evidence validation.

### Deterministic analyzers

| Analyzer | Category | Signals |
|---|---|---|
| **Authentication** | Authentication | SPF/DKIM/DMARC failures, plus blind-spot reporting for `none`/`temperror` results |
| **Sender** | Sender identity | Cousin/typosquat domains, Reply-To mismatch, Return-Path mismatch |
| **URL** | URL structure | Anchor/href mismatch, IP-literal hosts (IPv4 / IPv6), dangerous URI schemes (`javascript:`, `data:`, `vbscript:`, `file:`) |
| **Body content** | Body content | HTML `<form>` with input fields in the email body (structural only — language-based body checks are owned by the Language Assessment analyzer below) |
| **Attachment** | Attachment | Dangerous extensions (.exe, .scr, .js, .html), double extensions (.pdf.exe), macro-enabled Office files, password-protected archive hints |

### Semantic analyzer

| Analyzer | Category | Signals |
|---|---|---|
| **Language Assessment** | Body content | One `manipulative_language` signal (LOW–HIGH) derived from a structured assessment of the body: requested action, pressure level, claimed authority, manipulation tactics. Behind an `LlmService` port with two interchangeable providers — a **local** SLM (Ollama, default; email content never leaves the host) and **OpenAI** (Chat Completions; opt-in tradeoff that sends content to a third party). Output is schema-constrained (Pydantic + Ollama `format` for local, `response_format` for OpenAI), and any non-default finding must include a verbatim evidence quote that grounds in the email source; ungrounded responses are rejected as a blind spot. Severity is capped at HIGH so a probabilistic verdict cannot single-handedly drive an email to MALICIOUS — CRITICAL stays reserved for findings provable from the artifact (cousin domain, HTML form, dangerous extension). Off by default (`LANGUAGE_ANALYZER_ENABLED=false`); when disabled or the configured provider is unreachable, a `language_assessment` blind spot is reported instead. |

---

## Limitations

Every analysis result includes a limitations section — runtime-generated declarations of what the system did *not* check for this specific email. These are framed as honest disclosures of scope, not as findings against the message.

| Condition | Limitation | What was not checked |
|---|---|---|
| Email has file attachments | "Attachment content not inspected" | Only attachment metadata (name, size, type) was checked — file contents were not opened or scanned |
| Email has URLs | "URLs found but not followed" | URLs were detected, but destination pages were not fetched or verified |
| Email contains images | "Embedded images not analyzed" | Image contents were not extracted — any text or QR codes inside images were not read |
| Email has an HTML body | "HTML body not rendered" | The message was not rendered as a browser would display it, so CSS- or script-driven content was not evaluated |
| Authentication-Results header absent, or a method returned `none` / `temperror` | "Authentication status unknown" / "<METHOD> returned '<result>'" | SPF, DKIM, and DMARC were not (or could not be) evaluated for this email |
| From address could not be parsed | "Sender identity checks skipped" | Cousin domain, reply-to, and return-path mismatch were not evaluated — a SAFE verdict here should not be read as "the sender looks fine" |
| Language Assessment analyzer disabled, provider unreachable, or response failed schema/grounding validation | "Language assessment unavailable" | Social-engineering language (paraphrased urgency, credential solicitation, authority impersonation, financial lure) was not assessed for this email |
| Always | "Single-email analysis only" | Only this email was analyzed — surrounding thread context was not considered |

This means the result is never just "score: 5, safe" — it includes "…but the PDF attachment was not opened and URL destinations were not fetched," giving the user the scope of the check alongside the verdict.

---

## Scoring

The scoring engine converts signals into a final score and verdict. Constants live in [`backend/detection_engine/scoring.py`](backend/detection_engine/scoring.py); this section explains *why* they're shaped the way they are. See `docs/detection-policy.md` for fully worked examples.

**Severity points** — each signal carries a base weight from its severity, scaled by the analyzer's confidence:

| Severity | Base points | Intent |
|---|---|---|
| INFO | 0 | Appears in report, never affects score |
| LOW | 5 | Supporting signal — needs corroboration |
| MEDIUM | 12 | Notable but not alarming alone |
| HIGH | 25 | Two HIGH signals from different categories cross SUSPICIOUS |
| CRITICAL | 40 | One alone reaches LIKELY_MALICIOUS |

Every point in the final score traces back to a specific finding with verbatim evidence in its summary.

**Within-category attenuation** — each additional signal in the same category is divided by `1.4^k` (first signal: full value, second: ~71%, third: ~51%). Models diminishing returns on correlated evidence — three auth failures (SPF + DKIM + DMARC) on the same spoofed message contribute roughly 2.2× one failure, not 3×.

**Category cap** — each category is capped at 50 points. An email with eight suspicious URL patterns but nothing else wrong won't score as malicious — correlated signals from a single vector are bounded.

**Cross-category boost** — `+15%` per active category beyond the first. Two active categories → ×1.15, three → ×1.30, four → ×1.45. Convergent evidence across orthogonal categories (auth fail + cousin domain + deceptive URL) is more diagnostic than depth in one.

**Infrastructure-only dampener** — when ≥2 active categories are firing, *all* of them are AUTHENTICATION or SENDER_IDENTITY ("infrastructure looks unsettled" signals), and *no* category contributes a CRITICAL-strength score (≥40), the run is multiplied by `×0.78`. This is the false-positive guard for the "SPF softfail + Reply-To mismatch on a small-vendor email" pattern: two HIGH signals across two categories that would otherwise reach LIKELY_MALICIOUS, but with no URL/body/attachment evidence declaring an actual attack. A decisive infrastructure finding (DMARC fail at CRITICAL, cousin domain at CRITICAL) disables the dampener — it's strong enough to justify the verdict on its own.

**Inspection-gap floor** — when zero signals fired but a primary inspection channel was unavailable (today: the `language_assessment` blind spot), the verdict is floored from `safe` to `inconclusive` rather than certified safe on missing coverage. The numeric score stays 0 because there was nothing to score.

### Verdict thresholds

| Score | Verdict |
|---|---|
| 0–14 | `safe` |
| 15–34 | `suspicious` |
| 35–64 | `likely_malicious` |
| 65+ | `malicious` |
| n/a | `inconclusive` (score-independent — emitted when zero signals fired but a primary inspection channel was unavailable) |

Thresholds are calibrated against test cases including both attack patterns and legitimate email (transactional, marketing, internal).

---

## Security

| Concern | Mitigation |
|---|---|
| Untrusted email content | Pydantic models enforce field limits (max lengths, allowed values, attachment size ≤ 25 MiB). HTML is parsed but never rendered or eval'd. |
| URL safety | URLs are parsed and pattern-matched but never followed. No outbound connections to attacker infrastructure. |
| Secrets | Environment variables via `.env` (backend) and `PropertiesService` (Apps Script). |
| Data retention | No email content persisted beyond request lifecycle. Stateless by design. |
| Logging | Analysis metadata only (timing, analyzer names, verdict). Never email content. |
| Backend access | HMAC-signed requests with timestamp replay protection. |
| Request size | Hard cap on the raw request body (default 1 MiB, configurable). Oversized requests are rejected with 413 before HMAC reads the body. |
| API schema visibility | `/docs`, `/redoc`, and `/openapi.json` are unconditionally disabled. The API surface is not published. |
| Rate limiting / DoS | Per-request bounds are enforced in-app (HMAC, timestamp drift, body-size cap, Pydantic field limits). A per-IP fixed-window limiter on `/analyze` (`RATE_LIMIT_PER_WINDOW`/`RATE_LIMIT_WINDOW_SECONDS`, default 60 req / 60 s) bounds compute per client and runs *before* HMAC so blocked clients short-circuit before SHA256 reads the body. The limiter is in-process and per-worker — sufficient for the single-uvicorn-worker demo but not durable: a multi-worker or horizontally scaled deployment needs a shared store (Redis), and volumetric DDoS mitigation still belongs at the edge (Cloudflare, Railway, Fly). `X-Forwarded-For` is intentionally not trusted — without a known proxy, honoring it would let callers spoof their key. |
| Code execution | No `eval`, `exec`, or dynamic execution on any input path. |

---

## Setup

### Prerequisites

- Python 3.11+
- A Google Workspace account (for installing the add-on)
- An HTTPS-reachable backend URL — Apps Script cannot call `http://localhost`. For local development, expose the backend via [ngrok](https://ngrok.com/) or [cloudflared](https://github.com/cloudflare/cloudflared); for a stable demo, deploy to a host of your choice (Railway, Fly, Render, etc.)
- *(optional)* a language-model backend for the Language Assessment analyzer — choose one:
  - [Ollama](https://ollama.com/) running a small model (default: `gemma:2b`) for the **local** provider — email content stays on the host
  - an OpenAI API key for the **openai** provider — sends email subjects and bodies to a third party (opt-in tradeoff)

  Without either, the deterministic analyzers still run on their own and a `language_assessment` blind spot is reported on every email
- *(optional)* [`clasp`](https://github.com/google/clasp) for pushing the add-on from the CLI instead of copy-paste — see `CLAUDE.md` for the workflow

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Configure — set at minimum the HMAC shared secret
cp .env.example .env
# Edit .env: set HMAC_SECRET to a strong random value (the .env.example comment
# shows how to generate one). Use the same value as the Apps Script property.
# Optional knobs documented in .env.example: LOG_LEVEL, MAX_REQUEST_BYTES,
# RATE_LIMIT_PER_WINDOW / RATE_LIMIT_WINDOW_SECONDS (per-IP fixed-window limit
# on /analyze, default 60 req / 60 s), LANGUAGE_PROVIDER (local | openai),
# LLM_HOST / LLM_MODEL / LLM_TIMEOUT (local provider), OPENAI_API_KEY /
# OPENAI_MODEL / OPENAI_TIMEOUT (openai provider), and
# LANGUAGE_ANALYZER_ENABLED (set to "true" once the selected provider is
# reachable to wire in the Language Assessment analyzer).

# Run
uvicorn app.main:app --reload --port 8000
```

Smoke-test the backend in another shell:

```bash
curl http://localhost:8000/healthz
# → {"status":"ok"}
```

The full `/analyze` endpoint requires an HMAC-signed request (see "API Contract" below) — the Gmail Add-on does this for you.

### Gmail Add-on

> Apps Script can only call **HTTPS** URLs. For local backend development, expose `http://localhost:8000` via `ngrok http 8000` (or `cloudflared tunnel --url http://localhost:8000`) and use the resulting `https://...` URL as `BACKEND_URL`. For a stable demo, deploy the backend somewhere with HTTPS termination.

1. Create a new project at [Google Apps Script](https://script.google.com)
2. Add the add-on source — either:
   - **Copy-paste:** copy `Code.gs`, `EmailExtractor.gs`, `BackendClient.gs`, `CardBuilder.gs` from `addon/` into the project
   - **Or via `clasp`:** run `clasp create` in your own clone, then `clasp push` from `addon/`. Note: `addon/.clasp.json` is committed and points to *this* repo's script ID — replace it with your own after `clasp create`
3. Replace `appsscript.json` with the project manifest from `addon/appsscript.json`
4. Set script properties (Project Settings → Script Properties):
   - `BACKEND_URL` — backend's HTTPS URL, no trailing slash. Examples: `https://abcd1234.ngrok.io`, `https://my-app.up.railway.app`
   - `HMAC_SECRET` — shared HMAC secret. **Must match** the `HMAC_SECRET` value in `backend/.env`
5. Deploy as a test add-on (Apps Script editor → Deploy → Test deployments → Install) and authorize for your Gmail account
6. Open any email — the add-on card appears in the right-hand panel

### Tests

```bash
cd backend
source .venv/bin/activate
python -m pytest tests/ -v
```

Tests do not require a configured `.env` — `tests/conftest.py` seeds a stand-in `HMAC_SECRET` before any module imports `app.config`. Only `uvicorn` requires the real value.

---

## API Contract

### `POST /analyze`

**Request:**

```json
{
  "message_id": "phish-001",
  "sender_address": "security@paypa1-support.com",
  "sender_display_name": "",
  "recipient": "victim@example.com",
  "subject": "Your account has been limited - Immediate action required",
  "date": "2026-05-01T10:00:00+00:00",
  "body_text": "Dear Customer, ... verify your identity immediately ...",
  "body_html": "<html><body>...<a href=\"http://192.168.1.100/verify-account\">Click here to verify your account</a>...</body></html>",
  "reply_to_address": "",
  "return_path_address": "bounce-999@cheap-mailer.xyz",
  "headers": [
    { "name": "From", "value": "security@paypa1-support.com" },
    { "name": "Authentication-Results", "value": "mx.example.com; spf=fail smtp.mailfrom=paypa1-support.com; dkim=fail header.d=paypa1-support.com; dmarc=fail header.from=paypa1-support.com" }
  ],
  "attachments": []
}
```

**Response** (deterministic engine output for this input — Language Assessment analyzer disabled). The numbers below are produced by running the request above through the engine; `score_contribution` is post-attenuation and post-cap, before the cross-category boost folds into the final score.

```json
{
  "verdict": "malicious",
  "score": 100.0,
  "explanation": "Verdict: malicious.\n• sender_identity: Sender domain 'paypa1-support.com' resembles brand 'paypal' (critical, +40.0 pts)\n• authentication: DMARC policy returned 'fail' for sender domain (critical, +28.3 pts)\n• url_structure: URL contains IP address: http://192.168.1.100/verify-account (high, +22.5 pts)\nEvidence spans 3 categories. 3 area(s) could not be inspected.",
  "signals": [
    {
      "id": "spf_fail",
      "category": "authentication",
      "severity": "high",
      "summary": "SPF check returned 'fail' for sender domain",
      "confidence": 1.0,
      "score_contribution": 12.64
    },
    {
      "id": "dkim_fail",
      "category": "authentication",
      "severity": "high",
      "summary": "DKIM verification returned 'fail' for sender domain",
      "confidence": 1.0,
      "score_contribution": 9.03
    },
    {
      "id": "dmarc_fail",
      "category": "authentication",
      "severity": "critical",
      "summary": "DMARC policy returned 'fail' for sender domain",
      "confidence": 1.0,
      "score_contribution": 28.32
    },
    {
      "id": "cousin_domain",
      "category": "sender_identity",
      "severity": "critical",
      "summary": "Sender domain 'paypa1-support.com' resembles brand 'paypal'",
      "confidence": 1.0,
      "score_contribution": 40.0
    },
    {
      "id": "return_path_mismatch",
      "category": "sender_identity",
      "severity": "medium",
      "summary": "Return-Path domain (cheap-mailer.xyz) differs from sender domain (paypa1-support.com)",
      "confidence": 0.8,
      "score_contribution": 6.86
    },
    {
      "id": "ip_address_in_url",
      "category": "url_structure",
      "severity": "high",
      "summary": "URL contains IP address: http://192.168.1.100/verify-account",
      "confidence": 0.9,
      "score_contribution": 22.5
    }
  ],
  "top_signals": [ "...same structure as signals, top 3 by score_contribution: cousin_domain, dmarc_fail, ip_address_in_url..." ],
  "active_categories": ["authentication", "sender_identity", "url_structure"],
  "blind_spots": [
    {
      "area": "thread_history",
      "reason": "Single-email analysis only",
      "risk_note": "Only this email was analyzed — surrounding thread context was not considered."
    },
    {
      "area": "html_rendering",
      "reason": "HTML body not rendered — text extracted from raw markup",
      "risk_note": "The message was not rendered as a browser would display it, so CSS- or script-driven content was not evaluated."
    },
    {
      "area": "url_destination",
      "reason": "URLs found but not followed — cannot verify destination content",
      "risk_note": "URLs were detected, but destination pages were not fetched or verified."
    }
  ],
  "scope": {
    "analyzers_run": ["authentication_analyzer", "sender_analyzer", "body_content_analyzer", "url_structure_analyzer", "attachment_analyzer"],
    "has_html": true,
    "has_attachments": false,
    "has_auth_headers": true
  }
}
```

---

## Out of Scope

| Attack Vector | Reason |
|---|---|
| Conversation hijacking | Requires thread history; single-email analysis only |
| Multi-stage attacks | First email is typically clean; requires session state |
| Delayed detonation URLs | Safe at scan time, weaponized later; needs re-scanning infrastructure |
| Zero-day attachment exploits | Requires sandbox execution |
| Compromised legitimate accounts | Authentication passes; requires behavioral analysis over time |
| QR code / image-only phishing | Requires OCR/vision capabilities |
| Obfuscated HTML (CSS-hidden text, base64 sections, data: URI inlining) | Requires HTML rendering or deep heuristics; deliberately deferred to keep deterministic analyzers explainable. See `docs/detection-policy.md` "Deferred Indicators" |

---

## Trade-offs

**Rules for structure, one constrained extractor for language** — header, address, URL, attachment, and HTML-structure findings are deterministic rules with verbatim evidence. Language understanding is isolated into a single SLM-backed analyzer with a closed-set schema, grounded evidence quotes, and a HIGH severity ceiling, so a probabilistic verdict can amplify but never solely drive a MALICIOUS verdict. Splitting along this seam keeps the system explainable where rules suffice and resilient to paraphrase where they don't.

**Local SLM by default, OpenAI as opt-in alternative** — the language analyzer talks to an `LlmService` port; the default provider is a local Ollama-served SLM, so attacker-controlled email content never leaves the host. An OpenAI provider exists as a drop-in alternative for environments without a local model, but enabling it sends subjects and bodies to a third party — that tradeoff is opt-in, never the default. Both providers share the same prompt-injection defenses (per-request random delimiter, Unicode hygiene, schema-strict parsing, evidence grounding) and the same blind-spot fallback when the backend is unreachable. Grammar-constrained decoding (`format` for Ollama, `response_format` for OpenAI) keeps outputs inside the closed-set schema. Neither provider pins `temperature` — newer reasoning-class OpenAI models reject non-default values, so the two stay symmetric on this point.

**Static analysis over dynamic** — URLs are pattern-matched but never fetched. Cannot detect redirect chains or cloaked pages, but eliminates SSRF and data exfiltration risks from outbound connections to attacker infrastructure.

**Single-email over contextual** — each email is analyzed in isolation. Cannot detect behavioral anomalies or thread-based attacks, but requires no database, no user profiles, and raises no privacy concerns from stored history.

**Conservative over aggressive** — tuned to keep legitimate transactional and marketing emails below the suspicious threshold. A missed phishing email is costly, but an inbox of false alarms trains users to ignore the tool.

---

## Future Improvements

- **External threat intelligence** — wire in network-backed lookups (Google Safe Browsing for URL reputation, WHOIS/RDAP for domain age, VirusTotal/AbuseIPDB for hash reputation). Out of scope for this build to keep the system static, deterministic, and free of third-party dependencies, but a natural next layer once those tradeoffs are acceptable.
- **Image analysis** — OCR for QR code phishing and image-only emails
- **Thread awareness** — conversation context for detecting hijacking and BEC patterns
- **Feedback loop** — user reporting of false positives/negatives for threshold tuning
- **Caching** — memoize results by message ID for repeated opens
- **Distributed rate limiting** — replace the in-process per-IP fixed-window limiter with a shared-store implementation (Redis) that survives multiple workers and instances, and front the API with edge throttling at the platform layer (Cloudflare, Railway, Fly) for volumetric DDoS coverage.
