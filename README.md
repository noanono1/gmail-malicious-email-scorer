# Malicious Email Scorer — Gmail Add-on

A Gmail Add-on that analyzes an opened email and produces a maliciousness score with an explainable verdict. The system reports what it checked, what it found, what it couldn't check, and why it reached its conclusion.

<!-- TODO: Add screenshot of the add-on card UI here -->

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
│  │  │    Analyzers     │  │ │
│  │  │ Authentication   │  │ │
│  │  │ Sender           │  │ │
│  │  │ URL              │  │ │
│  │  │ Content          │  │ │
│  │  │ Attachment       │  │ │
│  │  └─────────────────┘  │ │
│  │  ┌─────────────────┐  │ │
│  │  │  Intel Sources   │  │ │
│  │  │  (planned)       │  │ │
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
| **Backend** (Python / FastAPI) | Decision engine — all analysis, scoring, threat intelligence, and explanation logic. | Python provides proper libraries, type safety, testability, and independent evolution of detection logic. |

The detection engine (`detection_engine/`) is a pure Python library with zero web framework dependencies. It can be imported from a CLI, a test suite, or a different web framework. The FastAPI layer (`app/`) is a thin HTTP adapter.

---

## Detection Capabilities

### Analyzers

| Analyzer | Category | Signals |
|---|---|---|
| **Authentication** | Authentication | SPF/DKIM/DMARC failures, plus blind-spot reporting for `none`/`temperror` results |
| **Sender** | Sender identity | Cousin/typosquat domains, display-name impersonation, Reply-To mismatch, Return-Path mismatch |
| **URL** | URL structure | Anchor/href mismatch, IP-literal hosts (IPv4 / IPv6) |
| **Body content** | Body content | Urgency/pressure language, sensitive data requests, HTML forms with input fields |
| **Attachment** | Attachment | Dangerous extensions (.exe, .scr, .js, .html), double extensions (.pdf.exe), macro-enabled Office files, password-protected archive hints |

### Intel Sources

No external intel sources are wired in the current build. The architecture supports them via the `ThreatIntelSource` ABC — Google Safe Browsing is the planned first integration. When an intel source is unavailable, the engine reports a blind spot instead of failing.

---

## Blind Spots

Every analysis result includes a blind spots section — runtime-generated declarations of what could not be inspected for this specific email and what risk that creates.

| Condition | Blind Spot | Risk |
|---|---|---|
| Email has file attachments | "Attachment content not inspected" | Malicious payloads inside files are not detected; only metadata is analyzed |
| Email has URLs | "URLs found but not followed" | A clean-looking domain could redirect to a phishing page |
| Email contains images | "Embedded images not analyzed" | Images may contain text, QR codes, or visual phishing undetectable by text analysis |
| Authentication-Results header absent | "Authentication status unknown" | SPF, DKIM, and DMARC could not be evaluated |
| Always | "Single-email analysis only" | Thread context may reveal social engineering patterns |

This means the result is never just "score: 5, safe" — it includes "...but I couldn't inspect the PDF attachment or verify URL destinations," giving the user context for their own judgment.

---

## Scoring

The scoring engine converts signals into a final score and verdict.

**Signal scoring** — each signal has a base severity weight. Every point in the final score traces back to a specific finding with evidence.

**Category caps** — each category is capped at 50 points. An email with 8 suspicious URL patterns but nothing else wrong won't score as "malicious" — correlated signals from a single vector are bounded.

**Within-category attenuation** — each additional signal within a category is attenuated by a factor of 1.6 (first signal: full value, second: ~63%, third: ~39%). Redundant signals produce diminishing returns.

**Cross-category amplification** — the final score receives a 1.08x multiplier for each additional active category beyond the first. Convergent evidence across multiple categories is a stronger indicator than depth in one.

### Verdict Thresholds

| Score | Verdict |
|---|---|
| 0–14 | `safe` |
| 15–34 | `suspicious` |
| 35–64 | `likely_malicious` |
| 65+ | `malicious` |

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
| Rate limiting / DoS | Per-request bounds are enforced in-app (HMAC, timestamp drift, body-size cap, Pydantic field limits). Volumetric protection — rate limiting and DDoS mitigation — is deferred to the edge/platform layer (Cloudflare, Railway, Fly). An in-app per-IP limiter is deliberately not implemented: Apps Script traffic shares Google's IP ranges, the HMAC secret is shared (no per-user identity), and an in-process counter would not survive multiple workers or instances. |
| Code execution | No `eval`, `exec`, or dynamic execution on any input path. |

---

## Setup

### Prerequisites

- Python 3.11+
- A Google Workspace account (for installing the add-on)
- An HTTPS-reachable backend URL — Apps Script cannot call `http://localhost`. For local development, expose the backend via [ngrok](https://ngrok.com/) or [cloudflared](https://github.com/cloudflare/cloudflared); for a stable demo, deploy to a host of your choice (Railway, Fly, Render, etc.)
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
# Optional knobs documented in .env.example: LOG_LEVEL, MAX_REQUEST_BYTES.

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

**Response** (actual output from the engine for this input):

```json
{
  "verdict": "malicious",
  "score": 100.0,
  "explanation": "Verdict: malicious.\n• sender_identity: Sender domain 'paypa1-support.com' resembles brand 'paypal' (critical, +35.0 pts)\n• authentication: DMARC policy returned 'fail' for sender domain (critical, +30.5 pts)\n• url_structure: URL contains IP address: http://192.168.1.100/verify-account (high, +19.8 pts)\nEvidence spans 4 categories. 2 area(s) could not be inspected.",
  "signals": [
    {
      "id": "dmarc_fail",
      "category": "authentication",
      "severity": "critical",
      "summary": "DMARC policy returned 'fail' for sender domain",
      "confidence": 1.0,
      "score_contribution": 30.5
    },
    {
      "id": "cousin_domain",
      "category": "sender_identity",
      "severity": "critical",
      "summary": "Sender domain 'paypa1-support.com' resembles brand 'paypal'",
      "confidence": 1.0,
      "score_contribution": 35.0
    },
    {
      "id": "ip_address_in_url",
      "category": "url_structure",
      "severity": "high",
      "summary": "URL contains IP address: http://192.168.1.100/verify-account",
      "confidence": 0.9,
      "score_contribution": 19.8
    },
    {
      "id": "sensitive_data_request",
      "category": "body_content",
      "severity": "high",
      "summary": "Sensitive data request detected: 'verify your identity'",
      "confidence": 0.8,
      "score_contribution": 17.6
    }
  ],
  "top_signals": [ "...same structure as signals, top 3 by score_contribution..." ],
  "active_categories": ["authentication", "sender_identity", "url_structure", "body_content"],
  "blind_spots": [
    {
      "area": "thread_history",
      "reason": "Single-email analysis only",
      "risk_note": "Thread context may reveal social engineering patterns"
    },
    {
      "area": "url_destination",
      "reason": "URLs found but not followed",
      "risk_note": "A clean-looking domain could redirect to a phishing page"
    }
  ],
  "scope": {
    "analyzers_run": ["authentication_analyzer", "sender_analyzer", "body_content_analyzer", "url_structure_analyzer", "attachment_analyzer"],
    "intel_sources_run": [],
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
| Obfuscated HTML (CSS-hidden text, base64 sections, data: URI inlining) | Requires HTML rendering or deep heuristics; deliberately deferred to keep static analyzers explainable. See `docs/detection-policy.md` "Deferred Indicators" |

---

## Trade-offs

**Rule-based over ML** — every decision is explainable and debuggable, but the system cannot generalize to novel attack patterns it hasn't been programmed to recognize.

**Static analysis over dynamic** — URLs are pattern-matched but never fetched. Cannot detect redirect chains or cloaked pages, but eliminates SSRF and data exfiltration risks from outbound connections to attacker infrastructure.

**Single-email over contextual** — each email is analyzed in isolation. Cannot detect behavioral anomalies or thread-based attacks, but requires no database, no user profiles, and raises no privacy concerns from stored history.

**Conservative over aggressive** — tuned to keep legitimate transactional and marketing emails below the suspicious threshold. A missed phishing email is costly, but an inbox of false alarms trains users to ignore the tool.

---

## Future Improvements

- **Intel source expansion** — domain age (WHOIS), threat intelligence feeds (VirusTotal, AbuseIPDB), certificate transparency logs
- **Image analysis** — OCR for QR code phishing and image-only emails
- **Thread awareness** — conversation context for detecting hijacking and BEC patterns
- **Feedback loop** — user reporting of false positives/negatives for threshold tuning
- **Caching** — memoize results by message ID for repeated opens
- **Edge rate limiting** — per-IP / per-account throttling at the platform layer (Cloudflare, Railway, Fly). In-app rate limiting was deliberately deferred — see the Security section for why per-IP counters don't fit this architecture.
