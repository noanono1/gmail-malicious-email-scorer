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
│  │  │ Header │ Sender  │  │ │
│  │  │ URL    │ Content │  │ │
│  │  │ Attachment       │  │ │
│  │  └─────────────────┘  │ │
│  │  ┌─────────────────┐  │ │
│  │  │   Intel Sources   │  │ │
│  │  │ Safe Browsing   │  │ │
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
| **Header** | Authentication | SPF/DKIM/DMARC failures, From/Reply-To mismatch, missing Message-ID, suspicious Received chains |
| **Sender** | Identity | Freemail from "corporate" senders, cousin/typosquat domains, display-name spoofing, suspicious TLDs |
| **URL** | URL structure | IP-based URLs, anchor/href mismatch, URL shortener use, excessive link count |
| **Content** | Language | Urgency/pressure language, credential harvesting phrases, financial manipulation, threat language |
| **Attachment** | Files | Dangerous extensions (.exe, .scr, .js), double extensions (.pdf.exe), macro-enabled Office files, password-protected archive hints |

### Intel Sources

| Provider | Purpose | Fallback |
|---|---|---|
| **Google Safe Browsing** | URL reputation from Google's threat database | Analysis proceeds without it; a blind spot is reported |

Intel Sources are injected dependencies. When unavailable, the engine degrades gracefully and the blind spots section reflects what was missed.

---

## Blind Spots

Every analysis result includes a blind spots section — runtime-generated declarations of what could not be inspected for this specific email and what risk that creates.

| Condition | Blind Spot | Risk |
|---|---|---|
| Email has file attachments | "Attachment content not inspected" | Malicious payloads inside files are not detected; only metadata is analyzed |
| Body contains `<img>` tags | "Embedded images not analyzed" | Image-based phishing and tracking pixels are not detected |
| No Safe Browsing API key | "Safe Browsing not queried" | Known malicious URLs will not be flagged — only structural patterns are checked |
| Email has HTML body | "HTML rendering behavior not simulated" | CSS/JS-based content hiding or redirects are not detected |

This means the result is never just "score: 5, safe" — it includes "...but I couldn't inspect the PDF attachment or query Safe Browsing," giving the user context for their own judgment.

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
| Untrusted email content | Pydantic models enforce field limits (max lengths, allowed values). HTML is parsed but never rendered or eval'd. |
| URL safety | URLs are parsed and pattern-matched but never followed. No outbound connections to attacker infrastructure. |
| Secrets | Environment variables (backend) and `PropertiesService` (Apps Script). Nothing hardcoded. |
| Data retention | No email content persisted beyond request lifecycle. Stateless by design. |
| Logging | Analysis metadata only (timing, analyzer names, verdict). Never email content. |
| Backend access | Authenticated endpoint with rate limiting. |
| Code execution | No `eval`, `exec`, or dynamic execution on any input path. |

---

## Setup

### Prerequisites

- Python 3.11+
- A Google Workspace account
- (Optional) Google Safe Browsing API key

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env with your API keys

# Run
uvicorn app.main:app --reload --port 8000
```

### Gmail Add-on

1. Create a new project at [Google Apps Script](https://script.google.com)
2. Copy all `.gs` files from `addon/` (`Code.gs`, `EmailExtractor.gs`, `BackendClient.gs`, `CardBuilder.gs`) into the project
3. Replace `appsscript.json` with the project manifest from `addon/appsscript.json`
4. Set script properties (Project Settings):
   - `BACKEND_URL` — backend's public URL
   - `HMAC_SECRET` — shared HMAC secret (same value as backend env var)
5. Deploy as a test add-on and authorize for your Gmail account

### Tests

```bash
cd backend
source .venv/bin/activate
python -m pytest tests/ -v
```

---

## API Contract

### `POST /analyze`

**Request:**

```json
{
  "message_id": "18a1b2c3d4e5f6g7",
  "sender": "support@paypa1.com",
  "recipient": "victim@company.com",
  "subject": "Your account has been limited - Immediate action required",
  "date": "2026-04-28T14:30:00Z",
  "body_text": "Dear customer, your account access has been limited...",
  "body_html": "<html><body><a href='http://192.168.1.1/login'>Click here to verify</a></body></html>",
  "headers": {
    "from": "support@paypa1.com",
    "reply-to": "different-address@freemail.com",
    "authentication-results": "mx.google.com; spf=fail smtp.mailfrom=paypa1.com; dkim=fail; dmarc=fail",
    "received": "from suspicious-server.example.com (10.0.0.1) by mx.google.com"
  },
  "attachments": [
    {
      "filename": "invoice.pdf.exe",
      "mime_type": "application/x-msdownload",
      "size_bytes": 245760,
      "sha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    }
  ]
}
```

**Response:**

```json
{
  "score": 87.3,
  "verdict": "malicious",
  "scope": {
    "analyzers_run": ["header_analyzer", "sender_analyzer", "url_analyzer", "content_analyzer", "attachment_analyzer"],
    "intel_sources_run": ["safe_browsing"],
    "has_html": true,
    "has_attachments": true,
    "has_auth_headers": true
  },
  "signals": [
    {
      "id": "spf_fail",
      "category": "authentication",
      "severity": "high",
      "confidence": 0.95,
      "score_contribution": 20.9,
      "evidence": "SPF check returned 'fail' for sender domain paypa1.com"
    },
    {
      "id": "cousin_domain",
      "category": "sender_identity",
      "severity": "high",
      "confidence": 0.9,
      "score_contribution": 18.5,
      "evidence": "Domain 'paypa1.com' is 1 edit distance from known brand 'paypal.com'"
    }
  ],
  "top_signals": ["...same structure, top 3 by score_contribution..."],
  "categories_active": ["authentication", "sender_identity", "url_structure", "content", "attachment"],
  "blind_spots": [
    {
      "area": "attachment_content",
      "reason": "Attachment binary content not parsed",
      "risk_note": "Malicious payloads inside 'invoice.pdf.exe' are not detected; only metadata was analyzed"
    }
  ],
  "explanation": "Strong convergent evidence across 5 categories. Authentication fails for the sender domain, which is a typosquat of PayPal. The email contains an IP-based URL with anchor text mismatch, urgency language typical of credential harvesting, and an attachment with a dangerous double extension."
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
