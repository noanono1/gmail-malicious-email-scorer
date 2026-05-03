# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run

```bash
# Backend setup (from repo root)
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run server
uvicorn app.main:app --reload --port 8000

# Run all tests
python -m pytest tests/ -v

# Run a single test class or method
python -m pytest tests/test_tier1_detection.py::TestMassPhishing -v
python -m pytest tests/test_tier1_detection.py::TestMassPhishing::test_score_range -v
```

All `python`/`pytest`/`uvicorn` commands must run from `backend/` with the venv active.

## Apps Script Deployment

The `addon/` directory contains the Google Apps Script code. This is synced to Google cloud using `clasp`.

When you modify, add, or delete any files in the `addon/` directory (like `.gs` or `.html` files), you **must** deploy your changes using `clasp` so they take effect.

```bash
# Push changes to Google Apps Script (must run from addon/ directory)
cd addon
clasp push

# Or use watch mode — auto-pushes on every file save
clasp push --watch
```

**Rule for AI:** Never assume Apps Script changes are live just because you wrote them to the local file system. You must explicitly run `cd addon && clasp push` after completing modifications to the add-on code.

## Architecture

Two-tier system: a **Gmail Add-on** (Apps Script) that extracts email data and renders a Card UI, and a **Python backend** (FastAPI) that scores emails for maliciousness.

```
Gmail Add-on (addon/)          Backend (backend/)
┌──────────────────┐    POST   ┌──────────────────────────────┐
│ Extract email    │──/analyze─▶│ FastAPI adapter (app/)       │
│ HMAC-sign request│  (HMAC)   │   ↓                          │
│ Render Card UI   │◀──JSON────│ DetectionEngine (pure lib)   │
└──────────────────┘           │   analyzers[] → signals      │
                               │   intel_sources[] → signals  │
                               │   scoring → verdict 0-100    │
                               └──────────────────────────────┘
```

**Key separation**: `backend/detection_engine/` is a pure Python library with zero web-framework deps. FastAPI is just an HTTP adapter around it. The engine can be imported and used standalone.

### Backend layers

- **`app/`** — FastAPI adapter: routes, HMAC auth, Pydantic schemas, DI wiring, structured logging
- **`detection_engine/`** — Pure detection library:
  - **`engine.py`** — Orchestrator: runs analyzers → intel sources → scoring → verdict. Analyzer crashes fail the analysis (raises `AnalyzerCrashed`); intel source crashes degrade gracefully into blind spots.
  - **`scoring.py`** — Scoring algorithm: severity points, intra-category attenuation (÷1.6^k), category cap (50pts), cross-category boost (+8% per extra category), verdict thresholds (0-14 safe, 15-34 suspicious, 35-64 likely_malicious, 65+ malicious).
  - **`domain/`** — Frozen dataclasses and enums: `EmailData`, `Signal`, `BlindSpot`, `AnalysisResult`, `Verdict`, `SignalSeverity`, `SignalCategory`.
  - **`analyzers/base.py`** — `BaseAnalyzer` ABC: implement `name`, `category`, `analyze(email) → AnalysisOutput`.
  - **`intel_sources/base.py`** — `ThreatIntelSource` ABC: implement `source_type`, `is_available()`, `query(email) → AnalysisOutput`.
- **`app/dependencies.py`** — DI wiring point: wires all analyzer implementations and intel sources into the `DetectionEngine`.

### Add-on layer (Apps Script)

- `Code.gs` — Entry points (`onGmailMessageOpen`, `onReanalyze`)
- `EmailExtractor.gs` — Extracts sender, headers, attachments from Gmail message
- `BackendClient.gs` — HMAC-signs and POSTs to `/analyze`
- `CardBuilder.gs` — Renders verdict, findings, blind spots as Gmail Card UI

### Current state

All Tier 1 analyzers are implemented: `AuthenticationAnalyzer`, `SenderAnalyzer`, `BodyContentAnalyzer`, `UrlStructureAnalyzer`, `AttachmentAnalyzer`. No intel sources are wired yet (Safe Browsing is the planned first). Test fixtures cover ~40 email scenarios across phishing, spear phishing, BEC, malware, scams, evasion, legitimate, and edge cases.

## Documentation

**Sync rule**: when a code change affects architecture, scope, detection capabilities, scoring behavior, API contracts, or implementation status — update the relevant docs in the same change. If code and documentation disagree, stop and reconcile them together.

### Tracked docs (committed)

| File | Purpose |
|---|---|
| `CLAUDE.md` | AI development guide: build commands, architecture summary, conventions, doc index |
| `README.md` | Public-facing project documentation: architecture, capabilities, API contract, setup, trade-offs |
| `docs/detection-policy.md` | Indicator selection criteria, full signal tables by category, scoring algorithm mapping, blind spots |
| `docs/ROADMAP.md` | Tier-based development plan with analyzer specs, test contracts, and post-MVP extensions |

### Untracked docs (local reference)

| File | Purpose |
|---|---|
| `local-docs/project-overview.md` | Detailed architecture boundaries, domain model rules, coding rules, provisional decisions |
| `local-docs/demo-prep.md` | Demo email strategy and interview talking points |
| `local-docs/task-spec.md` | Original Upwind Bootcamp assignment (read-only reference) |
| `local-docs/readme-spec.md` | Checklist for README section requirements |

### Ownership rules

- **Architecture and boundaries** → `CLAUDE.md` (summary) + `local-docs/project-overview.md` (detail)
- **What signals exist and why** → `docs/detection-policy.md`
- **What to build and when** → `docs/ROADMAP.md`
- **Public-facing explanation** → `README.md`

## Conventions

- **Naming**: favor highly readable, self-documenting names. Names should explain purpose without needing comments. Avoid abbreviations except universals (url, html, id, sha256).
- **Domain objects**: frozen dataclasses throughout `detection_engine/domain/`. `EmailHeaders` is case-insensitive with multi-value support.
- **Error philosophy**: analyzer crashes fail the analysis (the engine raises `AnalyzerCrashed`, the API returns 500) because a buggy analyzer producing wrong signals is worse than no result. Intel source crashes degrade gracefully into blind spots, since external service failures are expected at runtime.
- **Reusable scripts**: save testing/utility scripts to `local-scripts/` (gitignored), organized by category (e.g., `local-scripts/testing/smoke-test-api.sh`).


## Core Clean Code Principles:
- Code Clarity: Prioritize readability and clean & elegant logic over micro-optimizations for the machine.
- Meaningful Naming: Use intention-revealing names for variables and functions to make code self-documenting.
- Single Responsibility (SRP): Ensure every class and function has one specific purpose and only one reason to change.
- DRY (Don't Repeat Yourself): Eliminate logic duplication to ensure a single, authoritative source of truth.
- Concise Functions: Write small, focused functions that perform exactly one task efficiently.
- SOLID Foundations: Apply object-oriented design patterns to build decoupled and flexible architectures.
- Modular Abstraction: Utilize interfaces and classes to create scalable, swappable, and testable components.
- Intentional Design: Keep the codebase maintainable by favoring simple, transparent solutions over complexity.
Ensure maintainability. Code should be easy to modify, extend, and debug over time. Design with scalability in mind. Avoid patterns that break or become confusing as the project grows.

