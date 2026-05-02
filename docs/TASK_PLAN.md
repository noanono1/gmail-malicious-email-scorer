# Task Plan: HeaderAnalyzer Integration

Implementation plan for the first concrete analyzer in the system.

---

## 1. Current State

The skeleton (Tier 0) is complete. The engine, scoring algorithm, domain model, ABCs, FastAPI adapter, and Gmail Add-on are all wired and working. The `/analyze` endpoint returns a valid `AnalysisResult` with score 0, verdict SAFE, and a `THREAD_HISTORY` blind spot — but no analyzers run because `dependencies.py` injects an empty list.

Seven test fixtures exist in [email_fixtures.py](../backend/tests/email_fixtures.py) with scoring contracts. The contract tests in [test_tier1_detection.py](../backend/tests/test_tier1_detection.py) import `HeaderAnalyzer` (which doesn't exist yet) and will fail on import.

**HeaderAnalyzer is the first real analyzer.** It unlocks end-to-end scoring integration: signals flow through the engine, get scored, produce a verdict, and appear in the API response. Every subsequent analyzer follows the same pattern.

---

## 2. Where HeaderAnalyzer Fits

```
detection_engine/
├── analyzers/
│   ├── base.py          ← BaseAnalyzer ABC (exists)
│   └── header.py        ← NEW: HeaderAnalyzer
├── domain/              ← EmailData, Signal, BlindSpot, enums (exists, unchanged)
├── engine.py            ← orchestrator (exists, unchanged)
└── scoring.py           ← scoring algorithm (exists, unchanged)
```

HeaderAnalyzer is a leaf node. It:
- inherits `BaseAnalyzer`
- receives `EmailData` (read-only)
- returns `DetectionOutput` (signals + blind spots)
- uses only stdlib — no new dependencies

The engine already knows how to run any `BaseAnalyzer`, collect its outputs, and handle crashes. No engine changes needed.

---

## 3. Architectural Boundaries — Must Not Break

| Boundary | Constraint | How HeaderAnalyzer respects it |
|---|---|---|
| **Pure library** | `detection_engine/` has zero framework deps | No FastAPI, Pydantic, structlog imports |
| **No network** | Analyzers never make HTTP/DNS/socket calls | Parses header string in-memory |
| **No mutation of EmailData** | `EmailData` is frozen | Reads `email.headers`, never modifies |
| **Producer-owned blind spots** | Only the analyzer knows what it couldn't check | Returns `AUTHENTICATION_HEADERS` blind spot when header is absent |
| **score_contribution = 0** | Analyzers never set `score_contribution` | Leaves default 0.0 on all emitted Signals |
| **Defensive, never raises** | Malformed input → empty output + blind spot, not exception | Early return on missing/unparseable header |
| **Logging** | stdlib `logging` only inside `detection_engine/` | Uses `logging.getLogger(__name__)` |
| **Import direction** | `detection_engine/` never imports from `app/` or `infrastructure/` | Imports only from `detection_engine.domain.*` and stdlib |
| **Public API** | `app/` imports only from `detection_engine/__init__.py` | HeaderAnalyzer is not exported in `__init__.py` — `dependencies.py` imports it directly from `detection_engine.analyzers.header` |

---

## 4. Implementation Plan

### Phase 1 — HeaderAnalyzer class

**File:** `backend/detection_engine/analyzers/header.py`

**Responsibilities:**
1. Parse the `Authentication-Results` header from `email.headers`
2. Extract SPF, DKIM, and DMARC results
3. Emit signals for failures/absence
4. Report a blind spot when the header is missing entirely

**Class structure:**

```
HeaderAnalyzer(BaseAnalyzer)
├── name → "header_analyzer"
├── category → SignalCategory.AUTHENTICATION
└── analyze(email) → DetectionOutput
    ├── _extract_auth_results(email) → str | None
    ├── _parse_auth_result(header_value, method) → str | None
    └── _build_signal(method, result) → Signal | None
```

**Signals emitted:**

| Signal ID | Trigger | Severity | Confidence | Evidence template |
|---|---|---|---|---|
| `spf_fail` | `spf=fail` or `spf=softfail` or `spf=none` | HIGH | 1.0 (fail) / 0.7 (softfail) / 0.8 (none) | `"SPF check returned '{result}' for sender domain"` |
| `dkim_fail` | `dkim=fail` or `dkim=none` | HIGH | 1.0 (fail) / 0.8 (none) | `"DKIM signature {result} for sender domain"` |
| `dmarc_fail` | `dmarc=fail` or `dmarc=none` | CRITICAL | 1.0 (fail) / 0.8 (none) | `"DMARC policy returned '{result}' for sender domain"` |

**Confidence rationale:** `fail` = 1.0 (definitive rejection). `none` = 0.8 (absent record — suspicious but could be misconfiguration). `softfail` = 0.7 (SPF-specific transitional state, weaker signal).

**Blind spot:**

| Condition | BlindSpot |
|---|---|
| `Authentication-Results` header absent | `area=AUTHENTICATION_HEADERS`, reason="No Authentication-Results header present", risk_note="Email authentication status unknown — SPF, DKIM, and DMARC could not be evaluated" |

**Parsing approach:**

The `Authentication-Results` header follows RFC 8601. Real-world format from our fixtures:

```
mx.example.com; spf=fail smtp.mailfrom=paypa1-support.com; dkim=fail header.d=paypa1-support.com; dmarc=fail header.from=paypa1-support.com
```

Structure: `authserv-id; method=result [reason] [prop.key=value]; ...`

Parsing strategy:
1. Get header value via `email.headers.get("authentication-results")`
2. For each method (`spf`, `dkim`, `dmarc`): regex search for `method=result` where result is one of `pass`, `fail`, `softfail`, `none`, `neutral`, `temperror`, `permerror`
3. Pattern: `r"(?:^|;\s*)spf=(pass|fail|softfail|none|neutral|temperror|permerror)"` (anchored to start or semicolon to avoid substring matches)

This is deliberately simple. We don't need to parse the full RFC 8601 grammar — we need to extract three results from a semi-structured string. The regex approach handles all fixture formats and real Gmail `Authentication-Results` headers.

**Design decisions:**

| Decision | Rationale |
|---|---|
| `pass` emits no signal | Passing auth is the normal state — no signal, no score contribution. The system scores absence of good, not presence of good |
| `temperror` / `permerror` are not flagged | Transient DNS errors and policy errors are infrastructure issues, not phishing indicators. Flagging them would create false positives on misconfigured legitimate domains |
| Single `Authentication-Results` header | Use `email.headers.get()` (first value), not `get_all()`. Multiple `Authentication-Results` headers are possible but rare; the first is from the receiving MTA closest to the recipient, which is the most authoritative |
| Regex over full parser | The header format is semi-structured but our extraction is narrow (3 key-value pairs). A full RFC 8601 parser would be over-engineering for this scope |

### Phase 2 — Wire into the engine

**File:** `backend/app/dependencies.py`

Change the `_get_detection_engine()` function to inject `HeaderAnalyzer`:

```python
from detection_engine.analyzers.header import HeaderAnalyzer

def _get_detection_engine() -> DetectionEngine:
    return DetectionEngine(analyzers=[HeaderAnalyzer()], intel_sources=[])
```

This is the only `app/` change. The import goes directly to the module, not through `__init__.py` — consistent with [project-overview.md](../local-docs/project-overview.md) §2 ("app/ imports only from detection_engine/__init__.py") for domain types, but concrete analyzer wiring is DI plumbing that lives in `dependencies.py` by design.

### Phase 3 — Unit tests for HeaderAnalyzer

**File:** `backend/tests/test_header_analyzer.py` (new)

Test the analyzer in isolation (not through the engine). Focused on parsing correctness and signal emission.

| Test | Input | Expected |
|---|---|---|
| `test_all_auth_fail` | Auth-Results: `spf=fail; dkim=fail; dmarc=fail` | 3 signals: spf_fail (HIGH, 1.0), dkim_fail (HIGH, 1.0), dmarc_fail (CRITICAL, 1.0) |
| `test_all_auth_pass` | Auth-Results: `spf=pass; dkim=pass; dmarc=pass` | 0 signals, 0 blind spots |
| `test_spf_softfail` | Auth-Results: `spf=softfail; dkim=pass; dmarc=pass` | 1 signal: spf_fail (HIGH, 0.7) |
| `test_dkim_none` | Auth-Results: `dkim=none` | 1 signal: dkim_fail (HIGH, 0.8) |
| `test_dmarc_none` | Auth-Results: `dmarc=none` | 1 signal: dmarc_fail (CRITICAL, 0.8) |
| `test_missing_auth_header` | No Authentication-Results header | 0 signals, 1 blind spot (AUTHENTICATION_HEADERS) |
| `test_malformed_auth_header` | Auth-Results: `garbage value` | 0 signals, 0 blind spots (no match = no signal, not an error) |
| `test_partial_results` | Auth-Results: `spf=pass; dmarc=fail` (no DKIM) | 1 signal: dmarc_fail. No DKIM signal (absence of a method in the header ≠ failure) |
| `test_score_contribution_is_zero` | Any failing auth | All emitted signals have `score_contribution == 0.0` |
| `test_real_fixture_mass_phishing` | `MASS_PHISHING` fixture | 3 signals emitted (spf, dkim, dmarc all fail) |
| `test_real_fixture_legit_amazon` | `LEGIT_AMAZON_ORDER` fixture | 0 signals emitted |

**Test helper:** Build minimal `EmailData` objects with just the headers needed, using `EmailHeaders` directly. Don't go through the fixture converter for unit tests — keep dependencies minimal.

### Phase 4 — Scoring integration verification

Run the existing contract tests with HeaderAnalyzer only (no SenderAnalyzer or ContentAnalyzer yet). This verifies:

1. HeaderAnalyzer signals flow through the engine correctly
2. Scoring algorithm processes them as expected
3. No crashes on any fixture

**Expected results with HeaderAnalyzer alone:**

| Fixture | Auth status | Signals | Expected score | Contract met? |
|---|---|---|---|---|
| `MASS_PHISHING` | spf=fail, dkim=fail, dmarc=fail | 3 (CRITICAL + HIGH + HIGH) | ~50 (capped) | Not yet — needs ≥65, requires cross-category signals from SenderAnalyzer/ContentAnalyzer |
| `LEGIT_AMAZON_ORDER` | all pass | 0 | 0 | Yes — <15, SAFE |
| `BEC_WIRE_TRANSFER` | all pass (gmail.com) | 0 | 0 | Not yet — needs ≥15, requires SenderAnalyzer/ContentAnalyzer |
| `SPEAR_PHISH_COUSIN_DOMAIN` | all pass (arnazon.com) | 0 | 0 | Not yet — needs ≥35, requires SenderAnalyzer |
| `LEGIT_MARKETING` | all pass | 0 | 0 | Yes — <15, SAFE |
| `MALWARE_ATTACHMENT` | spf=fail, dkim=none, dmarc=fail | 3 | ~50 | Not yet — needs ≥65, requires AttachmentAnalyzer (Tier 2) |
| `EMPTY_MINIMAL` | no header | 0 | 0 | Yes — <15, SAFE |

The full contract tests (`test_tier1_detection.py`) will still fail because they import SenderAnalyzer and ContentAnalyzer. But running HeaderAnalyzer-only tests will validate the integration path.

---

## 5. File-by-File Impact

| File | Change | Type |
|---|---|---|
| `detection_engine/analyzers/header.py` | **Create** — HeaderAnalyzer class | New file |
| `tests/test_header_analyzer.py` | **Create** — unit tests for HeaderAnalyzer | New file |
| `app/dependencies.py` | **Edit** — add HeaderAnalyzer import and inject into engine | 2 lines changed |
| `detection_engine/__init__.py` | **No change** — HeaderAnalyzer is not part of the public API | Unchanged |
| `detection_engine/engine.py` | **No change** — already handles any BaseAnalyzer | Unchanged |
| `detection_engine/scoring.py` | **No change** — already handles any Signal | Unchanged |
| `detection_engine/domain/*` | **No change** — all needed types exist | Unchanged |
| `tests/email_fixtures.py` | **No change** — fixtures already have Authentication-Results headers | Unchanged |
| `tests/test_tier1_detection.py` | **No change** — will still fail (imports SenderAnalyzer/ContentAnalyzer), resolved in later task | Unchanged |

---

## 6. Testing and Validation Plan

### Level 1 — Unit tests (Phase 3)

Run: `python -m pytest tests/test_header_analyzer.py -v`

Validates: parsing correctness, signal emission, blind spot generation, defensive behavior.

### Level 2 — Scoring math verification

Manually verify that HeaderAnalyzer signals produce expected scores through the scoring algorithm:

```
3 auth failures (DMARC=CRITICAL, SPF=HIGH, DKIM=HIGH), all confidence=1.0:
  DMARC: 35.0 / 1.6^0 = 35.0
  SPF:   22.0 / 1.6^1 = 13.75
  DKIM:  22.0 / 1.6^2 = 8.59
  Total: 57.34 → capped at 50.0
  Active categories: 1 → boost = 1.0
  Final: 50.0 → LIKELY_MALICIOUS
```

This matches the Detection Policy's example and validates that a single category cannot reach MALICIOUS (≥65) alone. The cap is working as designed.

### Level 3 — Integration test (Phase 4)

Create a focused integration test that runs HeaderAnalyzer through the engine:

```python
engine = DetectionEngine(analyzers=[HeaderAnalyzer()])
result = engine.analyze(build_email_data(MASS_PHISHING["email"]))
assert 35 <= result.score <= 50  # capped by category cap
assert result.verdict == Verdict.LIKELY_MALICIOUS
assert "header_analyzer" in result.scope.analyzers_run
```

### Level 4 — API-level smoke test

After wiring in `dependencies.py`, start the server and POST a test payload to `/analyze`. Verify the response includes authentication signals and the score matches expectations.

Script location: `local-scripts/testing/smoke-test-header-analyzer.sh`

---

## 7. Risks, Assumptions, and Open Questions

### Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Auth-Results header format varies across MTAs | Parsing may miss valid results or match false positives | Regex anchored to semicolons/start. Test against all 7 fixture formats. The RFC 8601 format is well-adopted by major MTAs (Gmail, Exchange, Postfix) |
| `softfail` confidence (0.7) may be too high or too low | Score calibration slightly off | Provisional — mark as `[PROVISIONAL]` in code comment, tune after running against more fixtures |
| `none` (record absent) vs `fail` (record present, check failed) distinction | Different confidence levels needed | Handled: `fail` = 1.0, `none` = 0.8. The distinction preserves the scoring system's ability to differentiate |

### Assumptions

- The `Authentication-Results` header is populated by the receiving MTA before the email reaches the add-on. This is standard Gmail behavior — Gmail always adds this header.
- The first `Authentication-Results` header (via `email.headers.get()`) is the most authoritative. In multi-hop scenarios, later MTAs may add their own, but the first one (from Gmail's MTA) is what matters for the recipient.
- `neutral` and `temperror`/`permerror` SPF results are not phishing signals. They indicate DNS issues or "neither pass nor fail" states that shouldn't push the score.

### Open Questions

| Question | Current decision | Revisit when |
|---|---|---|
| Should we handle multiple `Authentication-Results` headers? | No — use first (most authoritative) | If we encounter real emails where the first header is from an intermediate MTA, not the final receiver |
| Should `temperror`/`permerror` emit INFO signals for visibility? | No — keep them silent | After Tier 1 is complete and we review blind spot coverage |
| Should the analyzer extract the domain from `smtp.mailfrom=` and include it in evidence? | Yes — include in evidence string for explainability | N/A, decided |

---

## 8. Definition of Done

- [ ] `detection_engine/analyzers/header.py` exists with `HeaderAnalyzer` class
- [ ] HeaderAnalyzer inherits `BaseAnalyzer`, implements `name`, `category`, `analyze`
- [ ] Parses `Authentication-Results` header for SPF, DKIM, DMARC results
- [ ] Emits correct signals for `fail`, `softfail`, `none` results
- [ ] Emits no signals for `pass` results
- [ ] Returns `AUTHENTICATION_HEADERS` blind spot when header is absent
- [ ] Never raises on malformed input
- [ ] All emitted signals have `score_contribution == 0.0`
- [ ] Uses only stdlib imports (no FastAPI, Pydantic, structlog)
- [ ] `tests/test_header_analyzer.py` passes with all cases green
- [ ] `dependencies.py` updated to wire HeaderAnalyzer into the engine
- [ ] Scoring integration verified: 3 auth failures → ~50 (capped), verdict = LIKELY_MALICIOUS
- [ ] Legitimate fixtures (Amazon, marketing) produce 0 signals, score 0
- [ ] Empty fixture produces 0 signals + 1 blind spot, no crash
