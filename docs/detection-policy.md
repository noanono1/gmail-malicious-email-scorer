# Detection Policy

## Scope

The engine is split along a deliberate seam:

1. **Deterministic analyzers** (authentication, sender, URL, attachment, body HTML structure) — every indicator is extracted from the email as received. Same input, same output, every time. Verbatim evidence in every signal. No outbound network access.
2. **Language Assessment analyzer** — one analyzer, isolated from the rest, that asks a **local** SLM (Ollama, no external API) to decompose the body into a closed-set schema. Severity is capped at HIGH so a probabilistic assessment can amplify but never solely drive the engine to MALICIOUS.

The indicator set covers mass phishing as the primary use case, with meaningful overlap into credential harvesting, malware delivery via attachments, and basic impersonation patterns (including some BEC and spear-phishing variants). When the Language Assessment analyzer is enabled, paraphrased social-engineering language that keyword rules historically over- or under-flagged is also covered. Threats that require capabilities beyond these two seams — sandbox execution, user profiling, organizational context, threat-intel lookups — are explicitly out of scope and documented in "Deferred Indicators."

### Why this split

Email threats split cleanly into two kinds of evidence: **artifacts** (headers, addresses, links, files) and **language** (urgency, manipulation, requested action). Artifacts have repeatable structure — a `dmarc=fail` is unambiguous, a `<form>` in the body is or isn't there, a `.exe` attachment is one rule. Language doesn't. Keyword rules over-flag legitimate transactional copy that shares vocabulary with phishing ("verify your identity") and miss novel phrasings of the same manipulation.

So we use rules where they're strong and isolate language understanding into one constrained extractor where they're brittle. The Language Assessment analyzer is grammar-constrained at decode time (Ollama `format` against a Pydantic schema), validates that any non-default finding cites a verbatim quote from the email, and on any failure (transport, parse, ungrounded quote) returns a blind spot rather than a guess.

### Why the deterministic analyzers stay offline

They run on the email artifact as-is, without URL resolution, WHOIS, or sandbox execution. This gives us:

- **No external dependencies** — the deterministic analyzers run anywhere, with no API keys, rate limits, or availability concerns.
- **Deterministic results** — same email always produces the same deterministic-engine verdict, which makes testing and debugging straightforward.
- **Fast execution** — no I/O waits, suitable for real-time Gmail Add-on UX.

The Language Assessment analyzer breaks none of these guarantees externally — under the default `LANGUAGE_PROVIDER=local` the SLM is local and content never leaves the host; decoding is grammar-constrained against the `LanguageAssessment` schema, and the analyzer reports a blind spot when the configured provider is unreachable rather than degrading silently. The optional `LANGUAGE_PROVIDER=openai` path sends content to OpenAI's API; that tradeoff is opt-in, never the default.

The cost: we cannot resolve shortened URLs, check domain age via WHOIS, scan attachments in a sandbox, or query threat intelligence feeds. These would all require external network lookups; they are out of scope for the initial implementation. See `docs/ROADMAP.md` Tier 4 for the planned shape if added later.

---

## Indicator Selection Criteria

Every candidate indicator was evaluated on six axes:

| Axis | Measures | Prefer |
|---|---|---|
| **Severity** | How serious the finding is if detected | Higher |
| **Commonality** | How often this appears in real phishing | Higher |
| **Ease of extraction** | How simple to collect via static analysis | Higher |
| **Signal strength** | How strongly it suggests malicious intent vs. noise | Higher |
| **Complexity** | Implementation and maintenance effort | Lower |
| **False-positive risk** | How often this appears in benign email | Lower |

An indicator earns inclusion when it scores well across most axes. High false-positive risk is acceptable only when the indicator functions as a **supporting signal** (amplifies confidence alongside stronger signals, never drives the verdict alone). This is enforced by the scoring algorithm's within-category attenuation and category cap.

---

## Included Indicators

### AUTHENTICATION category

These indicators check whether the sending infrastructure is authorized by the claimed domain. Authentication failures are among the strongest phishing signals — they indicate the sender may not be who they claim to be, though failures can also result from misconfiguration (forwarding breaks SPF, mailing lists break DKIM).

| ID | Indicator | What it detects | Severity | Signal strength | FP risk | Implementation notes |
|---|---|---|---|---|---|---|
| **AUTH-1** | SPF failure (`fail` / `softfail` / `permerror`) | Sending server not authorized by domain's DNS, or SPF record is malformed | HIGH (`fail`), HIGH (`softfail` @ 0.7 conf), LOW (`permerror`) | Strong for `fail`, moderate for `softfail`, weak for `permerror` | Low for `fail`; moderate for `softfail` (forwarders); high for `permerror` (often misconfig) | Parse `Authentication-Results` header for `spf=<result>` |
| **AUTH-2** | DKIM failure (`fail` / `permerror` / `policy`) | Message signature invalid, key record malformed, or signature doesn't meet local policy | HIGH (`fail`), LOW (`permerror`), MEDIUM (`policy`) | Strong for `fail`, weak for `permerror`/`policy` | Low for `fail`; moderate for others (mailing lists break DKIM, key rotation causes `permerror`) | Parse `Authentication-Results` for `dkim=<result>` |
| **AUTH-3** | DMARC failure (`fail` / `permerror`) | Domain's own policy says this message is unauthorized, or DMARC record is malformed | CRITICAL (`fail`), LOW (`permerror`) | Very strong for `fail` | Very low for `fail` — domain owner explicitly configured this | Parse `Authentication-Results` for `dmarc=<result>` |

**Why DMARC is CRITICAL while SPF/DKIM are HIGH**: DMARC is a policy decision by the domain owner — a DMARC fail means the sender's own domain is rejecting this message. SPF and DKIM are infrastructure checks that can fail for operational reasons (forwarding breaks SPF, mailing lists break DKIM). DMARC synthesizes both and adds owner intent.

**Attenuation note**: SPF, DKIM, and DMARC failures are correlated — a spoofed email typically fails all three. The scoring algorithm's within-category attenuation (÷1.4 per additional signal) prevents triple-counting. Three auth failures contribute roughly the same as 2.2 individual failures, not 3.0.

#### Result vocabulary (per RFC 7601)

Every Authentication-Results value belongs to a fixed vocabulary. The analyzer maps each `(method, result)` pair to one or two outcomes — a signal, a blind spot, both, or neither.

| Result | SPF | DKIM | DMARC | Outcome | Rationale |
|---|---|---|---|---|---|
| `pass` | ✓ | ✓ | ✓ | no-op | Verified — no signal needed |
| `neutral` | ✓ | ✓ | — | no-op | Domain explicitly asserts nothing — no info |
| `fail` | ✓ | ✓ | ✓ | signal | Active verification failure |
| `softfail` | ✓ | — | — | signal (HIGH @ 0.7 conf) | SPF weak fail — domain says "probably not me" |
| `permerror` | ✓ | ✓ | ✓ | signal (LOW @ 0.4 conf) | Misconfigured record — usually legit ops mistake, not malice |
| `policy` | — | ✓ | — | signal (MEDIUM @ 0.6 conf) | Valid signature but doesn't meet local policy (e.g. weak key) |
| `none` | ✓ | ✓ | ✓ | **blind spot + weak signal** | No policy/signature published. SPF/DKIM signal: LOW @ 0.5 conf. DMARC signal: MEDIUM @ 0.6 conf. |
| `temperror` | ✓ | ✓ | ✓ | **blind spot only** | Transient DNS/lookup error — unrelated to message validity, must not contribute to the score |

**Why `none` is both a blind spot AND a signal**: `none` carries two meanings. It is a *coverage gap* (we cannot enforce that authentication mechanism, so the user should know), and it is a *weak risk indicator* (a serious sender almost always publishes SPF/DKIM/DMARC; the absence is mildly suspicious). The blind spot communicates uncertainty in the UI; the low/medium signal contributes to the score only enough to amplify a verdict when stacked with other findings (cousin domain, urgency language, suspicious URLs). `none` alone — even on all three methods — is bounded well under the SUSPICIOUS threshold by within-category attenuation, so it cannot drive a false positive on its own.

**Why `temperror` is blind-spot-only**: A transient DNS or lookup failure tells us nothing about the sender's posture. Treating it as a signal would penalize legitimate email for unrelated infrastructure noise.

Unknown result strings (vendor-specific tokens, typos) are silently treated as no-ops rather than crashing the analyzer.

### SENDER_IDENTITY category

These indicators examine who is sending and whether the identity is deceptive, independent of authentication.

| ID | Indicator | What it detects | Severity | Signal strength | FP risk | Implementation notes |
|---|---|---|---|---|---|---|
| **SENDER-1** | Cousin/lookalike domain | `paypa1.com`, `arnazon.com`, `docs-google-verify.com` — sender domain visually similar to a known brand | CRITICAL | Very strong — proves impersonation intent | Very low | Split the registered domain into hyphen-separated segments and compare each against a curated brand list. Normalize visually similar substitutions before comparison: single-char (`1`↔`l`, `0`↔`o`, `5`↔`s`) and multi-char (`rn`↔`m`, `vv`↔`w`, `cl`↔`d`). Threshold scales with brand length — short brands (<5 chars) require an exact match, longer brands tolerate 1–2 edits. Domain-driven only; does not depend on display name. Legitimate regional variants (`amazon.in`, `paypal.fr`, `ebay.co.uk`) are suppressed via a trusted-public-suffix allowlist so they do not become CRITICAL false positives — squatters on fancy gTLDs (`paypal.xyz`) still fire |
| **SENDER-3** | From ≠ Reply-To mismatch | Response directed to a different address | HIGH | Strong | Moderate — legit mailing lists sometimes use different Reply-To | Flag when Reply-To domain differs from From domain. Suppressed when (a) both share the same registered organization (e.g. `support@mail.acme.com` ↔ `acme.com`), (b) the Reply-To is a known ESP, or (c) the From is a freemail provider — personal mail routinely sets a different reply address and flagging it would be too noisy |

**Why cousin domain is CRITICAL**: Unlike authentication failures (which could be misconfiguration), a cousin domain like `paypa1-support.com` is almost never accidental. It represents deliberate, premeditated impersonation — the attacker registered lookalike infrastructure. A single cousin domain detection pushes the score into LIKELY_MALICIOUS territory on its own (CRITICAL = 40 base points, threshold = 35).

**Display-name impersonation is intentionally not a signal here**: An earlier draft included a brand-claim check on the From display name. It was removed because (a) it overlapped almost entirely with SENDER-1 — when the cousin domain fired, the display-name finding was suppressed to avoid double-counting, leaving its unique coverage limited to brand impersonation from freemail or unrelated domains; (b) coverage was bounded by a small static brand list that does not address the long tail of impersonated brands; (c) the more impactful display-name attack is personal-name impersonation in BEC (e.g. "John Smith, CEO" from a freemail account), which requires organizational context this static analyzer does not have. The attack surface is acknowledged as a deferred indicator rather than partially covered.

### URL_STRUCTURE category

These indicators analyze links in the email body without following them.

| ID | Indicator | What it detects | Severity | Signal strength | FP risk | Implementation notes |
|---|---|---|---|---|---|---|
| **URL-1** | href ≠ display text mismatch | Link text says "paypal.com" but href points elsewhere | CRITICAL | Very strong — deliberate deception | Very low — legitimate emails almost never do this | Parse HTML `<a>` tags, extract href and inner text. If inner text looks like a URL (contains a dot and no spaces), compare its domain against the href domain |
| **URL-2** | IP-literal host in URL | `http://192.168.1.100/verify`, `http://[::1]/verify` | HIGH | Strong — legitimate services use domain names | Low | Parse the URL host and validate it with `ipaddress.ip_address` (covers IPv4 and IPv6) |
| **URL-3** | Dangerous URI scheme in href | `javascript:`, `data:`, `vbscript:`, `file:` URLs in `<a>` tags | CRITICAL | Very strong — mail clients block or strip these; surviving instances read as evasion | Very low — legitimate mail does not link these schemes | Parse the href scheme on every HTML link; flag anything in the dangerous-scheme set |

**Why URL mismatch is CRITICAL**: An anchor that displays "www.paypal.com" while the href points to an IP address or unrelated domain is one of the clearest phishing signals — there is rarely an innocent explanation. Combined with a cousin domain (SENDER-1), this produces convergent evidence across two categories, triggering the cross-category boost.

**Why dangerous URI schemes are CRITICAL**: Each of `javascript:`, `vbscript:`, `data:`, and `file:` either embeds executable content (script schemes), embeds a whole payload page in the href itself (`data:`), or escapes to local resources (`file:`). Major mail clients block or strip them, so a surviving instance in an inbound message reads as deliberate evasion rather than a normal link.

**What this category does not flag**: shortened URLs (bit.ly, tinyurl.com, t.co) and high link counts are intentionally excluded — see "Deferred Indicators" for the reasoning. The destination question they gesture at is already represented as the `URL_DESTINATION` blind spot.

### BODY_CONTENT category

These indicators are **structural** — they detect attacker techniques observable in the body's HTML or DOM, not in its language. Linguistic body content (urgency, credential solicitation, paraphrased manipulation) is owned by the Language Assessment analyzer below.

| ID | Indicator | What it detects | Severity | Signal strength | FP risk | Implementation notes |
|---|---|---|---|---|---|---|
| **CONTENT-3** | HTML form in email body | Inline `<form>` with `<input>` fields | CRITICAL | Very strong — almost never appears in legitimate email | Very low | Search HTML body for `<form>` tags containing input elements |

**Why language indicators were removed from this category**: Earlier drafts defined CONTENT-1 (urgency keyword list) and CONTENT-2 (sensitive-data keyword list). They were removed in the move to a deterministic-rules + one-semantic-extractor architecture. Two reasons drove the removal:

1. **Brittle in both directions.** Keyword rules over-flagged legitimate transactional copy that happens to share vocabulary with phishing ("verify your identity" appears in real bank password-reset flows) and under-flagged paraphrased variants the curated list didn't anticipate. False-positive risk on CONTENT-1 was already documented as "High" in the earlier table.
2. **Double-counting with the language analyzer.** Once the Language Assessment analyzer captures the same intent (`pressure_level`, `requested_action == provide_secrets`) from a structured assessment with grounded evidence, keeping the keyword version produces two BODY_CONTENT signals from the same evidence — partially cushioned by within-category attenuation, but architecturally a duplicate path.

The Language Assessment analyzer (next section) replaces both with a single signal grounded in a verbatim quote.

### Semantic body analysis (Language Assessment → BODY_CONTENT category)

Language understanding is isolated into one analyzer, gated behind a port (`LlmService`) that any backend implementing `assess(subject, body, *, envelope) -> LanguageAssessment | None` could fulfill. Two providers are wired today: a local Ollama-served SLM (default) and the OpenAI Chat Completions API. Selection is via `LANGUAGE_PROVIDER` (`local` or `openai`); `local` is the default because it keeps email content on the host.

| ID | Indicator | What it detects | Severity | Signal strength | FP risk | Implementation notes |
|---|---|---|---|---|---|---|
| **LANG-1** | Manipulative language (`manipulative_language`) | Combination of risky `requested_action` (`provide_secrets`, `provide_payment`, `login_or_verify_identity`, …), `pressure_level`, and itemized `manipulation_tactics` derived from a structured SLM assessment of the body | LOW–HIGH (capped at HIGH) | Moderate — depends on the combination of axes; isolated provide_secrets without pressure reaches MEDIUM, secrets + severe pressure + multiple tactics reaches HIGH | Low — defended by closed-set schema, grammar-constrained decoding (Ollama `format`), and verbatim evidence-quote grounding | One signal in the BODY_CONTENT category. Confidence floor (0.6) suppresses uncertain assessments. Severity ceiling is HIGH by design — a probabilistic assessment cannot single-handedly drive an email to MALICIOUS; CRITICAL stays reserved for findings provable from the artifact (cousin domain, HTML form, dangerous extension). On any failure (transport, schema, grounding) the analyzer emits a `language_assessment` blind spot rather than a guess |

**Why HIGH ceiling**: Any language model — SLM or LLM — is probabilistic; even a well-grounded assessment can be wrong on adversarial input. Capping at HIGH means the analyzer can amplify a verdict already supported by deterministic findings (auth fail + cousin domain + manipulative language → MALICIOUS) without being able to drive an otherwise-clean email past LIKELY_MALICIOUS on its own.

**Anti-injection and anti-hallucination defenses** (see `infrastructure/llm/_prompt.py` for the full list): per-request random delimiter, Unicode control/format hygiene, grammar-constrained decoding against the Pydantic schema, and rejection of any non-default finding whose evidence quotes don't appear verbatim in the (sanitized) source text. The grounding check is the load-bearing one — without it, the analyzer would surface fabricated quotes; with it, ungrounded responses degrade to a blind spot.

### ATTACHMENT category

These indicators examine attachment metadata without opening or executing files.

| ID | Indicator | What it detects | Severity | Signal strength | FP risk | Implementation notes |
|---|---|---|---|---|---|---|
| **ATTACH-1** | Dangerous file extension | .exe, .scr, .bat, .cmd, .ps1, .vbs, .js, .msi, .com, .pif, .hta, .wsf, .cpl, .reg, .html, .htm | CRITICAL | Very strong — these file types have no legitimate reason to arrive via email in most contexts | Very low for executables; moderate for `.html`/`.htm` (see design note below) | Check attachment filename extension against a curated dangerous-extensions list |
| **ATTACH-2** | Double extension | `invoice.pdf.exe` — masquerading as a safe file type | CRITICAL | Very strong — always deliberate deception | Very low | Check if filename contains multiple extensions where the final one is dangerous |
| **ATTACH-3** | Macro-enabled Office format | .docm, .xlsm, .pptm, .dotm, .xltm, .potm — Office files with macros | HIGH | Strong — macro malware is a primary delivery vector | Moderate — some organizations still use macro-enabled templates | Check extension against macro-enabled Office file extensions |
| **ATTACH-4** | Password-protected archive | Encrypted .zip/.rar mentioned in body | HIGH | Strong — used to evade scanning | Moderate — legit confidential docs use this too | Check for archive MIME types combined with body text mentioning "password" near attachment references |

#### Design note: `.html` / `.htm` at CRITICAL

`.html` and `.htm` sit on ATTACH-1 at **CRITICAL** with the rest of the dangerous-extension list. Unlike the other entries (which execute code natively on the OS), HTML files only run inside a browser and are routinely attached to legitimate mail (invoices, receipts, exported reports, newsletter archives). The risk is real — an HTML attachment can host a credential-harvesting form or a JavaScript redirect — but the false-positive rate is higher than for `.exe`/`.bat`/`.ps1`.

The alternatives considered:

1. **Keep CRITICAL** (chosen). HTML attachments that survive mail-client filtering are more likely evasion than routine. In the absence of content inspection (we don't open attachments), treating them as dangerous errs on the side of caution.
2. **Downgrade to HIGH or MEDIUM.** Would reduce FP risk but weaken coverage for credential-harvesting-via-attachment, which is a common delivery pattern.
3. **Remove `.html`/`.htm` entirely.** The credential-harvesting vector is partially represented by CONTENT-3 (HTML form in body), but only when the HTML is inlined — not when it arrives as a file.

CRITICAL was chosen because at this stage, without attachment content inspection, the extension is the only signal we have. If attachment sandboxing is added later, the severity should be revisited since the content itself would provide stronger evidence than the file type alone.

---

## Deferred Indicators (with reasoning)

These indicators were evaluated and intentionally excluded from the initial scope. Each exclusion has a specific technical reason, not just "out of scope."

| Indicator | Why deferred | What would be needed |
|---|---|---|
| **Received chain analysis** | The Received header format is not standardized — each MTA writes it differently. Parsing is fragile and produces unreliable results. Effort-to-value ratio is poor | A robust multi-format parser with per-MTA heuristics |
| **Domain age** | Requires WHOIS or RDAP lookup — an external network call that violates our static-analysis constraint | A WHOIS/RDAP client behind a threat-intel port (see ROADMAP Tier 4) |
| **URL destination check** | Requires HTTP requests to follow redirects — violates static-analysis constraint and introduces latency | A Safe Browsing client behind a threat-intel port (see ROADMAP Tier 4) |
| **Obfuscated HTML** | CSS-hidden text (`font-size:0`, `color:white`, `display:none`), base64-encoded sections, `data:` URI inlining of phishing pages. Detecting these requires rendering or deep HTML analysis. Moderate effort for low commonality | HTML rendering engine or heuristic decoder |
| **QR code phishing** | Embedded QR codes pointing to malicious URLs. Requires image parsing — not available in static text analysis | Image processing library, QR decoder |
| **Shortened URL detection** | Shorteners (bit.ly, t.co, tinyurl.com) hide the destination, but legitimate marketing, social media, and CRM tooling use them constantly. As a standalone signal the FP rate is too high to defend; the destination question it raises is already represented by the `URL_DESTINATION` blind spot, and is properly resolved by following the link in a sandbox or threat-intel service rather than by host-list matching | A shortener-resolving client (or a Safe Browsing query on the resolved URL) behind a threat-intel port (see ROADMAP Tier 4) |
| **Link volume / excessive URL count** | Counting unique link domains is metadata, not evidence. As an INFO-severity signal it contributed 0 points to the score while still appearing in the findings list — pure noise. If link volume ever becomes useful it will be as an input to a stronger composite signal, not as a finding on its own | A composite scoring rule that combines link volume with content or sender heuristics |
| **Display-name impersonation** | A static brand-claim check on the From display name was prototyped and removed. Its unique coverage was narrow — when a cousin domain was present (the typical attack pattern) it was suppressed to avoid double-counting, leaving only the freemail/unrelated-domain case — and it was bounded by a small static brand list that does not reflect the long tail of impersonated brands. The higher-value display-name attack is personal-name impersonation in BEC ("John Smith, CEO" from a freemail account), which static analysis cannot resolve without organizational identity context | A directory of legitimate internal senders (or threat-intel feed of impersonated brands) cross-referenced against display-name claims |

---

## How Indicators Map to the Scoring Algorithm

The scoring algorithm is defined in [`backend/detection_engine/scoring.py`](../backend/detection_engine/scoring.py); the constants below are the live values. This section explains the design rationale — for the source-of-truth values, read the constants in `scoring.py` directly.

### Severity → base points

| Severity | Points | Design rationale |
|---|---|---|
| INFO | 0 | Appears in report, never affects score |
| LOW | 5 | Supporting signal — needs corroboration |
| MEDIUM | 12 | Notable but not alarming alone |
| HIGH | 25 | Two from different categories cross SUSPICIOUS even at 0.9 confidence |
| CRITICAL | 40 | One alone reaches LIKELY_MALICIOUS even at 0.9 confidence |

### Score accumulation safeguards

- **Within-category attenuation (÷1.4^k)**: Prevents correlated signals from stacking. Three AUTH failures ≈ 2.2× one failure, not 3×.
- **Category cap (50 pts)**: No single category can dominate. Five auth failures cannot push past LIKELY_MALICIOUS without evidence from another category.
- **Cross-category boost (+15% per extra active category)**: Two categories → ×1.15, three → ×1.30, four → ×1.45. Reflects that convergent evidence across orthogonal categories is more diagnostic than depth in one.
- **Infrastructure-only dampener (×0.78)**: Applied when ≥2 active categories are firing, *all* of them are AUTHENTICATION or SENDER_IDENTITY ("infrastructure looks unsettled" signals), and *no* category contributes a CRITICAL-strength score (≥40). The false-positive guard for the "small-vendor email with auth/sender weirdness but no concrete attack content" pattern — without any URL/body/attachment evidence the email has no declared attack vector, just unsettled infrastructure. The dampener softens the verdict by ~22%, which fully demotes weaker pairs (e.g. SPF softfail + DKIM none from SUSPICIOUS to SAFE) and meaningfully reduces the strength of stronger pairs (e.g. SPF softfail + Reply-To mismatch stays in LIKELY_MALICIOUS but at the bottom of the band rather than mid-band — see worked example below). Decisive single signals (DMARC fail at CRITICAL, cousin domain at CRITICAL) disable the dampener — they are strong enough on their own to justify the verdict.

### Verdict thresholds

| Score range | Verdict | What it means |
|---|---|---|
| 0–14 | SAFE | No significant indicators detected |
| 15–34 | SUSPICIOUS | Some indicators present — review recommended |
| 35–64 | LIKELY_MALICIOUS | Strong evidence from one or more categories |
| 65–100 | MALICIOUS | Convergent evidence across multiple categories |

### Example: mass phishing email scoring path

An email from `paypa1-support.com` with SPF/DKIM/DMARC fail, a deceptive URL, and (with the Language Assessment analyzer enabled) provide_secrets + severe pressure:

```
AUTHENTICATION:
  DMARC fail     → CRITICAL (40.0) ÷ 1.4^0 = 40.00
  SPF fail       → HIGH    (25.0) ÷ 1.4^1 = 17.86
  DKIM fail      → HIGH    (25.0) ÷ 1.4^2 = 12.76
  Category total = 70.62 → scaled to cap of 50.00
    DMARC fail   → 40.00 × 50/70.62 = 28.32
    SPF fail     → 17.86 × 50/70.62 = 12.64
    DKIM fail    → 12.76 × 50/70.62 =  9.03

SENDER_IDENTITY:
  Cousin domain  → CRITICAL (40.0) ÷ 1.4^0 = 40.00

URL_STRUCTURE:
  Href ≠ display → CRITICAL (40.0) ÷ 1.4^0 = 40.00

BODY_CONTENT (language assessment):
  manipulative_language → HIGH (25.0 × 0.95 conf) = 23.75

Raw total = 50.00 + 40.00 + 40.00 + 23.75 = 153.75
Active categories = 4 → cross-category boost ×1.45
Dampener: BODY_CONTENT and URL_STRUCTURE are not infrastructure → no dampener
Final = 153.75 × 1.45 = 222.94 → clamped to 100.0
Verdict = MALICIOUS ✓
```

### Example: strong language body alone — language is a *helper*, not the decider

A body that asks for the user's password under severe pressure, but with valid auth and a real-looking domain:

```
BODY_CONTENT (language assessment):
  manipulative_language → HIGH (25.0 × 0.95 conf) = 23.75

Raw total = 23.75
1 active category → no cross-category boost
Final = 23.75 → SUSPICIOUS
```

A flagrantly worded body alone is bounded at SUSPICIOUS — by design. The HIGH severity ceiling on probabilistic language assessments applies, and a single category produces no cross-category boost. Pair the same language with another finding (deceptive URL, sender mismatch, auth fail) and the cross-category boost lifts the score into LIKELY_MALICIOUS / MALICIOUS without raising any individual signal's severity.

### Example: weak unrelated infrastructure signals — the false-positive guard

A small-vendor email with `spf=softfail` and a Reply-To pointing to a different domain. Two HIGH-severity signals across two categories — but no concrete "what is this email trying to do" finding:

```
AUTHENTICATION:
  SPF softfail      → HIGH (25.0 × 0.7 conf) = 17.50

SENDER_IDENTITY:
  Reply-To mismatch → HIGH (25.0 × 1.0 conf) = 25.00

Raw total = 42.50
2 active categories → cross-category boost ×1.15 → 48.88
Both categories are infrastructure, no CRITICAL contribution → dampener ×0.78
Final = 48.88 × 0.78 = 38.12 → LIKELY_MALICIOUS (low end of the 35–64 band)
```

Without the dampener this case would sit at 48.88 — mid-band LIKELY_MALICIOUS. The dampener pulls it down to 38.12, just inside the same band. This is the strongest infrastructure-only pair — for weaker ones (e.g. DKIM fail + SPF none), the ~22% reduction does cross the LIKELY_MALICIOUS → SUSPICIOUS threshold. Tightening the dampener further would risk demoting genuine spoofing cases — see the constant's docstring in `scoring.py`.

### Example: legitimate Amazon order

An email from `amazon.com` with SPF/DKIM/DMARC pass, real URLs, no manipulative language:

```
No signals emitted → score = 0.0
Verdict = SAFE ✓
```

---

## Blind Spots (user-facing label: "Limitations")

Every detection system has known gaps. Ours are modeled as `BlindSpot` domain objects and reported alongside verdicts, so the user sees the **scope of the check**, not just the verdict. The Gmail Add-on surfaces them under the heading **Limitations** — phrased as factual disclosures of what was not done, deliberately *not* as findings against the email.

| Blind spot | When reported | What was not checked (user-facing copy) | Status |
|---|---|---|---|
| `ATTACHMENT_CONTENT` | Email has attachments | Only attachment metadata (name, size, type) was checked — file contents were not opened or scanned | Emitted by AttachmentAnalyzer |
| `URL_DESTINATION` | Email has URLs | URLs were detected, but destination pages were not fetched or verified | Emitted by UrlStructureAnalyzer |
| `AUTHENTICATION_HEADERS` | Authentication-Results header absent, OR a method returned `none` (no policy published) / `temperror` (transient lookup failure) | SPF, DKIM, and DMARC were not evaluated for this email — different from a `fail`, which means we *did* evaluate and it failed | Emitted by AuthenticationAnalyzer |
| `SENDER_IDENTITY` | The From address could not be parsed (no `@`, empty domain, malformed) | All sender-identity checks (cousin domain, reply-to mismatch) were skipped. A verdict of SAFE on a malformed From should not be read as "the sender looks fine" | Emitted by SenderAnalyzer |
| `THREAD_HISTORY` | Always | Only this email was analyzed — surrounding thread context was not considered | Emitted by engine |
| `EMBEDDED_IMAGE` | Email has inline images or image attachments | Image contents were not extracted — any text or QR codes inside images were not read | Emitted by engine |
| `QR_CODE` | (reserved) | QR codes inside images were not decoded — image processing is out of scope | Defined in the `BlindSpotArea` enum but not emitted yet — image-content inspection (OCR / QR decoding) is a future extension. The `EMBEDDED_IMAGE` blind spot above already covers the user-facing "we did not look inside images" message |
| `HTML_RENDERING` | Email has HTML body | The message was not rendered as a browser would display it, so CSS- or script-driven content was not evaluated | Emitted by engine |
| `LANGUAGE_ASSESSMENT` | Language Assessment analyzer is disabled, the local SLM is unreachable, or its response failed schema or evidence-grounding validation | Social-engineering language (paraphrased urgency, credential solicitation, authority impersonation, financial lure) could not be assessed for this email | Emitted by LanguageAssessmentAnalyzer |

Reporting limitations is a deliberate design choice: a verdict of SAFE with three limitations means something different than SAFE with zero. Phrasing them as scope ("what was not done") rather than risk ("what could go wrong") keeps them honest without alarming the user about every email.
