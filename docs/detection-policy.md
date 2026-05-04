# Static Analysis Detection Policy

## Scope

This system detects **mass phishing** using **static analysis only** — no sandboxing, no external API calls, no ML models. Every indicator is extracted from the email as received: headers, sender address, body text/HTML, and attachment metadata.

### Why mass phishing

Email threats span a wide spectrum: mass phishing, spear phishing, BEC (business email compromise), malware delivery, credential harvesting, and spam/scam. We focus on mass phishing because:

- **Detectable statically** — mass phishing relies on repeatable patterns (spoofed domains, urgency language, deceptive links) rather than personalized social engineering.
- **High coverage** — mass phishing accounts for the majority of phishing volume. A system that handles it well addresses the most common real-world threat.
- **Bounded complexity** — other threat types require capabilities beyond static analysis (user profiling for spear phishing, sandbox execution for malware, organizational context for BEC). Scoping to mass phishing keeps the system focused and honest about its boundaries.

### Why static analysis only

Static analysis means we examine the email artifact as-is, without network calls, URL resolution, or file execution. This gives us:

- **No external dependencies** — the engine runs anywhere, with no API keys, rate limits, or availability concerns.
- **Deterministic results** — same email always produces the same verdict, which makes testing and debugging straightforward.
- **Fast execution** — no I/O waits, suitable for real-time Gmail Add-on UX.

The cost: we cannot resolve shortened URLs, check domain age via WHOIS, scan attachments in a sandbox, or query threat intelligence feeds. The architecture supports these via the `ThreatIntelSource` ABC, but they are out of scope for the initial implementation.

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

These indicators check whether the sending infrastructure is authorized by the claimed domain. Authentication failures are the foundation of phishing detection — they prove the sender is not who they claim to be.

| ID | Indicator | What it detects | Severity | Signal strength | FP risk | Implementation notes |
|---|---|---|---|---|---|---|
| **AUTH-1** | SPF failure (`fail` / `softfail` / `permerror`) | Sending server not authorized by domain's DNS, or SPF record is malformed | HIGH (`fail`), HIGH (`softfail` @ 0.7 conf), LOW (`permerror`) | Strong for `fail`, moderate for `softfail`, weak for `permerror` | Low for `fail`; moderate for `softfail` (forwarders); high for `permerror` (often misconfig) | Parse `Authentication-Results` header for `spf=<result>` |
| **AUTH-2** | DKIM failure (`fail` / `permerror` / `policy`) | Message signature invalid, key record malformed, or signature doesn't meet local policy | HIGH (`fail`), LOW (`permerror`), MEDIUM (`policy`) | Strong for `fail`, weak for `permerror`/`policy` | Low for `fail`; moderate for others (mailing lists break DKIM, key rotation causes `permerror`) | Parse `Authentication-Results` for `dkim=<result>` |
| **AUTH-3** | DMARC failure (`fail` / `permerror`) | Domain's own policy says this message is unauthorized, or DMARC record is malformed | CRITICAL (`fail`), LOW (`permerror`) | Very strong for `fail` | Very low for `fail` — domain owner explicitly configured this | Parse `Authentication-Results` for `dmarc=<result>` |

**Why DMARC is CRITICAL while SPF/DKIM are HIGH**: DMARC is a policy decision by the domain owner — a DMARC fail means the sender's own domain is rejecting this message. SPF and DKIM are infrastructure checks that can fail for operational reasons (forwarding breaks SPF, mailing lists break DKIM). DMARC synthesizes both and adds owner intent.

**Attenuation note**: SPF, DKIM, and DMARC failures are correlated — a spoofed email typically fails all three. The scoring algorithm's within-category attenuation (÷1.6 per additional signal) prevents triple-counting. Three auth failures contribute roughly the same as 1.9 individual failures, not 3.0.

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
| **SENDER-2** | Free provider with org display name | "Bank of America" \<boa.security@gmail.com\> | MEDIUM | Moderate | Moderate — individuals legitimately use free email with business names | Check if From domain is a known free provider (gmail, yahoo, outlook, protonmail, …) while display name contains organizational keywords |
| **SENDER-3** | From ≠ Reply-To mismatch | Response directed to a different address | HIGH | Strong | Moderate — legit mailing lists sometimes use different Reply-To | Flag when Reply-To domain differs from From domain. Suppressed when (a) both share the same registered organization (e.g. `support@mail.acme.com` ↔ `acme.com`), (b) the Reply-To is a known ESP, or (c) the From is a freemail provider — personal mail routinely sets a different reply address and flagging it would be too noisy |
| **SENDER-4** | Return-Path ≠ From domain | Bounce address points to a different domain than the sender | MEDIUM | Moderate | Moderate — ESPs (SendGrid, SES) use their own Return-Path | Flag when Return-Path domain differs from From domain. Suppressed when both share the same registered organization or when Return-Path is a known ESP |
| **SENDER-5** | Display name impersonation | "PayPal Security" \<user@random.com\> — display name claims a brand the domain doesn't own | HIGH | Strong — display name is the first thing users see | Low | Extract identity tokens from the display name (filtering out role/title noise like "Security", "Support", "Team"), then collect every token that matches the curated brand list. Emit a signal only if **none** of the claimed brands resolves to the sender's registered domain — so "Microsoft Apple" sent from `apple.com` is treated as legitimate Apple mail, not Microsoft impersonation. The same regional-TLD allowlist used by SENDER-1 applies here. Defers to SENDER-1: if a cousin domain is already detected, this signal is suppressed to avoid double-counting one impersonation as two |

**Why cousin domain is CRITICAL**: Unlike authentication failures (which could be misconfiguration), a cousin domain like `paypa1-support.com` is almost never accidental. It represents deliberate, premeditated impersonation — the attacker registered lookalike infrastructure. A single cousin domain detection should push the score into LIKELY_MALICIOUS territory on its own (CRITICAL = 35 base points, threshold = 35).

**Why display name impersonation is HIGH, not CRITICAL**: Setting a display name to "PayPal" costs nothing — any mail client can do it. It's strong evidence of deception but weaker than cousin domain infrastructure. When both are present, only the cousin domain fires (the stronger signal subsumes the weaker one).

### URL_STRUCTURE category

These indicators analyze links in the email body without following them.

| ID | Indicator | What it detects | Severity | Signal strength | FP risk | Implementation notes |
|---|---|---|---|---|---|---|
| **URL-1** | href ≠ display text mismatch | Link text says "paypal.com" but href points elsewhere | CRITICAL | Very strong — deliberate deception | Very low — legit emails wont probably do this | Parse HTML `<a>` tags, extract href and inner text. If inner text looks like a URL (contains a dot and no spaces), compare its domain against the href domain |
| **URL-2** | IP-literal host in URL | `http://192.168.1.100/verify`, `http://[::1]/verify` | HIGH | Strong — legitimate services use domain names | Low | Parse the URL host and validate it with `ipaddress.ip_address` (covers IPv4 and IPv6) |

**Why URL mismatch is CRITICAL**: This is the single strongest phishing indicator. When a link displays "www.paypal.com" but the href points to an IP address or unrelated domain, there is probably no innocent explanation. Combined with a cousin domain (SENDER-1), this produces convergent evidence across two categories, triggering the cross-category boost.

**What this category does not flag**: shortened URLs (bit.ly, tinyurl.com, t.co) and high link counts are intentionally excluded — see "Deferred Indicators" for the reasoning. The destination question they gesture at is already represented as the `URL_DESTINATION` blind spot.

### BODY_CONTENT category

These indicators analyze the textual content for manipulation patterns.

| ID | Indicator | What it detects | Severity | Signal strength | FP risk | Implementation notes |
|---|---|---|---|---|---|---|
| **CONTENT-1** | Urgency/threat language | "suspended within 24 hours", "immediate action required" | MEDIUM | Moderate — pressure tactics are a phishing hallmark | High — legit services also send deadline notices | Keyword/phrase pattern matching against a curated urgency dictionary. MEDIUM severity specifically because of FP risk — this should support a verdict, not drive it |
| **CONTENT-2** | Sensitive data request | "verify your password", "confirm SSN", "update payment" | HIGH | Strong — legit services explicitly state they never ask for this via email | Low | Keyword matching for credential/financial/identity terms in request context |
| **CONTENT-3** | HTML form in email body | Inline `<form>` with `<input>` fields | CRITICAL | Very strong — almost never appears in legitimate email | Very low | Search HTML body for `<form>` tags containing input elements |

**Why urgency is only MEDIUM**: Urgency language has the highest false-positive risk of any included indicator. Legitimate services routinely send "your trial expires in 3 days" or "payment due by Friday". However, urgency is a **supporting signal** — it almost always co-occurs with stronger indicators in actual phishing. The scoring algorithm handles this correctly: MEDIUM = 12 base points (never enough to cross SUSPICIOUS alone at 15), but it amplifies a verdict when combined with auth failures or URL mismatches.

### ATTACHMENT category

These indicators examine attachment metadata without opening or executing files.

| ID | Indicator | What it detects | Severity | Signal strength | FP risk | Implementation notes |
|---|---|---|---|---|---|---|
| **ATTACH-1** | Dangerous file extension | .exe, .scr, .bat, .cmd, .ps1, .vbs, .js, .msi, .com, .pif, .hta, .wsf, .cpl, .reg, .html, .htm | CRITICAL | Very strong — these file types have no legitimate reason to arrive via email in most contexts | Very low | Check attachment filename extension against a curated dangerous-extensions list |
| **ATTACH-2** | Double extension | `invoice.pdf.exe` — masquerading as a safe file type | CRITICAL | Very strong — always deliberate deception | Very low | Check if filename contains multiple extensions where the final one is dangerous |
| **ATTACH-3** | Macro-enabled Office format | .docm, .xlsm, .pptm, .dotm, .xltm, .potm — Office files with macros | HIGH | Strong — macro malware is a primary delivery vector | Moderate — some organizations still use macro-enabled templates | Check extension against macro-enabled Office MIME types |
| **ATTACH-4** | Password-protected archive | Encrypted .zip/.rar mentioned in body | HIGH | Strong — used to evade scanning | Moderate — legit confidential docs use this too | Check for archive MIME types combined with body text mentioning "password" near attachment references |

---

## Deferred Indicators (with reasoning)

These indicators were evaluated and intentionally excluded from the initial scope. Each exclusion has a specific technical reason, not just "out of scope."

| Indicator | Why deferred | What would be needed |
|---|---|---|
| **Received chain analysis** | The Received header format is not standardized — each MTA writes it differently. Parsing is fragile and produces unreliable results. Effort-to-value ratio is poor | A robust multi-format parser with per-MTA heuristics |
| **Domain age** | Requires WHOIS or RDAP lookup — an external network call that violates our static-analysis constraint | `ThreatIntelSource` implementation with WHOIS/RDAP client |
| **URL destination check** | Requires HTTP requests to follow redirects — violates static-analysis constraint and introduces latency | `ThreatIntelSource` implementation with Safe Browsing API |
| **Obfuscated HTML** | Base64-encoded sections, CSS tricks to hide text. Detecting these requires rendering or deep HTML analysis. Moderate effort for low commonality | HTML rendering engine or heuristic decoder |
| **NLP tone analysis** | ML-based content classification. Entirely different system — requires training data, model serving, and introduces non-determinism | Trained classifier, inference infrastructure |
| **QR code phishing** | Embedded QR codes pointing to malicious URLs. Requires image parsing — not available in static text analysis | Image processing library, QR decoder |
| **Shortened URL detection** | Shorteners (bit.ly, t.co, tinyurl.com) hide the destination, but legitimate marketing, social media, and CRM tooling use them constantly. As a standalone signal the FP rate is too high to defend; the destination question it raises is already represented by the `URL_DESTINATION` blind spot, and is properly resolved by following the link in a sandbox or threat-intel service rather than by host-list matching | A `ThreatIntelSource` that resolves shorteners (or a Safe Browsing query on the resolved URL) |
| **Link volume / excessive URL count** | Counting unique link domains is metadata, not evidence. As an INFO-severity signal it contributed 0 points to the score while still appearing in the findings list — pure noise. If link volume ever becomes useful it will be as an input to a stronger composite signal, not as a finding on its own | A composite scoring rule that combines link volume with content or sender heuristics |

---

## How Indicators Map to the Scoring Algorithm

The scoring algorithm (defined in `scoring.py`) enforces the relationships described above:

### Severity → base points

| Severity | Points | Design rationale |
|---|---|---|
| INFO | 0 | Appears in report, never affects score |
| LOW | 5 | Supporting signal — needs corroboration |
| MEDIUM | 12 | Notable but not alarming alone |
| HIGH | 22 | Serious finding — two from different categories cross SUSPICIOUS |
| CRITICAL | 35 | One alone reaches LIKELY_MALICIOUS |

### Score accumulation safeguards

- **Within-category attenuation (÷1.6^k)**: Prevents correlated signals from stacking. Three AUTH failures ≈ 1.9× one failure, not 3×.
- **Category cap (50 pts)**: No single category can dominate. Five auth failures cannot push past LIKELY_MALICIOUS without evidence from another category.
- **Cross-category boost (+8% per extra category)**: Rewards convergent evidence. Auth failure + URL mismatch + urgency language = 3 categories = +16% boost.

### Verdict thresholds

| Score range | Verdict | What it means |
|---|---|---|
| 0–14 | SAFE | No significant indicators detected |
| 15–34 | SUSPICIOUS | Some indicators present — review recommended |
| 35–64 | LIKELY_MALICIOUS | Strong evidence from one or more categories |
| 65–100 | MALICIOUS | Convergent evidence across multiple categories |

### Example: mass phishing email scoring path

An email from `paypa1-support.com` with SPF/DKIM/DMARC fail, a deceptive URL, and urgency language:

```
AUTHENTICATION:
  DMARC fail     → CRITICAL (35.0) ÷ 1.6^0 = 35.0
  SPF fail       → HIGH    (22.0) ÷ 1.6^1 = 13.75
  DKIM fail      → HIGH    (22.0) ÷ 1.6^2 =  8.59
  Category total = 57.34 → capped at 50.0

SENDER_IDENTITY:
  Cousin domain  → CRITICAL (35.0) ÷ 1.6^0 = 35.0

URL_STRUCTURE:
  IP in URL      → HIGH    (22.0) ÷ 1.6^0 = 22.0

BODY_CONTENT:
  Urgency        → MEDIUM  (12.0) ÷ 1.6^0 = 12.0

Raw total = 50.0 + 35.0 + 22.0 + 12.0 = 119.0
Active categories = 4 → boost = 1 + 0.08 × 3 = 1.24
Final = 119.0 × 1.24 = 147.56 → clamped to 100.0
Verdict = MALICIOUS ✓
```

### Example: legitimate Amazon order

An email from `amazon.com` with SPF/DKIM/DMARC pass, real URLs, no urgency:

```
No signals emitted → score = 0.0
Verdict = SAFE ✓
```

---

## Blind Spots

Every detection system has known gaps. Ours are documented as `BlindSpot` domain objects and reported alongside verdicts, so the user knows what the system *didn't* check.

| Blind spot | When reported | Risk | Status |
|---|---|---|---|
| `ATTACHMENT_CONTENT` | Email has attachments | We check metadata (extension, MIME) but not file content — a .pdf could contain malicious JavaScript | Emitted by AttachmentAnalyzer |
| `URL_DESTINATION` | Email has URLs | We check URL structure but don't follow links — a clean-looking domain could redirect to a phishing page | Emitted by UrlStructureAnalyzer |
| `AUTHENTICATION_HEADERS` | Authentication-Results header absent, OR a method returned `none` (no policy published) / `temperror` (transient lookup failure) | We cannot evaluate that authentication mechanism — different from a `fail`, which means we *did* evaluate and it failed | Emitted by AuthenticationAnalyzer |
| `SENDER_IDENTITY` | The From address could not be parsed (no `@`, empty domain, malformed) | All sender-identity checks (cousin domain, display-name impersonation, reply-to and return-path mismatch) were skipped. A verdict of SAFE on a malformed From should not be read as "the sender looks fine" | Emitted by SenderAnalyzer |
| `THREAD_HISTORY` | Always | We analyze the single message, not the conversation thread — a reply to a legitimate thread is harder to identify as phishing | Emitted by engine |
| `EMBEDDED_IMAGE` | Email has inline images or image attachments | Images could contain QR codes or text designed to bypass text-based analysis | Emitted by engine |
| `QR_CODE` | Email has inline images or image attachments | QR codes in images can encode phishing URLs — undetectable without image processing | Emitted by engine |
| `HTML_RENDERING` | Email has HTML body | We parse HTML structure but don't render it — CSS tricks could hide or show content selectively | Defined in enum, not yet emitted |

Reporting blind spots is a deliberate design choice: a verdict of SAFE with three blind spots means something different than SAFE with zero. The consumer (Gmail Add-on UI) can display these to help the user make informed decisions.
