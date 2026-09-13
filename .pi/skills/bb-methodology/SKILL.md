---
name: bb-methodology
description: "Use at the START of any bug bounty hunting session, when switching targets, or when feeling lost about what to do next. Master orchestrator that combines the 5-phase non-linear hunting workflow with the critical thinking framework (developer psychology, anomaly detection, What-If experiments). Routes to all other skills based on current hunting phase. Also use when asking \"what should I do next\" or \"where am I in the process. Use with IDA Pro via ida_mcp (triage-first, escalate per ladder)."
compatibility: "IDA Pro 8.3+ with the ida_mcp plugin (Hex-Rays for decompiler tools)"
metadata:
  workflow: "ida-pro-mcp-lazy"
  ceiling: "?profile=readonly"
---

> **IDA-MCP adapter (read first).** This skill runs against the binary open in IDA Pro through ida_mcp.
> Start at `?profile=triage` (`server_health` → `survey_binary`), escalate top-down; ceiling for this skill: **`?profile=readonly`** — read-only ceiling — start at `?profile=triage`.
> Never request unsafe/dbg "just in case" — justify each escalation in one sentence. All addresses accept hex/symbol/dec; `decompile_function` returns plain text, everything else JSON.

All tool calls below are native ida_mcp tools.

---

# Bug Bounty Methodology: Workflow + Mindset

Master orchestrator for hunting sessions. Combines the 5-phase non-linear workflow with the critical thinking framework that separates top 1% hunters from the rest.

---

## PART 1: MINDSET (How to Think)

### Core Principle

Hunting is not "find a bug" -- it is "prove an attack scenario." Think like an attacker with a specific goal, not a scanner looking for patterns.

### Daily Discipline: Define, Select, Execute

Before touching any tool:

1. **Define**: "Today I target [feature/domain] to achieve [CIA impact]"
2. **Select**: Choose 1-2 vuln classes (IDOR, Race Condition, etc.)
3. **Execute**: Focus ONLY on selected techniques. No wandering.

### 5 Ultimate Goals (Pick One Per Session)

1. **Confidentiality** -- steal data the attacker shouldn't see
2. **Integrity** -- modify data the attacker shouldn't change
3. **Availability** -- disrupt service (app-level DoS only)
4. **Account Takeover** -- control another user's account
5. **RCE** -- execute commands on the server

### 4 Thinking Domains

#### 1. Critical Thinking (deep analysis)

**Question trust boundaries:**
- Frontend control disabled? Send request directly via proxy
- `user_role=user` cookie? Change to `admin`
- `price=1000` in POST? Change to `1`
- `<script>` blocked? Try `<img onerror=...>`

**Reverse-engineer developer psychology:**
- Feature A has auth checks -> Similar feature B (newly added) probably doesn't
- Complex flows (coupon + points + refund) -> Edge cases have bugs
- `/api/v2/user` exists -> Does `/api/v1/user` still work with weaker auth?

**What-If experiments:**
- Skip checkout -> hit `/checkout/success` directly
- Skip 2FA -> navigate to `/dashboard`
- Send coupon request 10x simultaneously -> Race condition?
- Replace `guid=f8a2...` with `id=100` on sibling endpoint -> IDOR?

#### 2. Multi-Perspective (multiple angles)

| Perspective | What to check |
|------------|---------------|
| Horizontal (same role) | User A's token + User B's ID -> IDOR |
| Vertical (different role) | Regular user -> `/admin/deleteUser` |
| Data flow (proxy view) | Hidden params in JSON: `debug=false`, `discount_rate` |
| Time/State | Race conditions, post-delete session reuse |
| Client environment | Mobile UA -> legacy API with weaker auth |
| Business impact | "What's the $ damage if this breaks?" |

#### 3. Tactical Thinking (pattern detection)

- **Naming anomaly**: `userId` everywhere but suddenly `user_id` -> different dev, weaker security
- **Error diff**: Same 403 but different JSON structure -> different backend systems
- **Environment diff**: Prod vs Dev/Staging -> debug headers, CSP disabled
- **Version diff**: JS file before/after update -> new endpoints, removed params
- **Supply chain**: Check framework/library versions for known CVEs
- **Third-party integration**: Stripe/Auth0/Intercom -> webhook signature missing?

#### 4. Strategic Thinking (big picture)

- **Asymmetry**: Defender must patch ALL holes. You only need ONE.
- **Intuition engineering**: Log why something "feels wrong." Verify later. Update mental DB.
- **Unknown management**: Can't understand something? Add to "investigate later" list. Just-in-Time Learning.

### Amateur vs Pro: 7-Phase Comparison

| Phase | Amateur | Pro |
|-------|---------|-----|
| Recon | Main domain only | Shadow IT, dev environments, all assets |
| Discovery | Look for errors | Look for design contradictions, business logic flaws |
| Exploit | Give up when blocked | Build filter-bypass payloads |
| Escalation | Report the phenomenon only | Chain to real harm (session steal, ATO) |
| Feasibility | Include unrealistic conditions | Minimize attack prerequisites |
| Reporting | State facts only | Quantify business risk |
| Retest | Check if old PoC fails | Analyze fix method, find incomplete patches |

### Two Approach Routes

- **Route A (Feature-based)**: "This feature is complex" -> deep-dive its input handling -> find vuln
- **Route B (Vuln-based)**: "I want IDOR" -> find endpoints with sequential IDs -> test access control

### Anti-Patterns (Stop Doing These)

- **Program hopping**: Stick with one target minimum 2 weeks / 30 hours
- **Tool-only hunting**: Automation finds duplicates. Manual testing finds unique bugs.
- **Rabbit hole**: Max 45 min per parameter. Set a timer. If stuck, sleep on it.
- **No goal**: "Just looking around" = wasted time. Always Define first.

---

## PART 1.5: ZERO-DAY HUNTING MINDSET (Novel Vulnerabilities)

### Known vs Novel: The Critical Distinction

**Known vulnerabilities (N-day)** = Patterns already documented, tools exist, checklists work
**Novel vulnerabilities (0-day)** = No pattern exists, must discover NEW attack vectors

> **Rule of thumb**: If you can find it with a checklist or automated scanner, someone else already found it. To get 0-day, you must think DIFFERENTLY.

### The 0-Day Discovery Framework

```
┌─────────────────────────────────────────────────────────────┐
│                    ZERO-DAY DISCOVERY                        │
├─────────────────────────────────────────────────────────────┤
│  1. ASSUMPTION BREAKING                                      │
│     "What do developers ASSUME can't happen?"                │
│     → Test the opposite                                       │
├─────────────────────────────────────────────────────────────┤
│  2. DESIGN CONTRADICTION                                     │
│     "Where does the design conflict with implementation?"      │
│     → Find the gap                                            │
├─────────────────────────────────────────────────────────────┤
│  3. UNTESTED COMBINATIONS                                    │
│     "What happens when Feature A + Feature B interact?"       │
│     → Feature interaction bugs                                │
├─────────────────────────────────────────────────────────────┤
│  4. PROTOCOL VIOLATION                                       │
│     "What if I break the expected protocol?"                  │
│     → State machine abuse                                     │
├─────────────────────────────────────────────────────────────┤
│  5. IMPLEMENTATION DETOURS                                   │
│     "Where did the developer take a shortcut?"               │
│     → Corner cases, error paths, race conditions              │
└─────────────────────────────────────────────────────────────┘
```

### Phase 1: ASSUMPTION BREAKING (The "Why" Method)

**Developer Assumptions → Attack Paths**

| Developer Assumes | Reality → 0-Day Path |
|-------------------|---------------------|
| "Auth middleware protects all endpoints" | Find the ONE endpoint that bypasses it |
| "Client validates input" | Send raw request bypassing UI |
| "API only accepts JSON" | Send XML, multipart, binary |
| "State transitions are linear" | Skip states, reverse flow, parallel requests |
| "Users only click one button at a time" | Race condition via concurrent requests |
| "Database transactions are atomic" | Find the non-transactional operation |
| "Secrets are server-side only" | Find client-side secret computation |
| "This endpoint is only for X" | Use it for Y (feature abuse) |

**Assumption Breaking Questions:**
1. "What validates input here?" → Test validation bypass
2. "What if this call fails?" → Test error handling paths
3. "What if two users do this simultaneously?" → Test race conditions
4. "What if the data changes mid-operation?" → Test TOCTOU bugs
5. "What if I send the WRONG content-type?" → Test parser confusion
6. "What if I NEVER respond to a challenge?" → Test state exhaustion
7. "What if I replay an old message?" → Test replay attacks

### Phase 2: DESIGN CONTRADICTION (The Gap Finder)

**Where Design ≠ Implementation = Vulnerability**

```
Design: "User can only upload images"
Implementation: "We check file extension"
0-Day: Upload .php.jpg → extension check passes, but PHP executes
```

**Design Contradiction Patterns:**

| Design Statement | Implementation | The Gap | 0-Day Exploit |
|-----------------|----------------|---------|----------------|
| "Sessions expire after logout" | `session_destroy()` only | Cookie remains valid | Replay session token |
| "Admin can only be promoted by owner" | Check in UI, not API | API has no check | Direct API call |
| "API rate limited to 100 req/min" | Per-user limiting | No limit on unauth endpoints | Unauth endpoint abuse |
| "File paths are sandboxed" | String prefix check | Path traversal via `../` | Directory traversal |
| "Tokens are single-use" | No server tracking | Token never invalidated | Token replay |
| "Payment requires 2FA" | 2FA after payment hold | Payment captured first | Race condition |

**Design Contradiction Discovery Process:**
1. Read documentation → Find security guarantees
2. Read implementation code → Find actual enforcement
3. Identify gaps → Exploit the difference
4. Document the contradiction → Prove with PoC

### Phase 3: UNTESTED COMBINATIONS (Feature Interaction)

**Single Feature: Usually Secure. Two Features Together: Vulnerable.**

```
Feature A: "Users can export their data as CSV"
Feature B: "Admins can import CSV to bulk-create users"
Combination: Regular user → Export → Manipulate → Import as admin = Privilege Escalation
```

**Feature Interaction Matrix:**

| Feature A + Feature B | Potential 0-Day |
|----------------------|-----------------|
| Export + Import | Data exfil, injection, privilege escalation |
| Share + Edit | Access control bypass |
| Webhook + Email | SSRF via email payload |
| OAuth + Legacy Auth | Token theft via downgrade |
| Mobile App + Web API | Different auth implementations → bypass |
| Caching + Personalization | Cache poisoning → user data leak |
| Async Processing + Callback | Race condition, TOCTOU |
| File Upload + File Processing | XXE via uploaded XML, template injection |

**Feature Interaction Testing:**
1. Map all features in the application
2. Create a matrix: Feature A vs Feature B
3. Ask: "What if A's output becomes B's input?"
4. Test the combination
5. Document the new attack surface

### Phase 4: PROTOCOL VIOLATION (State Machine Abuse)

**Protocols assume certain sequences. Break the sequence.**

```
Expected: Register → Verify Email → Login
Violated: Register → (skip verify) → Login → (verify) → Login again
Result: Session before email verified, session after too = 2 sessions
```

**Protocol Violation Types:**

| Violation | Example | 0-Day Impact |
|-----------|----------|---------------|
| State skip | `/dashboard` without login | Auth bypass |
| State reversal | `cancel` → `pay` | Double spend |
| Parallel states | 5x simultaneous password reset | Rate limit bypass |
| State confusion | Mobile API state ≠ Web state | Inconsistent auth |
| State replay | Old JWT used after revocation | Session persistence |
| State rollback | Downgrade API version | Legacy vuln access |

**Protocol Violation Testing:**
```bash
# 1. Request every endpoint in random order
for endpoint in $(cat endpoints.txt); do
  curl -s "https://target.com$endpoint" -H "Auth: expired_token"
done

# 2. Request with every HTTP method regardless of endpoint
for method in GET POST PUT PATCH DELETE OPTIONS TRACE; do
  curl -s -X $method "https://target.com/api/user"
done

# 3. Send requests in parallel (race condition)
seq 1 50 | xargs -P 50 -I {} curl -s "https://target.com/api/reset"

# 4. Replay old requests at different times
cat old_requests.txt | while read req; do
  echo "$req" | curl -X POST -d @- "https://target.com/api"
done
```

### Phase 5: IMPLEMENTATION DETOURS (Corner Case Hunting)

**Developers take shortcuts. Corners are cut. Bugs hide there.**

**Corner Case Categories:**

1. **Error Handling Paths**
   - What happens when DB connection fails mid-transaction?
   - What happens when file upload is interrupted?
   - What happens when external API times out?
   - What happens when memory allocation fails?

2. **Boundary Conditions**
   - Maximum filename length → Buffer overflow
   - Maximum nested depth → Stack overflow
   - Maximum concurrent requests → Resource exhaustion
   - Maximum file size → Chunked upload bypass

3. **Edge Cases**
   - Empty strings, null values, zero-length arrays
   - Unicode normalization issues (`%E2%84%AA` = `Å` = `Å`)
   - Time zone changes, daylight saving transitions
   - Leap years, leap seconds (Dec 31, 23:59:60)

4. **Race Conditions**
   ```python
   # VULNERABLE PATTERN:
   if not user_exists(username):  # Check
       create_user(username)  # Act

   # Thread 1: Check passes
   # Thread 2: Check passes (same username)
   # Thread 1: Create user
   # Thread 2: Create user (duplicate! or overwrites)
   ```

5. **TOCTOU (Time-of-Check-Time-of-Use)**
   - File permission check → File open (time gap = exploit window)
   - Balance check → Withdraw (time gap = double spend)
   - Auth verification → Resource access (time gap = privilege escalation)

### Zero-Day Code Audit Methodology

**Taint Analysis: Source → Sink**

```
┌─────────────────────────────────────────────────────────────┐
│                   TAINT ANALYSIS                            │
├─────────────────────────────────────────────────────────────┤
│  SOURCES (Attacker-Controlled Input)                       │
│  ├─ HTTP parameters (query, body, headers, cookies)       │
│  ├─ File uploads, webhooks, external API calls            │
│  ├─ Database results (if polluted by prior input)          │
│  └─ Environment variables, config files                    │
│                        │                                    │
│                        ▼ (follow the data)                │
│                    [DATA FLOW]                             │
│                        │                                    │
│                        ▼                                    │
│  SINKS (Dangerous Operations)                              │
│  ├─ SQL execution, system commands, file operations        │
│  ├─ Eval, template rendering, deserialization              │
│  ├─ Redirects, includes, require                          │
│  └─ External requests, email sending                      │
└─────────────────────────────────────────────────────────────┘
```

**Manual Taint Analysis Steps:**
1. Identify all SOURCES in the codebase
2. Trace data flow from each source
3. Check if data reaches a SINK without sanitization
4. Document the vulnerability path
5. Create PoC exploiting the path

**Grep Patterns for Dangerous Code:**

```bash
# PHP - Find eval/exec sinks
grep -rn "eval\|exec\|system\|passthru\|shell_exec\|assert\|preg_replace.*e.*"

# JavaScript - Find dangerous sinks
grep -rn "innerHTML\|eval\|setTimeout.*string\|setInterval.*string"

# Python - Find pickle/unpickle
grep -rn "pickle\.loads\|cPickle\|marshal\.loads"

# Ruby - Find YAML.load (vulnerable)
grep -rn "YAML\.load[^_]\|Marshal\.load"

# Java - Find deserialization
grep -rn "ObjectInputStream\|XMLDecoder\|XStream"

# Go - Find template rendering
grep -rn "template\.Execute\|template\.HTML"

# All languages - Find SQL queries with concatenation
grep -rnE '(\+|\.\||concat|format).*\$(REQUEST|GET|POST|cookie)'
```

### Zero-Day Discovery Checklist

Before testing known vuln classes, ask:

- [ ] **Assumption Breaking**: What do developers assume that's not true?
- [ ] **Design Contradiction**: Where does design ≠ implementation?
- [ ] **Feature Interaction**: What if Feature A + Feature B combine?
- [ ] **Protocol Violation**: Can I break the expected request sequence?
- [ ] **Corner Cases**: Error paths, boundaries, race conditions, TOCTOU?
- [ ] **Taint Analysis**: Does attacker input reach dangerous operations?
- [ ] **Source Code**: Have I audited the actual implementation?

### Zero-Day vs N-Day Decision Flow

```
                    ┌─────────────────┐
                    │  START HUNTING  │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │ READ SOURCE CODE │
                    └────────┬────────┘
                             │
                ┌────────────▼────────────┐
                │ Can I audit the code?   │
                └────────────┬────────────┘
                             │
              ┌──────────────┴──────────────┐
              │ YES                         │ NO
              ▼                             ▼
    ┌──────────────────┐         ┌──────────────────┐
    │ TAINT ANALYSIS   │         │ PROTOCOL FUZZING  │
    │ Follow data flow │         │ Break sequences   │
    │ Source → Sink   │         │ State machine ab. │
    └──────────┬───────┘         └──────────┬───────┘
               │                            │
               └────────────┬───────────────┘
                            │
                    ┌───────▼────────┐
                    │ Found novel    │
                    │ vuln pattern? │
                    └───────┬────────┘
                            │
              ┌─────────────┴─────────────┐
              │ YES                       │ NO
              ▼                           ▼
     ┌──────────────────┐      ┌──────────────────┐
     │ ZERO-DAY FOUND  │      │ Fall back to     │
     │ (novel pattern) │      │ N-Day checklist  │
     └──────────────────┘      └──────────────────┘
```

### Zero-Day Report Template

When you find a novel vulnerability, your report must explain WHY it's novel:

```
## Why This Is Novel

[1-2 paragraphs explaining what makes this vulnerability unique]

### Not Previously Documented Because:
- [ ] The vulnerability requires combining [Feature A] + [Feature B]
- [ ] The attack exploits [specific design contradiction]
- [ ] The vulnerability exists in [unusual code path]
- [ ] Standard scanners/tools miss this because [reason]

### Attack Scenario:
[Concrete scenario showing real-world impact]

### Proof of Concept:
[Detailed, reproducible steps]
```

---

## PART 2: WORKFLOW (What to Do)

### The 5-Phase Non-Linear Flow

```
+-------------------------------------------------+
|                                                 |
|  +----------+    +----------+    +----------+   |
|  | 1. RECON |---+| 2. MAP   |---+| 3. FIND  |  |
|  +----------+    +-----+----+    +-----+-----+  |
|       ^                |               |         |
|       |                v               v         |
|       |          +----------+    +----------+    |
|       +----------| 4. PROVE |---+| 5. REPORT|   |
|                  +----------+    +----------+    |
|                                                  |
|  Non-linear: stuck at any phase -> go back       |
|  New API found at phase 3 -> return to phase 2   |
|  WAF blocks at phase 4 -> origin IP from phase 1 |
+-------------------------------------------------+
```

**THIS IS NOT LINEAR.** Move freely between phases. When stuck, return to a previous phase.

### Phase 0: SESSION START (Every Time)

**Before touching any tool, answer these:**

1. **Define**: "Today I target [feature/domain] to achieve [C/I/A/ATO/RCE]"
2. **Select**: Choose 1-2 vuln classes (IDOR, XSS, SSRF, etc.)
3. **Execute**: Focus ONLY on selected techniques

**Route selection -- Wide or Deep?**

| Signal | Wide (recon sweep) | Deep (focused testing) |
|--------|-------------------|----------------------|
| New program, first day | X | |
| Wildcard scope `*.target.com` | X | |
| Main webapp, been here >3 days | | X |
| Scope update (new domain added) | X | |
| Found interesting subdomain | | X |

### Phase 1: RECON

**Goal**: Maximize attack surface. Find what others missed.

**Wide approach** (initial sweep):
```
Subdomain enum -> DNS resolution -> HTTP probing -> Port scan -> Tech detect
```

**Deep approach** (targeted):
```
Google Dorks -> JS file download -> Hidden param discovery -> API mapping
```

| What you find | Next action |
|--------------|-------------|
| Live subdomains with tech stack | Phase 2 (Mapping) |
| Known software (WordPress, Jira) | Check CVEs + defaults immediately |
| Cloud resources (S3, Firebase) | Test permissions (read/write/list) |
| Nothing after 5 min on a host | Skip, try next host (5-minute rule) |

**Command**: `/recon target.com`

### Phase 2: MAPPING & ANALYSIS

**Goal**: Understand the app like its developer does.

**Checklist:**
- [ ] Map all endpoints (Burp/Caido sitemap + JS analysis)
- [ ] Identify auth model (cookie, JWT, OAuth, SAML?)
- [ ] Find business-critical flows (payment, registration, password reset, data export)
- [ ] Download and analyze JS files for hidden routes, secrets, logic
- [ ] Identify roles and permissions (user, admin, API keys)
- [ ] Note "weird" behaviors (anomalies in naming, errors, timing)

| What you find | Next action |
|--------------|-------------|
| JS files with interesting code | Taint analysis (Sink -> Source) |
| OAuth/SAML authentication | OAuth/SAML checklist |
| API with ID parameters | Phase 3, target IDOR |
| Complex business logic (payment, coupon) | Phase 3, target BizLogic |
| postMessage listeners | DOM analysis, postMessage-tracker |

### Phase 3: VULNERABILITY DISCOVERY

**Goal**: Find the bug. Use Error-based first, then Blind-based.

**Decision flow based on what you're testing:**

```
What input are you testing?
+-- ID parameter (user_id, order_id)
|   -> IDOR checklist
+-- Search/filter/sort field
|   -> SQLi, NoSQLi probing
+-- URL input / webhook / PDF gen
|   -> SSRF checklist
+-- Text field reflected in page
|   -> XSS (DOM or reflected)
+-- File upload
|   -> SVG XSS, web shell, path traversal
+-- Price/quantity/coupon
|   -> Business logic, race conditions
+-- Login / 2FA / password reset
|   -> Auth bypass
+-- Profile update API
|   -> Mass Assignment
+-- Template / wiki editor
|   -> SSTI
+-- Nothing obvious
    -> Fuzz with ffuf, try Error-based probing
```

**Error vs Blind decision:**
1. Try Error-based first (send `'`, `"`, `{{7*7}}`, `${7*7}`) -- watch for 500 errors, stack traces
2. No error? Time-based (`SLEEP(10)`, `; sleep 10;`) -- watch response time
3. No time diff? OOB (`curl attacker.com`, interactsh) -- watch for DNS callback
4. Still nothing? Boolean (`AND 1=1` vs `AND 1=0`) -- watch content-length diff

| What you find | Next action |
|--------------|-------------|
| Low-impact behavior (redirect, self-XSS, cookie injection) | Chain it -- find a connector gadget |
| Confirmed vuln (XSS, IDOR, SQLi) | Phase 4 (Prove and Escalate) |
| Blocked by WAF/CSP/403 | Bypass techniques, then retry |
| Known software vuln (CVE) | 1-day speed workflow |
| Nothing after 20 min on this endpoint | Rotate (20-minute rule) |

### Phase 4: PROVE & ESCALATE

**Goal**: Prove maximum business impact. Turn Low into Critical.

**Escalation decision:**
```
What did you find?
+-- XSS
|   +-- Can steal cookie/token? -> Session hijack -> ATO
|   +-- Cookie is HttpOnly? -> Force email change via XHR -> ATO
|   +-- Self-XSS only? -> Find CSRF to trigger it
+-- IDOR
|   +-- Can read PII? -> Automate scraping, show scale
|   +-- Can change password/email? -> Direct ATO
|   +-- UUID only? -> Find UUID leak source, then retry
+-- SSRF
|   +-- DNS only? -> DON'T REPORT. Try cloud metadata
|   +-- Can reach 169.254.169.254? -> Extract keys -> RCE
|   +-- Internal port scan? -> Find Redis/K8s -> RCE
+-- SQLi
|   +-- Error-based? -> Extract data (passwords, tokens)
|   +-- Can INTO OUTFILE? -> Web shell -> RCE
|   +-- Blind? -> Boolean/Time extraction
+-- Open Redirect
|   +-- OAuth flow? -> Token theft -> ATO
|   +-- javascript: scheme? -> XSS
+-- Blocked by defense
|   -> Bypass (WAF/CSP/proxy/sanitizer/2FA)
+-- Low-impact, can't escalate alone
    -> Find connector gadget for chain
```

**After proving impact, check:**
- [ ] Can attack work with 0-1 clicks? (minimize prerequisites)
- [ ] Does it affect all users or specific role?
- [ ] What's the business $ impact?

### Phase 5: VALIDATE & REPORT

**Goal**: Get paid. Make triager's job easy.

**Pre-report gate:**
```
Run /validate (7-Question Gate)
+-- All 7 pass? -> Write report
+-- Any fail? -> KILL the finding. Don't waste time.
+-- Borderline? -> Run /triage for quick go/no-go
```

**Report:**
```
Run /report
+-- Platform-specific format (H1/Bugcrowd/Intigriti/Immunefi)
+-- Title: [Bug Class] in [Endpoint] allows [role] to [impact]
+-- Impact-first summary (sentence 1 = what attacker CAN do)
+-- Exact HTTP requests in Steps to Reproduce
+-- Under 600 words
+-- CVSS 3.1 score that MATCHES actual impact
```

**After submission:**
- [ ] While waiting for triage: try to escalate further (A->B signal method)
- [ ] If fix deployed: re-test for bypass (incomplete patch = new bug)
- [ ] Record finding with `/remember` for hunt memory

---

## PART 3: NAVIGATION & TIMING

### Non-Linear Navigation Quick Reference

| I'm stuck because... | Go to... |
|----------------------|----------|
| Can't find any subdomains | Phase 1: Try different recon sources, Google Dorks |
| Found subdomain but don't know what to test | Phase 2: Map the app, download JS, understand auth |
| Testing but nothing works | Phase 3: Switch vuln class (20-min rotation rule) |
| Found a bug but impact is low | Phase 4: Escalation paths or gadget chaining |
| WAF/CSP/403 blocking my payload | Bypass techniques, then return to current phase |
| Been stuck for 45 min on one param | STOP. Rabbit hole. Move to next endpoint. |
| New API endpoint discovered during testing | Return to Phase 2: map it before attacking |
| Found one bug | A->B signal: same dev made more mistakes. Hunt 20 min for siblings. |

### 20-Minute Rotation Clock

Every 20 minutes ask yourself: **"Am I making progress?"**
- Yes -> Continue
- No -> Rotate to next: endpoint -> subdomain -> vuln class -> target
- Been on same target 2+ weeks with no findings? -> Consider switching program

### Tool Routing by Phase

| Phase | Tools | Why this order |
|-------|-------|----------------|
| Recon: Subdomains | `subfinder` -> `amass` -> `puredns` -> `httpx` | Passive first (no detection) -> resolve DNS -> probe HTTP + tech stack |
| Recon: URLs | `gau` + `waymore` -> `katana` -> `uro` | Archive (forgotten endpoints) -> active crawl (JS-rendered) -> deduplicate |
| Recon: JS | `jsluice` + `mantra` + `trufflehog --only-verified` | Extract URLs/secrets -> find API keys -> verify keys actually work |
| Recon: Ports | `naabu` (wide) -> `rustscan` (deep) | Fast top-1000 sweep -> full 65535 on interesting targets |
| Recon: Scan | `nuclei -tags cve` -> `nuclei -tags takeover` | Known CVEs first -> then takeover (act immediately) |
| Mapping: Params | `arjun` + `paramspider` + ParamMiner | Brute-force hidden params + mine archives + cache headers |
| Mapping: JS code | Download -> `jsluice` -> VS Code/Cursor grep | Extract -> static analysis -> AI-assisted taint analysis |
| Mapping: Dorks | Manual Google Dorks | Custom per-target queries find what automation misses |
| Discovery: Fuzz | `ffuf -ac` + `cewl` custom wordlist | Auto-calibrate filtering + target-specific words beat generic lists |
| Discovery: XSS | `kxss` -> `dalfox` | Filter (which params reflect?) -> scan (only reflective params) |
| Discovery: SQLi | `ghauri` | Modern blind SQLi on ID-like parameters |
| Discovery: SSRF | `interactsh-client` | Self-hosted OOB listener for blind SSRF/XXE/RCE |
| Discovery: WAF | `wafw00f` -> `whatwaf` | Identify WAF vendor -> test bypass techniques |
| Exploit: 403 | `byp4xx` or `nomore403` | 20+ bypass techniques automated |
| Exploit: Takeover | `subzy` | Checks CNAME against 70+ vulnerable services |
| Exploit: Cloud | `s3scanner` + `aws` CLI | Scan bucket permissions -> extract metadata credentials |
| Exploit: Secrets | `trufflehog --only-verified` | Only verified working keys (no false positives) |

### Session End Checklist

- [ ] Save all Burp/Caido project files
- [ ] Record any "weird but not yet exploitable" behaviors (future gadgets)
- [ ] Update notes with failed attempts (don't re-test with same techniques)
- [ ] Log findings with `/remember`

---

**Evidence & reporting (ida_mcp workflow).** Every claim needs decompilation/xref/data-flow evidence (`analyze_function`/`decompile_function`/`trace_data_flow`/`callgraph`); use `int_convert` for bases; write `re/summary.md`, `re/analysis.md`, `re/findings.md` with hex addresses and the tool behind each claim. Mutations (`set_name`/`set_comment`/`set_type`/`patch_*`/`execute_script`) require `?unsafe=true`; live debugging requires `?unsafe=true&ext=dbg`.
