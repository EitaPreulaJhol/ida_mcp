---
name: report-writing
description: "Bug bounty report writing for H1/Bugcrowd/Intigriti/Immunefi — report templates, human tone guidelines, impact-first writing, CVSS 3.1 scoring, title formula, impact statement formula, severity decision guide, downgrade counters, pre-submit checklist. Use after validating a finding and before submitting. Never use \"could potentially\" — prove it or don't report. Use with IDA Pro via ida_mcp (triage-first, escalate per ladder)."
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

# REPORT WRITING

Impact-first. Human tone. No theoretical language. Triagers are people.

---

## THE MOST IMPORTANT RULE

> **Never use "could potentially" or "could be used to" or "may allow".**
> Either it does the thing or it doesn't. If you haven't proved it, don't claim it.

```
BAD:  "This vulnerability could potentially allow an attacker to access user data."
GOOD: "An attacker can access any user's order history by changing the user_id
       parameter to the target user's ID. I confirmed this using two test accounts:
       attacker@test.com (ID 123) successfully retrieved victim@test.com (ID 456)
       orders, including their shipping address and payment method last 4 digits."
```

---

## TITLE FORMULA

```
[Bug Class] in [Exact Endpoint/Feature] allows [attacker role] to [impact] [victim scope]
```

**Good titles (specific, impact-first):**
```
IDOR in /api/v2/invoices/{id} allows authenticated user to read any customer's invoice data
Missing auth on POST /api/admin/users allows unauthenticated attacker to create admin accounts
Stored XSS in profile bio field executes in admin panel — allows privilege escalation
SSRF via image import URL parameter reaches AWS EC2 metadata service
Race condition in coupon redemption allows same code to be used unlimited times
```

**Bad titles (vague, useless to triager):**
```
IDOR vulnerability found
Broken access control
XSS in user input
Security issue in API
Unauthorized access to user data
```

---

## HACKERONE REPORT TEMPLATE

```markdown
## Summary

[One paragraph: what the bug is, where it is, what an attacker can do. Be specific.
Include: endpoint, method, parameter, data exposed, required access level.]

Example: "The `/api/users/{user_id}/orders` endpoint does not verify that the
authenticated user owns the requested user_id. An attacker can enumerate any
user's order history, including PII (email, address, phone) and purchase history,
by incrementing the user_id parameter. No privileges beyond a standard free
account are required."

## Vulnerability Details

**Vulnerability Type:** IDOR / Broken Object Level Authorization
**CVSS 3.1 Score:** 6.5 (Medium) — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
**Affected Endpoint:** GET /api/users/{user_id}/orders

## Steps to Reproduce

**Environment:**
- Attacker account: attacker@test.com, user_id = 123
- Victim account: victim@test.com, user_id = 456
- Target: https://target.com

**Steps:**

1. Log in as attacker@test.com, obtain Bearer token

2. Send the following request:

```
GET /api/users/456/orders HTTP/1.1
Host: target.com
Authorization: Bearer ATTACKER_TOKEN_HERE
```

3. Observe response:

```json
{
  "orders": [
    {"id": 789, "items": [...], "email": "victim@test.com", "address": "123 Main St..."}
  ]
}
```

The response contains victim's full order history and PII despite being requested
by a different user.

## Impact

An authenticated attacker can enumerate all user orders by iterating user_id values.
This exposes: full name, email, shipping address, purchase history, and payment
method (last 4). With ~100K users, this represents a mass PII breach affecting
all registered users. Exploitation requires only a free account and takes minutes
with a simple loop.

## Recommended Fix

Add server-side ownership verification:
```python
if order.user_id != current_user.id:
    raise Forbidden()
```

## Supporting Materials

[Screenshot showing attacker's session returning victim's order data]
[Video walkthrough if available]
```

---

## BUGCROWD REPORT TEMPLATE

```markdown
# [IDOR] User order history accessible without authorization via /api/users/{id}/orders

**VRT Category:** Broken Access Control > IDOR > P2

## Description

[Same impact-first paragraph as HackerOne summary]

## Steps to Reproduce

[Same structured steps — exact HTTP requests, exact responses]

## Proof of Concept

[Screenshot/video showing the actual impact]

## Expected vs Actual Behavior

**Expected:** 403 Forbidden when user_id does not match authenticated user
**Actual:** 200 OK with victim's full order data

## Severity Justification

P2 (High) — Direct read access to other users' PII. Affects all user accounts.
No user interaction required. Exploitable by any authenticated user.
Automated enumeration could exfil all [N] user records in minutes.

## Remediation

Add ownership verification: `if order.user_id != current_user.id: raise 403`
```

---

## INTIGRITI REPORT TEMPLATE

```markdown
# [Bug Class]: [Exact Impact] in [Endpoint/Feature]

## Description

[Impact-first paragraph. Start with what an attacker can do, not with how you found it.
Include: endpoint, method, parameter, data exposed, required privileges.]

## Steps to Reproduce

**Environment:**
- Attacker: email=attacker@test.com (standard account, no special role)
- Victim: email=victim@test.com
- Tested: [date]

**Reproduction steps:**

1. [Login as attacker / visit URL / send request]

2. Send the following HTTP request:

\```http
METHOD /endpoint HTTP/1.1
Host: target.com
Authorization: Bearer ATTACKER_TOKEN
Content-Type: application/json

{"param": "victim_id_here"}
\```

3. Observe response contains victim's private data:

\```json
{"email": "victim@test.com", "address": "123 Main St", ...}
\```

## Impact

[Specific, quantified impact. What data, how many users, what can attacker do.]

CVSS 3.1 Score: X.X ([Severity]) — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N

## Remediation

[1-3 sentence concrete fix. Include code if helpful.]

## Attachments

[Screenshot or Loom video showing the impact — Intigriti triagers prefer video for complex bugs]
```

**Intigriti-specific notes:**
- Title format: `[Bug Class]: [One-line impact]` (no formula required, but keep it specific)
- Severity is set by you: Critical/High/Medium/Low/Exceptional
- CVSS 3.1 is standard (CVSS 4.0 also accepted on newer programs)
- PoC video is valued much more than screenshot alone — record with Loom
- Safe harbor: Intigriti enforces it, be comfortable going slightly aggressive with testing

---

## IMMUNEFI REPORT TEMPLATE

```markdown
# [Bug Class] — [Protocol Name] — [Severity]

## Summary

[One paragraph with: root cause, affected function, economic impact, attack cost.
Include numbers where possible: "attacker can drain $X in Y transactions."]

## Vulnerability Details

**Contract:** `VulnerableContract.sol`
**Function:** `claimRedemption()`
**Bug Class:** Accounting State Desynchronization
**Severity:** Critical

### Root Cause

[Exact code snippet showing the vulnerable code with comments]

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// Foundry PoC — run: forge test --match-test test_exploit -vvvv

contract ExploitTest is Test {
    // ... full working exploit
}
```

## Impact

[Quantified: "Attacker can drain X% of TVL = $Y at current rates.
Requires $Z gas. Attack is repeatable."]

## Recommended Fix

[Specific code change with before/after]
```

---

## CVSS 3.1 QUICK SCORING

### Formula
```
CVSS = f(AV, AC, PR, UI, S, C, I, A)
```

### Metric Quick Picks

| Metric | Value | Weight | When |
|---|---|---|---|
| **Attack Vector (AV)** | Network | +0.85 | Via internet |
| | Local | +0.55 | Local access needed |
| **Attack Complexity (AC)** | Low | +0.77 | Repeatable |
| | High | +0.44 | Race/timing needed |
| **Privileges Required (PR)** | None | +0.85 | No login |
| | Low | +0.62 | Regular user account |
| | High | +0.27 | Admin account |
| **User Interaction (UI)** | None | +0.85 | No victim action |
| | Required | +0.62 | Victim must click |
| **Scope (S)** | Changed | higher | Affects browser/OS/other |
| | Unchanged | lower | Stays in app |
| **Confidentiality (C)** | High | +0.56 | All data exposed |
| | Low | +0.22 | Limited data |
| **Integrity (I)** | High | +0.56 | Can modify any data |
| **Availability (A)** | High | +0.56 | Crashes service |

### Typical Scores by Bug Class

| Bug | Typical CVSS | Severity |
|---|---|---|
| IDOR (read PII) | 6.5 | Medium |
| IDOR (write/delete) | 7.5 | High |
| Auth bypass → admin | 9.8 | Critical |
| Stored XSS (any user) | 5.4–8.8 | Med–High |
| SQLi (data exfil) | 8.6 | High |
| SSRF (cloud metadata) | 9.1 | Critical |
| Race condition (double spend) | 7.5 | High |
| GraphQL auth bypass | 8.7 | High |
| JWT none algorithm | 9.1 | Critical |

---

## SEVERITY DECISION GUIDE

### Critical (P1)
- Full account takeover of any user without interaction
- Remote code execution
- SQLi with ability to dump/modify entire DB
- Auth bypass to admin panel
- SSRF to cloud metadata → IAM credentials exfil

### High (P2)
- Mass PII exposure (email, phone, SSN, payment data)
- Privilege escalation from user to admin
- SSRF reaching internal services (data returned)
- Stored XSS executing for all users of sensitive feature
- Payment bypass / financial loss without limit

### Medium (P3)
- IDOR on specific user's non-critical data
- XSS on low-sensitivity page requiring victim interaction
- CSRF on important but non-critical action
- Rate limit bypass on OTP (with effort demonstrated)

### Low (P4)
- Information disclosure (non-sensitive, no PII)
- Clickjacking on sensitive action WITH working PoC
- CORS on limited data

---

## SEVERITY SELF-ASSESSMENT

Each YES raises severity:
```
1. Exposes PII / health / financial data of other users?        → +1 severity
2. Allows account takeover or privilege escalation?             → +2 severity
3. Requires ZERO user interaction from victim?                  → +1 severity
4. Affects ALL users (not specific condition)?                  → +1 severity
5. Remotely exploitable with no internal network access?        → baseline for High+
```

---

## DOWNGRADE COUNTERS

| Program Says | Counter With |
|---|---|
| "Requires authentication" | "Attacker needs only a free account — no special role or permission" |
| "Limited impact" | "Affects [N] users / exposes [PII type] / $[amount] at risk" |
| "Already known" | "Show me the report number — I searched hacktivity and found none" |
| "By design" | "Show me the documentation stating this is intended behavior" |
| "Low CVSS" | "CVSS doesn't capture business impact — attacker can extract [X] in [Y] minutes" |
| "Not exploitable" | "Here is the exact response showing victim's data returned to attacker session" |

---

## THE 60-SECOND PRE-SUBMIT CHECKLIST

```
[ ] Title follows formula: [Class] in [endpoint] allows [actor] to [impact]
[ ] First sentence states exact impact in plain English
[ ] Steps to Reproduce has exact HTTP request (copy-paste ready)
[ ] Response showing the bug is included (screenshot or JSON body)
[ ] Two test accounts used — not just one account testing itself
[ ] CVSS score calculated and included
[ ] Recommended fix is 1-2 sentences (not a lecture)
[ ] No typos in endpoint paths or parameter names
[ ] Report is < 600 words — triagers skim long reports
[ ] Severity claimed matches impact described — don't overclaim
[ ] Never used "could potentially" or "may allow"
[ ] PoC is reproducible by triager from a fresh state
```

---

## CVSS 4.0 QUICK REFERENCE (newer programs)

CVSS 4.0 replaced CVSS 3.1 in November 2023. Some newer programs require it.

### Key Differences from CVSS 3.1

| Metric | CVSS 3.1 | CVSS 4.0 |
|---|---|---|
| Attack Vector | Network/Adjacent/Local/Physical | Same |
| Attack Complexity | Low/High | Low/High |
| **NEW**: Attack Requirements | (didn't exist) | None/Present (replaces some PR/UI) |
| Privileges Required | None/Low/High | Same |
| User Interaction | None/Required | None/Passive/Active |
| Scope | Unchanged/Changed | REMOVED |
| **NEW**: Sub-Impact metrics | (didn't exist) | Vulnerable/Subsequent system impact |

### CVSS 4.0 Score Examples

| Finding | CVSS 4.0 Score | Vector |
|---|---|---|
| Unauthenticated RCE | 10.0 | CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H |
| IDOR read PII, auth required | 6.9 | CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N |
| Stored XSS, admin views it | 8.2 | CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N |
| SSRF → cloud metadata | 8.7 | CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:N |

### Quick CVSS 4.0 Calculator
```
Use: https://www.first.org/cvss/calculator/4.0
Key fields:
  VC/VI/VA = Vulnerable System Confidentiality/Integrity/Availability
  SC/SI/SA = Subsequent System (downstream impact)
  AT = None (no special condition) | Present (race/specific config needed)
  UI = None | Passive (victim visits URL) | Active (victim takes explicit action)
```

**Practical rule**: If program uses CVSS 4.0 and you don't know the vector, use the calculator and include the full string starting with `CVSS:4.0/AV:...`. Programs cannot dispute a valid vector string.

---

## HUMAN TONE GUIDELINES

**Write to a person, not a system:**
- Triagers are tired. Get to the impact in sentence 1.
- Use "I" not "the researcher" — you found it, own it
- Short paragraphs, bullet points for steps
- Hyperlink relevant docs if needed

**Escalation language (when payout is being downgraded):**
```
"This vulnerability does not require any special privileges — only a free account."
"The exposed data includes [PII type], which is subject to GDPR requirements."
"An attacker can automate this with a simple loop — all [N] records in minutes."
"This is exploitable externally without network access to any internal system."
"The impact is equivalent to a full data breach of [feature/data type]."
```

**Avoid:**
- Jargon the triager might not know
- 5-paragraph explanations of what IDOR is (they know)
- Theoretical chains ("could be combined with X to...")
- Passive voice ("it was observed that...")
- Qualifying language ("seems to," "appears to")

---

## STEPS TO REPRODUCE FORMAT (triager-optimized)

```markdown
**Setup:**
- Account A (attacker): email=attacker@test.com, ID=111
- Account B (victim): email=victim@test.com, ID=222
- Both created via normal registration — no special access

**Steps:**

1. Log in as Account A
2. Send this request (replace `111` with victim ID `222`):

\```
GET /api/v2/resource/222 HTTP/1.1
Host: target.com
Authorization: Bearer ACCOUNT_A_TOKEN
\```

3. Response contains Account B's private data:

\```json
{"id": 222, "email": "victim@test.com", "name": "Victim User", "address": "..."}
\```

**Expected:** 403 Forbidden
**Actual:** 200 OK with victim's private data
```

---

# ZERO-DAY REPORT TEMPLATE

> **For novel vulnerabilities that don't fit known patterns**: Extra documentation to prove this is genuinely new and exploitable.

## Novel Vulnerability Report Structure

```markdown
# [Bug Class]: [Novel Attack Vector] in [Component] — [Severity]

## Summary

[One paragraph explaining the NOVEL aspect first:
- What makes this different from known patterns
- What combination/design contradiction/feature interaction is exploited
- What the attacker achieves (RCE/ATO/PII exfil/financial loss)]

Example: "A feature interaction vulnerability in the Export→Import workflow allows
any authenticated user to escalate privileges to admin. The Export endpoint returns
user data in a format that the Import endpoint accepts without validation. By exporting
a user profile, modifying the is_admin field, and re-importing, an attacker can grant
admin privileges to any account. This is a novel design flaw not covered by standard
IDOR patterns because it requires combining two separate features."

## Why This Is Novel

This vulnerability is not covered by existing scanners or checklists because:

1. **Feature Interaction Required**: Requires combining [Feature A] + [Feature B]
   - Export: /api/export returns data in serialized format
   - Import: /api/import accepts same format without schema validation

2. **Design Contradiction**: Documentation claims "Import validates all fields" but implementation has no validation

3. **Untested Code Path**: The data flow from Export → Import was never tested as an attack vector

4. **Not a Known Pattern**: Standard IDOR scanners miss this because the vulnerability requires:
   - Two separate API calls (not single parameter change)
   - Data modification between calls (not direct ID swap)
   - Understanding the internal data format (not accessible to scanners)

## Vulnerability Details

**Vulnerability Type:** [Design Flaw / Feature Interaction / POP Chain / Race Condition]
**CVSS 3.1 Score:** X.X ([Severity])
**Affected Components:** [Component A] + [Component B]

### Root Cause

[Explain the design contradiction or feature interaction]

**Code Evidence:**

```javascript
// Export endpoint - no sanitization
app.get('/api/export/:userId', (req, res) => {
    const user = await db.users.findById(req.params.userId);
    // VULNERABLE: Returns entire user object including sensitive fields
    res.json(user);  // ← No field filtering
});

// Import endpoint - trusts input
app.post('/api/import', (req, res) => {
    const userData = req.body;  // ← No validation that user owns this data
    const user = await db.users.upsert(userData);
    // VULNERABLE: Accepts is_admin field without verification
    res.json(user);
});
```

### Attack Flow Diagram

```
┌─────────────┐      ┌──────────────┐      ┌─────────────┐
│             │      │              │      │             │
│  Attacker   │─────▶│  Export     │─────▶│  Modify     │
│  Account    │      │  /api/export│      │  Data       │
│             │      │  (victim)   │      │  (add admin)│
│             │      │              │      │             │
└─────────────┘      └──────────────┘      └──────┬──────┘
                                              │
                                              ▼
                                        ┌──────────────┐
                                        │              │
                                        │  Import      │
                                        │  /api/import  │
                                        │              │
                                        └──────┬───────┘
                                               │
                                               ▼
                                        ┌──────────────┐
                                        │              │
                                        │  Victim      │
                                        │  Account     │
                                        │  = Admin     │
                                        │              │
                                        └──────────────┘
```

## Steps to Reproduce

**Environment:**
- Attacker account: attacker@test.com (standard user, no special access)
- Victim account: victim@test.com
- Target: https://target.com
- Date: [YYYY-MM-DD]

**Prerequisites:**
- Attacker has standard user account (no admin privileges)
- Both Export and Import features are accessible to standard users

**Exploitation Steps:**

1. **Export victim profile:**

```http
GET /api/export/456 HTTP/1.1
Host: target.com
Authorization: Bearer ATTACKER_TOKEN
```

Response:
```json
{
    "id": 456,
    "email": "victim@test.com",
    "name": "Victim User",
    "is_admin": false,
    "preferences": {...}
}
```

2. **Modify exported data (set is_admin to true):**

Save the response, modify `is_admin: false` → `is_admin: true`

3. **Import modified profile:**

```http
POST /api/import HTTP/1.1
Host: target.com
Authorization: Bearer ATTACKER_TOKEN
Content-Type: application/json

{
    "id": 456,
    "email": "victim@test.com",
    "name": "Victim User",
    "is_admin": true,
    "preferences": {...}
}
```

Response:
```json
{
    "success": true,
    "user": {
        "id": 456,
        "email": "victim@test.com",
        "is_admin": true,
        "role": "administrator"
    }
}
```

4. **Verify privilege escalation:**

```http
GET /api/admin/users HTTP/1.1
Host: target.com
Authorization: Bearer VICTIM_TOKEN
```

Response: 200 OK (access granted to admin-only endpoint)

## Impact

This vulnerability allows any authenticated user to:

1. **Privilege Escalation**: Grant admin privileges to any user account
2. **Account Takeover**: Reset passwords of admin accounts
3. **Data Access**: Access all admin-only endpoints and data
4. **Persistence**: Create backdoor accounts

**Affected Users:** All [N] registered users can be targeted
**Exploitation Time:** < 5 minutes per account
**Automation Potential:** Highly automatable — can escalate all accounts in < 1 hour

**Business Impact:**
- Complete compromise of user management system
- Attacker can create unlimited admin accounts
- All user data accessible via admin APIs
- Potential for mass account takeover campaign

## Proof of Concept

A working exploit script has been provided in the `poc/` directory:

```bash
# Python exploit
python3 poc/export_import_privesc.py --target https://target.com \
    --attacker-token ATTACKER_TOKEN --victim-id 456

# Bash exploit
./poc/export_import_privesc.sh https://target.com ATTACKER_TOKEN 456
```

**Video Demonstration:**
[Loom video showing the complete exploitation flow]

## Severity Assessment

**CVSS 3.1 Score:** 9.1 (Critical)
**Vector:** AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

**Rationale:**
- Network exploitable (AV:N)
- Low attack complexity (AC:L) — simple API calls
- Low privileges required (PR:L) — standard user account
- No user interaction (UI:N)
- Scope changed (S:C) — affects all user accounts
- High confidentiality (C:H) — all user data accessible
- High integrity (I:H) — can modify any user data
- High availability (A:H) — can disrupt service

## Recommended Fix

1. **Add Schema Validation**: Import endpoint should validate:
   - Requester owns the user data being imported
   - Sensitive fields (is_admin, role) cannot be modified via Import
   - Import only allowed for profile fields user is authorized to modify

2. **Field Whitelist**: Define explicit allowlist of importable fields:
```javascript
const IMPORTABLE_FIELDS = ['email', 'name', 'preferences'];
const sanitizedData = pick(req.body, IMPORTABLE_FIELDS);
```

3. **Ownership Verification**: Add authorization check:
```javascript
if (importData.id !== current_user.id && !current_user.is_admin) {
    throw new ForbiddenError('Cannot import other users data');
}
```

4. **Audit Logging**: Log all import/export operations for security monitoring

## Timeline

- [YYYY-MM-DD]: Vulnerability discovered
- [YYYY-MM-DD]: Report submitted
- [YYYY-MM-DD]: Vendor acknowledgment
- [YYYY-MM-DD]: Patch deployed
- [YYYY-MM-DD]: Public disclosure

## References

- Internal API documentation: /docs/api.md
- Related disclosed reports: [None — this is novel]
- CVE assignment: [Pending]
```

## Novel Report Writing Guidelines

### 1. Emphasize Novelty Early

**First paragraph must answer:**
- Why is this different from known patterns?
- What combination/contradiction/feature interaction is exploited?
- Why scanners miss this?

### 2. Prove Each Link in the Chain

For complex novel vulnerabilities, prove EVERY step:
```
[✓] Link A: Feature A exists and is accessible
[✓] Link B: Feature B exists and is accessible
[✓] Connection: A's output can reach B's input
[✓] Exploit: Attacker can control data flow A → B
[✓] Impact: Result achieves [RCE/ATO/PII exfil]
```

### 3. Include Exploit Script

Provide working exploit code in `poc/` directory:
- Python 3 (recommended for cross-platform)
- Bash (for quick testing)
- Target language if applicable (PHP for WordPress, etc.)

### 4. Show, Don't Tell

- Include exact HTTP requests/responses
- Provide video demonstration for complex flows
- Show actual impact (screenshot of admin panel, data exfil, etc.)
- Include code snippets with line numbers

### 5. Quantify Impact

```
BAD: "This could potentially affect many users."
GOOD: "This affects all 150,000 registered users. Exploitation takes
      < 5 minutes per account. Full compromise of user management system
      allows unlimited admin account creation."
```

### 6. Avoid "Theoretical" Language

```
FORBIDDEN PHRASES:
- "could potentially"
- "may allow"
- "might be possible"
- "theoretically"
- "if an attacker were to"

REQUIRED PHRASES:
- "An attacker can"
- "This allows"
- "I confirmed that"
- "Successfully exploited"
- "Achieved [specific impact]"
```

### 7. Provide Clear Remediation

```
1. Specific code change (with before/after)
2. Why this fix addresses the root cause
3. Additional hardening measures (audit logging, monitoring)
4. Testing recommendations to prevent regression
```

## Platform-Specific Novel Report Formats

### HackerOne Novel Report

```markdown
## Summary

[Novel aspect explanation + impact]

## Why This Is Novel

[List reasons scanners miss this]

## Root Cause

[Code analysis with vulnerable snippet]

## Attack Chain

[Step-by-step with diagram]

## Steps to Reproduce

[Exact HTTP requests]

## Impact

[Quantified business impact]

## CVSS 3.1 Score

X.X ([Severity]) — [Vector string]

## Recommended Fix

[Specific remediation]

## Supporting Materials

- Exploit: poc/exploit_name.py
- Video: [Loom link]
- Screenshots: [attached]
```

### Bugcrowd Novel Report

```markdown
# [Novel Vector]: [Component] — [Severity]

## Vulnerability Type

[Design Flaw / Feature Interaction / POP Chain]

## Summary

[Novel aspect + impact]

## Why This Is Novel

[Scanners miss this because...]

## Root Cause Analysis

[Code analysis]

## Steps to Reproduce

[Reproducible steps]

## Proof of Concept

[Working exploit provided]

## Impact

[Business impact quantified]

## Severity

P1/P2/P3 with CVSS 3.1 score

## Remediation

[Specific fix]
```

### Intigriti Novel Report

```markdown
# [Bug Class]: [Novel Vector] in [Component]

## Description

[Novel aspect explanation]

## Why This Is Novel

[List reasons]

## Steps to Reproduce

[With video demonstration link]

## Impact

[Quantified]

## CVSS 3.1

[Score and vector]

## Recommended Fix

[Specific remediation]

## Attachments

- PoC script
- Video walkthrough
```

## Novel Vulnerability Severity Quick Reference

| Novel Finding Type | Typical Severity | CVSS 3.1 Range | Justification |
|---|---|---|---|
| Feature interaction → ATO | Critical | 9.0-9.8 | Unexpected attack path |
| Design contradiction → Data leak | High | 8.0-8.7 | Doc says X, code does Y |
| POP chain → RCE | Critical | 9.1-10.0 | Deserialization abuse |
| Race condition → Financial loss | High | 7.5-8.6 | Timing-dependent exploit |
| TOCTOU → Privilege esc. | High | 7.0-8.2 | Check-then-use gap |
| Memory corruption → RCE | Critical | 9.5-10.0 | Low-level exploitation |
| Type confusion → Auth bypass | High | 7.5-8.7 | Input validation failure |
| Protocol violation → State abuse | Medium-High | 6.5-8.0 | Unexpected sequence |

---

**Evidence & reporting (ida_mcp workflow).** Every claim needs decompilation/xref/data-flow evidence (`analyze_function`/`decompile_function`/`trace_data_flow`/`callgraph`); use `int_convert` for bases; write `re/summary.md`, `re/analysis.md`, `re/findings.md` with hex addresses and the tool behind each claim. Mutations (`set_name`/`set_comment`/`set_type`/`patch_*`/`execute_script`) require `?unsafe=true`; live debugging requires `?unsafe=true&ext=dbg`.
