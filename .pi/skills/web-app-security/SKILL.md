---
name: web-app-security
description: Web application security — OWASP Top 10, authentication, authorization, input validation, API security, and modern web frameworks Use with IDA Pro via ida_mcp (triage-first, escalate per ladder).
compatibility: IDA Pro 8.3+ with the ida_mcp plugin (Hex-Rays for decompiler tools)
metadata:
  workflow: ida-pro-mcp-lazy
  ceiling: `?profile=readonly`
---

> **IDA-MCP adapter (read first).** This skill runs against the binary open in IDA Pro through ida_mcp.
> Start at `?profile=triage` (`server_health` → `survey_binary`), escalate top-down; ceiling for this skill: **`?profile=readonly`** — read-only ceiling — start at `?profile=triage`.
> Never request unsafe/dbg "just in case" — justify each escalation in one sentence. All addresses accept hex/symbol/dec; `decompile_function` returns plain text, everything else JSON.

All tool calls below are native ida_mcp tools.

---

Task: Web Application Security Analysis. You are analyzing web applications for security vulnerabilities following OWASP Top 10 and modern security practices.

## Approach

Systematic analysis covering authentication, authorization, input validation, business logic, and modern web framework issues. Focus on both client-side and server-side vulnerabilities.

## When to Use

Use this skill when:
- Analyzing web applications for security vulnerabilities
- Reviewing web application code for security issues
- Testing authentication, authorization, and session management
- Analyzing API security and data validation
- Assessing input validation and output encoding
- Testing for OWASP Top 10 vulnerabilities
- Reviewing JavaScript client-side security
- Analyzing web framework-specific issues

## Workflow

1. **Reconnaissance**
   - Map application structure and endpoints
   - Identify technologies and frameworks
   - Discover hidden endpoints and admin panels
   - Analyze JavaScript bundles and dependencies

2. **Authentication Testing**
   - Test login flows and password reset
   - Analyze session management and cookies
   - Test for session fixation and hijacking
   - Evaluate 2FA and SSO implementations

3. **Authorization Testing**
   - Test for IDOR and access control bypasses
   - Analyze role-based access control
   - Test for privilege escalation
   - Evaluate API authorization

4. **Input Validation Testing**
   - Test for injection vulnerabilities
   - Analyze input sanitization and validation
   - Test for XSS and CSRF
   - Evaluate file upload security

5. **Business Logic Testing**
   - Test for workflow bypasses
   - Analyze rate limiting and throttling
   - Test for race conditions and TOCTOU
   - Evaluate payment and transaction flows

## OWASP Top 10 Categories

**A01: Broken Access Control**
- IDOR (Insecure Direct Object References)
- Privilege escalation (horizontal/vertical)
- Missing authorization on sensitive endpoints
- Admin panel exposure

**A02: Cryptographic Failures**
- Sensitive data in transit (no HTTPS)
- Weak encryption algorithms
- Hardcoded keys and passwords
- Missing security headers

**A03: Injection**
- SQL Injection (union, blind, time-based)
- NoSQL Injection (MongoDB, Redis)
- Command Injection
- LDAP Injection

**A04: Insecure Design**
- Missing security controls
- Unsafe default configurations
- Insecure workflows

**A05: Security Misconfiguration**
- Default credentials
- Exposed admin panels
- Verbose error messages
- Missing security headers

**A06: Vulnerable Components**
- Outdated libraries with known CVEs
- Unpatched dependencies
- Unused but vulnerable components

**A07: Authentication Failures**
- Weak password policies
- Session fixation
- Credential stuffing
- Missing 2FA

**A08: Software/Data Integrity Failures**
- Insecure updates
- Unsigned firmware/software
- CI/CD pipeline vulnerabilities

**A09: Logging/Monitoring Failures**
- Insufficient logging
- Missing audit trails
- No alerting on critical events

**A10: Server-Side Request Forgery (SSRF)**
- Internal port scanning
- Cloud metadata access
- Internal API calls

## Authentication & Authorization

**Session Management:**
- Cookie security (Secure, HttpOnly, SameSite)
- Session fixation vulnerabilities
- Session timeout configuration
- Session regeneration after login

**Multi-Factor Authentication:**
- 2FA bypass techniques
- Weak 2FA implementations
- SMS interception risks
- TOTP/HOTP analysis

**OAuth/OpenID Connect:**
- Authorization code flow issues
- Implicit flow vulnerabilities
- Redirect URI validation
- Token leakage via redirect

**JWT (JSON Web Tokens):**
- Algorithm confusion (none algorithm)
- Weak signature verification
- Token leakage
- Missing token expiration

**Access Control:**
- IDOR vulnerabilities
- Missing authorization checks
- Direct object reference access
- Privilege escalation paths

## Input Validation

**SQL Injection:**
- Union-based extraction
- Blind injection (boolean, time)
- Error-based injection
- Second-order injection

**NoSQL Injection:**
- MongoDB operator injection
- Redis command injection
- Elasticsearch injection
- CouchDB injection

**Command Injection:**
- OS command execution
- Argument injection
- Pipe injection
- Command chaining

**Path Traversal:**
- File inclusion vulnerabilities
- Directory traversal
- Zip slip
- Configuration file access

**XSS (Cross-Site Scripting):**
- Reflected XSS
- Stored XSS
- DOM-based XSS
- Self-XSS and universal XSS

**SSRF (Server-Side Request Forgery):**
- Internal port scanning
- Cloud metadata access (AWS, Azure, GCP)
- Internal API enumeration
- File protocol access (file://)

**File Upload:**
- MIME type validation bypass
- File content validation bypass
- Path traversal in uploads
- Webshell upload

## API & Microservices Security

**REST API:**
- Authentication and authorization
- Rate limiting and throttling
- Input validation
- CORS misconfiguration

**GraphQL:**
- Query depth limiting
- Introspection exposure
- Authorization on fields
- Batching attacks

**API Gateway:**
- Rate limiting bypass
- Authentication bypass
- Request routing security
- Response splitting

**Microservices:**
- Service-to-service authentication
- Inter-service communication security
- Broken authentication propagation
- Internal API exposure

**WebSockets:**
- Origin validation
- Message validation
- Rate limiting
- Authentication

## Client-Side Security

**JavaScript Analysis:**
- DOM manipulation risks
- localStorage/sessionStorage security
- XSS vectors in client code
- Secret exposure in JavaScript

**Single Page Applications:**
- Client-side routing security
- State management issues
- API security
- Authentication token storage

**Browser Security:**
- CSP (Content Security Policy) analysis
- CORS misconfiguration
- XSS Protection headers
- Frame options

**Third-Party Scripts:**
- JavaScript library vulnerabilities
- Tracking script risks
- Analytics security
- Supply chain attacks

## Documentation Template

**Finding Summary:**
- Vulnerability type and severity
- Affected endpoints/parameters
- Proof of concept
- Business impact

**Technical Details:**
- Root cause analysis
- Exploitation steps
- Code examples
- Request/response samples

**Remediation:**
- Specific fix recommendations
- Code examples for fixes
- Security best practices
- Regression testing guidance

## Output

Comprehensive security analysis including:
- Identified vulnerabilities with severity ratings
- Proof of concepts and exploitation steps
- Risk assessment and business impact
- Remediation recommendations
- Security best practices and coding guidelines
- Regression testing recommendations
- Detailed security reports with evidence

Focus on providing actionable findings with concrete proof of concepts and clear remediation guidance. Follow responsible disclosure practices.

---

**Evidence & reporting (ida_mcp workflow).** Every claim needs decompilation/xref/data-flow evidence (`analyze_function`/`decompile_function`/`trace_data_flow`/`callgraph`); use `int_convert` for bases; write `re/summary.md`, `re/analysis.md`, `re/findings.md` with hex addresses and the tool behind each claim. Mutations (`set_name`/`set_comment`/`set_type`/`patch_*`/`execute_script`) require `?unsafe=true`; live debugging requires `?unsafe=true&ext=dbg`.
