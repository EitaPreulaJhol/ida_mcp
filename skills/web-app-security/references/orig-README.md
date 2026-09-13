# Archived upstream source — NOT a loadable skill (frontmatter stripped for lazy-load hygiene).

# Web Application Security Analysis

Comprehensive web application security analysis covering vulnerabilities, attack vectors, secure coding practices, and modern web frameworks. Focus on both client-side and server-side security issues.

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

## Capabilities

### OWASP Top 10 Analysis
- **Injection**: SQL injection, NoSQL injection, command injection, LDAP injection
- **Broken Authentication**: Session fixation, credential stuffing, weak password policies
- **XSS**: Reflected, stored, and DOM-based cross-site scripting
- **SSRF**: Server-side request forgery and internal API access
- **Security Misconfiguration**: Default credentials, exposed admin panels, misconfigured headers
- **Sensitive Data Exposure**: Data in transit, data at rest, caching issues
- **Access Control**: Broken access control, privilege escalation, IDOR
- **CSRF**: Cross-site request forgery and anti-CSRF measures
- **Vulnerable Components**: Known vulnerable libraries and dependencies
- **Logging**: Insufficient logging and monitoring, missing audit trails

### Authentication & Authorization
- **Session Management**: Cookie security, session fixation, session timeout
- **Multi-Factor Auth**: 2FA implementation analysis and bypass techniques
- **OAuth/OpenID**: SSO flows, token storage, and redirect URI validation
- **JWT**: Token validation, algorithm confusion, signature bypass
- **Password Security**: Hashing algorithms, pepper usage, salt management
- **Access Control**: RBAC, ABAC, privilege escalation, horizontal/vertical escalation

### Input Validation & Output Encoding
- **SQL Injection**: Union-based, blind, time-based, error-based techniques
- **NoSQL Injection**: MongoDB, Redis, Elasticsearch, CouchDB injection vectors
- **Command Injection**: OS command injection, argument injection, pipe injection
- **Path Traversal**: File inclusion, directory traversal, zip slip
- **XSS**: Reflected, stored, DOM-based, self-XSS, universal XSS
- **SSRF**: Internal port scanning, cloud metadata access, GCP/Azure/AWS abuse
- **File Upload**: MIME type validation, file content validation, path traversal

### API & Microservices Security
- **REST API**: Authentication, authorization, rate limiting, data validation
- **GraphQL**: Query depth limiting, introspection, authorization, batching attacks
- **API Gateway**: Rate limiting, authentication, request routing security
- **Microservices**: Service-to-service authentication, inter-service communication
- **WebSockets**: Origin validation, message validation, rate limiting
- **Webhooks**: Signature verification, replay protection, rate limiting

### Client-Side Security
- **JavaScript Analysis**: DOM manipulation, localStorage, sessionStorage, XSS vectors
- **Single Page Apps**: Client-side routing, state management, API security
- **Browser Security**: CSP, CORS, XSS Protection, Frame options
- **Third-Party Scripts**: JavaScript libraries, tracking scripts, analytics
- **Mobile Web**: Responsive design issues, mobile-specific vulnerabilities

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

6. **Documentation**
   - Document findings with proof of concepts
   - Provide risk ratings and impact analysis
   - Recommend remediation strategies
   - Create detailed security reports

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
