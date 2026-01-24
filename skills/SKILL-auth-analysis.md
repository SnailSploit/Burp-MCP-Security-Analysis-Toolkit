# SKILL: Authentication & Authorization Analysis

This skill covers testing for authentication bypasses, session management issues, and authorization flaws.

## Scope

| Category | Examples |
|----------|----------|
| Authentication Bypass | Missing auth checks, broken login flows |
| Session Management | Weak tokens, session fixation, insecure transmission |
| Authorization Flaws | Missing role checks, privilege escalation |
| Token Vulnerabilities | JWT issues, insecure token generation |

---

## Prerequisites

1. ✅ Endpoints triaged with `auth_bypass` indicator
2. ✅ Auth configuration in scope.yaml understood
3. ✅ Multiple auth contexts available (different users, roles)
4. ✅ Login/logout flow captured in Burp traffic

---

## Methodology

### Phase A: Authentication Mechanism Analysis

#### Step A1: Identify Auth Mechanism

Examine traffic to determine:

```
Authentication Type:
[ ] Bearer Token (JWT or opaque)
[ ] Session Cookie
[ ] API Key
[ ] Basic Auth
[ ] OAuth 2.0
[ ] Custom Header
[ ] Multiple/Hybrid

Storage:
[ ] Cookie (HttpOnly? Secure? SameSite?)
[ ] localStorage (visible in requests?)
[ ] Header only

Transmission:
[ ] Authorization header
[ ] Cookie header
[ ] Query parameter (dangerous)
[ ] Request body
```

#### Step A2: Analyze Token/Session Structure

For JWT tokens:
```
1. Decode token (base64)
2. Examine header: algorithm, type
3. Examine payload: claims, expiration, user ID
4. Note: Is signature validated? (test later)

Red Flags:
- alg: "none" 
- alg: "HS256" with guessable secret
- No expiration (exp claim)
- Sensitive data in payload
- User role in token (can be tampered?)
```

For session cookies:
```
1. Examine cookie attributes
2. Check randomness/entropy
3. Look for patterns across sessions

Red Flags:
- Sequential session IDs
- Predictable patterns
- Missing HttpOnly
- Missing Secure flag
- Missing SameSite
```

#### Step A3: Map Auth Endpoints

```
Endpoint                  | Purpose              | Risk Level
--------------------------|----------------------|-----------
POST /auth/login          | User authentication  | Critical
POST /auth/register       | Account creation     | High
POST /auth/forgot-password| Password reset       | Critical
POST /auth/reset-password | Password change      | Critical
POST /auth/token/refresh  | Token renewal        | High
GET  /auth/verify-email   | Email verification   | Medium
POST /auth/logout         | Session termination  | Medium
GET  /auth/me             | Current user info    | Medium
POST /oauth/authorize     | OAuth flow start     | High
GET  /oauth/callback      | OAuth callback       | Critical
```

---

### Phase B: Authentication Bypass Testing

#### Test B1: Missing Authentication Check

```
Scenario: Protected endpoint accessible without auth
Method: Remove auth header/cookie entirely

For each protected endpoint:
1. Capture authenticated request
2. Remove Authorization header (or session cookie)
3. Send request
4. Expected: 401 Unauthorized
5. Vulnerable: 200 OK with data

Document:
- Endpoint
- Normal auth requirement
- Response without auth
- Burp request ID
```

#### Test B2: Broken Authentication Logic

```
Scenario: Auth check exists but flawed

Tests:
- Empty token: Authorization: Bearer 
- Malformed token: Authorization: Bearer xxx
- Expired token: Use old/expired token
- Wrong type: Cookie instead of Bearer
- Case sensitivity: AUTHORIZATION vs Authorization
- Extra spaces: Authorization:  Bearer token
- Null bytes: Authorization: Bearer token%00extra

For each test:
1. Modify auth header
2. Send to protected endpoint
3. Expected: 401
4. Vulnerable: 200 or different auth error
```

#### Test B3: JWT Algorithm Confusion

```
Scenario: JWT signature not properly validated

Tests:
1. alg:none attack
   - Change header to {"alg": "none", "typ": "JWT"}
   - Remove signature
   - Submit: header.payload.
   
2. Algorithm switching
   - If RS256, try HS256 with public key as secret
   - Sign modified token
   
3. Signature stripping
   - Submit token without signature part
   
4. Key confusion
   - Try signing with known weak keys
   - Try kid (key id) injection

For each test:
- Expected: 401 (signature invalid)
- Vulnerable: 200 (token accepted)
```

#### Test B4: Token Manipulation

```
Scenario: Token payload can be modified

For JWT:
1. Decode payload
2. Modify user_id, role, permissions
3. Re-encode (if no signature check) or try alg:none
4. Submit modified token

For opaque tokens:
1. Look for patterns (sequential, encoded user info)
2. Try decoding (base64, hex)
3. If decodable, modify and re-encode
4. Submit modified token
```

---

### Phase C: Session Management Testing

#### Test C1: Session Fixation

```
Scenario: Attacker can set victim's session

Test:
1. Get session ID before login
2. Login with credentials
3. Check if session ID changed
4. Expected: New session ID after login
5. Vulnerable: Same session ID

Also test:
- Can session be set via URL parameter?
- Can session be set via form field?
```

#### Test C2: Session Expiration

```
Scenario: Sessions don't expire properly

Tests:
1. Idle timeout
   - Login, wait, check if session valid
   - Expected: Session expires after idle period
   
2. Absolute timeout
   - Old session still works days later?
   - Expected: Maximum session lifetime enforced
   
3. Logout invalidation
   - Login, get session
   - Logout
   - Use old session token
   - Expected: 401 (session invalidated)
   - Vulnerable: Still works
```

#### Test C3: Concurrent Sessions

```
Scenario: No limit on concurrent sessions

Tests:
1. Login from multiple browsers/contexts
2. Check if old sessions invalidated
3. Check if notification of new login

Security consideration:
- Unlimited sessions = compromised token stays valid
- No session visibility = user can't see compromise
```

#### Test C4: Session Cookie Security

```
Check for each session cookie:

[ ] HttpOnly flag set
    - Missing: XSS can steal session
    
[ ] Secure flag set  
    - Missing: Session sent over HTTP
    
[ ] SameSite attribute
    - None: CSRF possible
    - Lax: Limited CSRF protection
    - Strict: Full CSRF protection
    
[ ] Appropriate expiration
    - Session vs persistent
    - Reasonable timeout
```

---

### Phase D: Authorization Testing

#### Test D1: Horizontal Privilege Escalation

```
Scenario: User A can perform actions as User B

Test:
1. User A performs action on User A's resource
2. Change resource identifier to User B's
3. Expected: 403 Forbidden
4. Vulnerable: Action performed

Examples:
- GET /users/123/settings → GET /users/456/settings
- PUT /orders/A-001 → PUT /orders/B-002
- DELETE /posts/111 → DELETE /posts/222
```

#### Test D2: Vertical Privilege Escalation

```
Scenario: Regular user accesses admin functions

Test:
1. Identify admin-only endpoints from traffic
2. Access with regular user token
3. Expected: 403 Forbidden
4. Vulnerable: Admin function accessible

Common admin endpoints:
- /admin/*
- /manage/*
- /internal/*
- /api/admin/*
- User management, config, logs
```

#### Test D3: Function-Level Access Control

```
Scenario: Authorization only checked on some functions

Test for each sensitive operation:
1. Can regular user access?
2. Can user perform action on others' data?
3. Are all HTTP methods checked? (GET might work, but POST?)

Common misses:
- GET checked, PUT not checked
- Create checked, delete not checked
- List checked, export not checked
```

#### Test D4: Parameter-Based Access Control

```
Scenario: Role/permission passed as parameter

Look for:
- role=admin in requests
- isAdmin=true
- permissions[]=write
- user_type=administrator

Test:
1. Add/modify role parameter in request
2. Expected: Server ignores client-provided role
3. Vulnerable: Elevated privileges granted
```

---

## Evidence Requirements

For each finding, document:

### Authentication Bypass
```
Finding: [Endpoint] accessible without authentication
Severity: [Critical/High based on data exposure]

Evidence:
1. Normal request with auth → 200 OK
2. Same request without auth → Should be 401, got 200

Request (no auth):
[Full HTTP request]

Response:
[Full HTTP response showing data access]

Burp ID: #XXXX
```

### Authorization Flaw
```
Finding: [Action] possible across user contexts
Severity: [Based on impact]

Evidence:
1. User A's token
2. Attempt to access User B's resource
3. Response showing unauthorized access

Request:
[Full HTTP request with User A token to User B resource]

Response:
[Data that should belong to User B only]

Burp ID: #XXXX
```

---

## Common False Positives

### Intentionally Public Endpoints
```
Some endpoints don't require auth by design:
- /health, /status
- /public/*
- Login, registration endpoints
- Public content APIs

Verify with business logic before reporting
```

### Cached Responses
```
Response might be cached from authenticated request
- Check Cache-Control headers
- Try with unique cache-busting param
- Test in incognito/fresh session
```

### Rate Limiting Disguised as Auth
```
Some APIs return 401/403 for rate limiting
- Verify it's actually auth failure
- Check X-RateLimit headers
- Wait and retry
```

---

## Output Format

Write findings to `output/findings/auth.md`:

```markdown
# Authentication & Authorization Findings

## Summary
- Auth Mechanism: JWT Bearer Token
- Endpoints Tested: 24
- Critical Issues: 2
- High Issues: 3
- Medium Issues: 1

---

## Finding 1: JWT Algorithm None Accepted

**Severity**: Critical
**Category**: Authentication Bypass

### Description
The API accepts JWT tokens with algorithm set to "none", 
allowing complete authentication bypass.

### Evidence

**Modified Token** (alg: none):
\`\`\`
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxMjMsInJvbGUiOiJhZG1pbiJ9.
\`\`\`

**Request**:
\`\`\`http
GET /api/admin/users HTTP/1.1
Authorization: Bearer eyJhbGciOiJub25lIi...
\`\`\`

**Response**: 200 OK with admin data

**Burp ID**: #2345

### Impact
- Complete authentication bypass
- Any user can forge tokens
- Admin access achievable

### Remediation
1. Explicitly validate algorithm matches expected (RS256/HS256)
2. Reject "none" algorithm entirely
3. Use well-tested JWT library
```

---

## Testing Checklist

```
Authentication:
[ ] Auth mechanism identified and documented
[ ] Token/session structure analyzed
[ ] Missing auth check tested on all protected endpoints
[ ] Auth header manipulation tested
[ ] JWT algorithm attacks tested (if applicable)
[ ] Token manipulation tested
[ ] Expired token handling verified

Session Management:
[ ] Session fixation tested
[ ] Logout invalidation verified
[ ] Session timeout tested
[ ] Cookie security flags checked
[ ] Concurrent session handling noted

Authorization:
[ ] Horizontal escalation tested (user to user)
[ ] Vertical escalation tested (user to admin)
[ ] All HTTP methods tested per endpoint
[ ] Parameter-based access control tested
[ ] Role manipulation tested

Documentation:
[ ] All findings have evidence
[ ] False positives eliminated
[ ] Severity accurately assessed
[ ] Output written to findings/auth.md
```
