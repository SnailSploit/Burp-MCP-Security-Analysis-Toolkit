# SKILL: IDOR Testing Methodology

Insecure Direct Object Reference (IDOR) occurs when an application exposes internal object references (IDs) and fails to verify the requesting user has authorization to access the referenced object.

## Severity Context

| Data Exposed | Typical Severity |
|--------------|------------------|
| PII (SSN, DOB, address) | Critical |
| Financial data | Critical |
| Authentication credentials | Critical |
| User profile data | High |
| User-generated content | Medium-High |
| Non-sensitive metadata | Low |

---

## Prerequisites

Before starting IDOR analysis:

1. ✅ Endpoints triaged (endpoints.json exists)
2. ✅ Endpoints tagged with `idor` indicator loaded
3. ✅ Multiple auth contexts available in scope.yaml (user_a, user_b)
4. ✅ Traffic exists for both auth contexts

---

## Methodology

### Step 1: Identify Candidate Endpoints

Filter endpoints from endpoints.json where:

```
indicators CONTAINS 'idor'
OR
path_pattern MATCHES /.*\{id\}.*/
OR
path_pattern MATCHES /.*\{uuid\}.*/
OR
has query params: id, user_id, account_id, order_id, etc.
```

Sort candidates by interest_score descending.

### Step 2: Map Object References

For each candidate endpoint, document:

| Question | How to Determine |
|----------|------------------|
| What object type does the ID reference? | Examine response structure, field names |
| What data is returned? | Analyze response body |
| Is data user-specific? | Look for user identifiers, ownership fields |
| What operations are allowed? | Check HTTP methods (GET=read, PUT=modify, DELETE=remove) |

Create object reference map:

```
Endpoint: GET /api/users/{id}
Object Type: User Profile
Data Returned: email, name, address, phone, ssn_last4
User-Specific: YES (each user has unique profile)
Operations: GET (read), PUT (modify)
Ownership Field: response.id matches authenticated user's id

Endpoint: GET /api/orders/{id}
Object Type: Order
Data Returned: order_items, total, shipping_address, payment_method_last4
User-Specific: YES (orders belong to users)
Operations: GET (read), PUT (modify), DELETE (cancel)
Ownership Field: response.user_id
```

### Step 3: Identify Test Cases

For each mapped endpoint, define test cases:

#### Test Case Type A: Cross-User Access (Horizontal)
```
Scenario: User A requests User B's resource
Expected: 403 Forbidden or 404 Not Found
Vulnerable: 200 OK with User B's data

Setup:
1. Identify resource ID belonging to User B (from User B's traffic)
2. Craft request to that ID using User A's auth token
3. Check response
```

#### Test Case Type B: Privilege Escalation (Vertical)
```
Scenario: Regular user requests admin-only resource
Expected: 403 Forbidden
Vulnerable: 200 OK with admin data

Setup:
1. Identify admin resource IDs (if visible in traffic)
2. Request with regular user token
3. Check response
```

#### Test Case Type C: Unauthenticated Access
```
Scenario: No auth token, request user resource
Expected: 401 Unauthorized
Vulnerable: 200 OK with data

Setup:
1. Take any resource ID
2. Request without auth token
3. Check response
```

### Step 4: Execute Testing

For each test case, document:

```
TEST: [Endpoint] - [Test Type]
REQUEST:
  Method: GET
  URL: /api/users/456
  Auth: User A token (user_id=123)
  
EXPECTED:
  Status: 403 or 404
  Body: Error message
  
ACTUAL:
  Status: 200
  Body: {"id": 456, "email": "userb@example.com", ...}
  
RESULT: VULNERABLE
EVIDENCE: Burp Request ID #1234
```

### Step 5: Validate Findings

A valid IDOR finding MUST have:

| Requirement | Description |
|-------------|-------------|
| ✅ Cross-context proof | Request made with User A's auth |
| ✅ Different object | Resource ID belongs to User B |
| ✅ Data returned | Response contains User B's actual data |
| ✅ Not cached | Response is fresh (check headers, vary ID) |
| ✅ Not public data | Data should be private/user-specific |

### Step 6: Assess Impact

Rate each confirmed IDOR:

```
CRITICAL:
- PII exposure (SSN, government ID, DOB)
- Financial data (full card numbers, bank accounts)
- Credentials exposure (passwords, API keys)
- Mass data extraction possible

HIGH:
- User profile data (email, phone, address)
- Order/transaction history
- Private messages/communications
- Modification capability (PUT/PATCH/DELETE)

MEDIUM:
- Non-sensitive user content
- Public-ish data that should still be protected
- Limited data exposure

LOW:
- Metadata only
- Already semi-public information
- No clear sensitivity
```

---

## Patterns to Check

### Numeric ID Manipulation

```
Original: GET /api/users/123
Test: GET /api/users/124, 125, 122, 1, 999999
Pattern: Sequential, adjacent IDs
```

### UUID Manipulation

```
Original: GET /api/orders/550e8400-e29b-41d4-a716-446655440000
Test: Use UUIDs from other user's traffic
Pattern: Cannot guess, must find valid IDs from traffic
```

### ID in Different Locations

```
Path: /api/users/{id}/profile
Query: /api/profile?user_id={id}
Body: {"user_id": "{id}"}
Header: X-User-ID: {id}
```

### Indirect References

```
Endpoint: GET /api/documents/{document_id}
The document_id might not be user ID, but document belongs to user
Need to verify requesting user owns the document
```

### Batch Endpoints

```
Endpoint: POST /api/users/batch
Body: {"ids": [123, 456, 789]}
Test: Include IDs of other users
Pattern: Array parameters accepting multiple IDs
```

### GraphQL

```
Query: query { user(id: "123") { email, ssn } }
Test: Change id to other user's ID
Pattern: ID arguments in GraphQL queries
```

---

## Evidence Collection

For each finding, collect:

1. **Full Request** (sanitize your own tokens if sharing)
```http
GET /api/users/456 HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJ... [User A's token]
```

2. **Full Response**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": 456,
  "email": "userb@example.com",
  "ssn_last4": "6789"
}
```

3. **Proof of Ownership**
- Show User A's ID is 123 (from their token or another request)
- Show the returned data (id: 456) belongs to different user

4. **Burp Request ID** for reproducibility

---

## Common False Positives

### Public Data
```
Endpoint returns same data regardless of auth
Data is intentionally public (e.g., public profile)
→ Not IDOR, working as intended
```

### Cached Responses
```
Response has Cache-Control headers
CDN/proxy might return stale data
→ Re-test with cache-busting, verify multiple IDs
```

### Error Exposure
```
Returns 200 but body says "Not found" or "Unauthorized"
Some APIs return 200 for all responses with error in body
→ Check actual data, not just status code
```

### Self-Reference
```
User A requests User A's data with User A's token
This is normal behavior
→ Must test CROSS-user access
```

---

## Output Format

Write findings to `output/findings/idor.md`:

```markdown
# IDOR Analysis Findings

## Summary
- Endpoints Tested: 12
- Confirmed Vulnerabilities: 3
- Suspected (needs verification): 2

---

## Finding 1: User Profile IDOR

**Severity**: Critical
**Endpoint**: GET /api/users/{id}
**Indicator**: idor

### Description
The user profile endpoint returns full user data including PII without 
verifying the requesting user owns the requested profile.

### Evidence

**Request** (User A token, requesting User B's data):
\`\`\`http
GET /api/users/456 HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJ... [User A - id:123]
\`\`\`

**Response**:
\`\`\`http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": 456,
  "email": "userb@example.com",
  "phone": "+1-555-123-4567",
  "ssn_last4": "6789",
  "address": "123 Main St..."
}
\`\`\`

**Burp Request ID**: #1234

### Impact
- Attacker can enumerate all user IDs (sequential)
- Full PII exposure for any user
- Potential for mass data exfiltration

### Remediation
1. Verify requesting user's ID matches requested resource ID
2. Or verify user has admin role for cross-user access
3. Return 403/404 for unauthorized access attempts

---

## Finding 2: ...
```

---

## Testing Checklist

```
[ ] All idor-tagged endpoints tested
[ ] Cross-user (horizontal) access tested
[ ] Privilege escalation (vertical) tested
[ ] Unauthenticated access tested
[ ] All HTTP methods tested (GET, PUT, DELETE)
[ ] Numeric IDs manipulated
[ ] UUIDs cross-referenced from different user traffic
[ ] Batch endpoints tested with mixed IDs
[ ] False positives eliminated
[ ] Evidence collected for all findings
[ ] Severity accurately assessed
[ ] Findings written to output/findings/idor.md
```
