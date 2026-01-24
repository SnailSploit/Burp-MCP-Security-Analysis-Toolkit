# SKILL: BOLA Testing Methodology

Broken Object Level Authorization (BOLA), also known as IDOR at the authorization layer, occurs when APIs expose endpoints that handle object identifiers but fail to verify the user has permission to access the specific object.

## BOLA vs IDOR

| Aspect | IDOR | BOLA |
|--------|------|------|
| Focus | Direct object reference | Authorization check |
| Question | "Can I guess the ID?" | "Am I authorized for this ID?" |
| Fix | Indirect references | Proper authz checks |
| OWASP | Listed under IDOR | API Top 10 #1 |

BOLA is the API-specific manifestation of broken access control.

---

## Severity Context

| Scenario | Severity |
|----------|----------|
| Access other users' PII | Critical |
| Modify other users' data | Critical |
| Delete other users' resources | Critical |
| Read other users' non-sensitive data | High |
| Access other tenants' data (multi-tenant) | Critical |
| Enumerate object existence | Medium |

---

## Prerequisites

1. ✅ Endpoints triaged with `bola` indicator
2. ✅ Multiple user contexts with different permissions/tenants
3. ✅ Understanding of the application's object model
4. ✅ Object IDs captured for multiple users

---

## Methodology

### Phase A: Object Model Analysis

#### Step A1: Identify Objects and Ownership

Map the application's data model:

```
Object Type     | Ownership Model    | Examples from Traffic
----------------|--------------------|-----------------------
User            | Self               | /api/users/{id}
Profile         | Belongs to User    | /api/profiles/{id}
Order           | Belongs to User    | /api/orders/{id}
Document        | Belongs to User    | /api/documents/{id}
Organization    | Tenant (multi-org) | /api/orgs/{id}
Team            | Belongs to Org     | /api/orgs/{org_id}/teams/{id}
Project         | Belongs to Team    | /api/projects/{id}
```

#### Step A2: Map Object Relationships

```
Hierarchical:
Organization → Team → Project → Task

Flat:
User → Orders
User → Documents  
User → Settings

Shared:
Document ← shared with → Multiple Users
Project ← members → Multiple Users
```

#### Step A3: Identify Authorization Contexts

```
Context          | Who can access what
-----------------|--------------------------------------------
Owner            | Full access to own resources
Team Member      | Access to team resources
Org Admin        | Access to all org resources
System Admin     | Access to everything
Public           | Access to public resources only
Shared Access    | Access to explicitly shared resources
```

---

### Phase B: Systematic BOLA Testing

#### Test B1: Horizontal Access (User to User)

```
Scenario: User A accesses User B's resources

For each object type:
1. Identify User A's object IDs (from A's traffic)
2. Identify User B's object IDs (from B's traffic)
3. Request User B's objects with User A's token

Test Matrix:
┌────────────────┬──────────────┬──────────────┬──────────────┐
│ Endpoint       │ User A's ID  │ User B's ID  │ User A Token │
├────────────────┼──────────────┼──────────────┼──────────────┤
│ GET /orders/X  │ order-001    │ order-002    │ A requests   │
│                │              │              │ order-002    │
├────────────────┼──────────────┼──────────────┼──────────────┤
│ PUT /orders/X  │ order-001    │ order-002    │ A modifies   │
│                │              │              │ order-002    │
├────────────────┼──────────────┼──────────────┼──────────────┤
│ DELETE /orders │ order-001    │ order-002    │ A deletes    │
│                │              │              │ order-002    │
└────────────────┴──────────────┴──────────────┴──────────────┘

Expected: 403 Forbidden or 404 Not Found
Vulnerable: 200 OK (or 204 for DELETE)
```

#### Test B2: Vertical Access (Role Escalation)

```
Scenario: Regular user accesses admin/elevated resources

For each privileged operation:
1. Identify admin-only objects/endpoints
2. Request with regular user token

Examples:
- Regular user requests admin dashboard data
- Regular user modifies system settings
- Regular user accesses other users' management
- Member requests owner-only actions

Expected: 403 Forbidden
Vulnerable: 200 OK with elevated data/action
```

#### Test B3: Cross-Tenant Access (Multi-Tenant)

```
Scenario: Tenant A accesses Tenant B's resources

Critical for SaaS applications:
1. Identify Tenant A's org_id
2. Identify Tenant B's org_id
3. User from Tenant A requests Tenant B resources

Test:
GET /api/orgs/{tenant_b_id}/users
GET /api/orgs/{tenant_b_id}/data
GET /api/reports?org_id={tenant_b_id}

Expected: 403 or 404 (should not even acknowledge existence)
Vulnerable: 200 with cross-tenant data

THIS IS CRITICAL - Tenant isolation breach
```

#### Test B4: Nested Object Access

```
Scenario: Access nested objects through parent manipulation

Example hierarchy: /orgs/{org}/teams/{team}/projects/{project}

Tests:
1. Valid: /orgs/A/teams/A1/projects/PA1 (User owns all)
2. Attack: /orgs/A/teams/A1/projects/PB1 (Project from different tree)
3. Attack: /orgs/A/teams/B1/projects/PB1 (Team from different tree)

Some APIs only check leaf object, not full path ownership
```

#### Test B5: Indirect Object Reference

```
Scenario: Object referenced indirectly

Examples:
- /api/export?report_id=123 (report_id not in URL path)
- POST /api/share {"document_id": "456"}
- GET /api/download?file=789

These are often missed in access control implementations
Test same as direct references but via parameters
```

---

### Phase C: All HTTP Methods Testing

For each BOLA-candidate endpoint, test ALL methods:

```
Endpoint: /api/documents/{id}

┌────────┬──────────────────────────────────────────────────┐
│ Method │ Test                                             │
├────────┼──────────────────────────────────────────────────┤
│ GET    │ Read other user's document                       │
│ PUT    │ Modify other user's document                     │
│ PATCH  │ Partially modify other user's document           │
│ DELETE │ Delete other user's document                     │
│ POST   │ Create resource under other user's namespace     │
│ HEAD   │ Check existence without body (info disclosure)   │
│ OPTIONS│ Usually safe, but check for sensitive info       │
└────────┴──────────────────────────────────────────────────┘

Common pattern: GET is protected, but PUT/DELETE are not
```

---

### Phase D: Edge Case Testing

#### Test D1: ID Type Manipulation

```
If IDs are numeric, try:
- 0, -1, 999999999 (boundary values)
- ID+1, ID-1 (adjacent records)
- Own ID in different format (123 vs "123" vs 0x7B)

If IDs are UUIDs, try:
- All zeros UUID
- All ones UUID
- Swapped UUIDs from other users' traffic
- Modified UUID (change one character)
```

#### Test D2: Bulk Operations

```
Endpoint: POST /api/bulk-action
Body: {"ids": ["own-id-1", "other-user-id-1", "other-user-id-2"]}

Test if bulk operations check ALL IDs or just first one
Mixed legitimate + illegitimate IDs in same request
```

#### Test D3: Search and Filter Bypass

```
Endpoint: GET /api/documents?owner_id=X

Tests:
1. Change owner_id to other user
2. Remove owner_id entirely
3. Add multiple owner_ids: owner_id=A&owner_id=B
4. Try wildcard: owner_id=*
5. Try SQL-like: owner_id=1 OR 1=1

Some filters are client-side only or bypassable
```

#### Test D4: State Transition Attacks

```
Scenario: Access via state manipulation

Example - Order workflow:
1. Create order (state: draft)
2. Submit order (state: pending)
3. Admin approves (state: approved)

Attack: 
- Can User A change User B's draft to submitted?
- Can User A cancel User B's approved order?
- State transitions often have weaker authz
```

---

## API Pattern Analysis

### REST API Patterns

```
Resource-based URLs most likely BOLA targets:

GET    /api/users/{id}           → User profile
GET    /api/users/{id}/orders    → User's orders
PUT    /api/orders/{id}          → Modify order
DELETE /api/orders/{id}          → Delete order
POST   /api/users/{id}/documents → Create doc for user
```

### GraphQL Patterns

```
Query patterns to test:

query {
  user(id: "other-user-id") {
    email
    orders {
      id
      total
    }
  }
}

mutation {
  updateUser(id: "other-user-id", input: {email: "attacker@..."}) {
    id
  }
}

Node interface:
query {
  node(id: "base64-encoded-other-user-id") {
    ... on User { email }
  }
}
```

### Nested Routes

```
/api/orgs/{org_id}/                    → Org access
/api/orgs/{org_id}/members             → Org members
/api/orgs/{org_id}/teams/{team_id}     → Team in org
/api/orgs/{org_id}/teams/{team_id}/... → Deeper nesting

Test at each level:
- Correct org, wrong team
- Wrong org, "correct" team ID
- Mixed valid/invalid in path
```

---

## Evidence Requirements

For each BOLA finding:

```
Finding: BOLA - Cross-User Order Access
Severity: High

Proof Requirements:
1. ✅ Authenticated as User A (show token claims or /me response)
2. ✅ Object ID belongs to User B (show how we know)
3. ✅ Successful access/modification (show response data)
4. ✅ Data confirms it's User B's (ownership proof)

Evidence Structure:

Step 1 - Confirm User A's identity:
GET /api/me → {"id": "user-a-123", "email": "usera@..."}

Step 2 - Identify User B's object:
(From User B's traffic): GET /api/orders/order-b-456 
Response shows: {"id": "order-b-456", "user_id": "user-b-789"}

Step 3 - User A requests User B's object:
GET /api/orders/order-b-456
Authorization: Bearer [User A's token]

Response:
HTTP/1.1 200 OK
{"id": "order-b-456", "user_id": "user-b-789", "total": 299.99, ...}

Step 4 - Confirm unauthorized access:
User A (id: user-a-123) accessed order belonging to User B (user_id: user-b-789)

Burp Request IDs: #1001 (identity), #1002 (attack)
```

---

## Output Format

Write findings to `output/findings/bola.md`:

```markdown
# BOLA Analysis Findings

## Summary
- Object Types Tested: 6
- Endpoints Tested: 18
- Critical BOLA: 2
- High BOLA: 3

---

## Finding 1: Cross-User Document Access and Modification

**Severity**: Critical
**Endpoint**: GET/PUT /api/documents/{id}
**Object**: Document

### Description
The document API allows any authenticated user to read and modify 
any document by ID, regardless of ownership.

### Evidence

**Attacker Context**:
User A - ID: user-123, Token: eyJ...

**Victim's Document** (from Victim's traffic):
Document ID: doc-789, Owner: user-456

**Attack Request**:
\`\`\`http
GET /api/documents/doc-789 HTTP/1.1
Authorization: Bearer [User A token]
\`\`\`

**Response**:
\`\`\`json
{
  "id": "doc-789",
  "owner_id": "user-456",
  "title": "Confidential Report",
  "content": "Sensitive data..."
}
\`\`\`

User A (user-123) successfully accessed User B's (user-456) document.

**Modification Test**:
\`\`\`http
PUT /api/documents/doc-789 HTTP/1.1
Authorization: Bearer [User A token]
Content-Type: application/json

{"title": "Modified by attacker"}
\`\`\`

Response: 200 OK - Document modified

**Burp IDs**: #2001, #2002

### Impact
- Any user can read any document
- Any user can modify any document
- Complete breakdown of document access control

### Remediation
1. Verify document.owner_id matches requesting user.id
2. Or verify user is in document's share list
3. Return 404 (not 403) to prevent enumeration
```

---

## Testing Checklist

```
Object Model:
[ ] All object types identified
[ ] Ownership model mapped
[ ] Hierarchies documented
[ ] Multi-tenant boundaries identified

Horizontal BOLA:
[ ] User A → User B access tested for each object type
[ ] All CRUD operations tested
[ ] Both GET and mutation methods tested

Vertical BOLA:
[ ] Regular user → admin resources tested
[ ] Role-specific actions tested
[ ] Privilege boundaries mapped

Multi-Tenant:
[ ] Cross-tenant access tested
[ ] Tenant isolation verified
[ ] Shared resources properly scoped

Edge Cases:
[ ] Bulk operations tested
[ ] Nested objects tested
[ ] Indirect references tested
[ ] State transitions tested
[ ] ID manipulation tested

Documentation:
[ ] Evidence for all findings
[ ] Ownership proof included
[ ] Multiple request IDs
[ ] Accurate severity
[ ] Output to findings/bola.md
```
