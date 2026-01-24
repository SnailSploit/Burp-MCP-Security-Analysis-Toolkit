# SKILL: Endpoint Triage & Classification

This skill defines how to classify, filter, and prioritize endpoints for security analysis.

## Purpose

Transform raw Burp traffic into a prioritized list of interesting endpoints, filtering noise and tagging potential vulnerability indicators.

## Input

- Raw proxy history from Burp MCP
- Scope definition from scope.yaml

## Output

- `output/endpoints.json` - Structured, prioritized endpoint list

---

## Phase 2 Execution Steps

### Step 1: Scope Loading

```
1. Read scope.yaml
2. Parse target domains
3. Compile include regex patterns
4. Compile exclude regex patterns
5. Compile exclude extension list
6. Load enabled indicators
```

### Step 2: Traffic Retrieval

```
1. Query Burp MCP for all proxy history
2. Note total request count for statistics
```

### Step 3: Scope Filtering

Apply filters in this order:

```
1. DOMAIN FILTER
   - Keep only requests to target domains
   - Track: filtered_domain_count
   
2. PATH INCLUDE FILTER
   - Keep only paths matching include patterns
   - Track: filtered_path_include_count
   
3. PATH EXCLUDE FILTER
   - Remove paths matching exclude patterns
   - Track: filtered_path_exclude_count
   
4. EXTENSION FILTER
   - Remove requests for excluded extensions
   - Track: filtered_extension_count
   
5. THIRD-PARTY FILTER
   - Remove requests to known third-party domains
   - Track: filtered_thirdparty_count
```

### Step 4: Deduplication

```
1. Normalize paths (replace IDs with {id} placeholder)
2. Create endpoint signature: METHOD + normalized_path
3. Group requests by signature
4. Keep representative examples for each unique endpoint
```

### Step 5: Classification

Classify each unique endpoint into categories:

| Category | Indicators | Priority Boost |
|----------|------------|----------------|
| `API_DATA` | CRUD endpoints, JSON responses, resource paths | +2 |
| `API_AUTH` | /login, /logout, /token, /auth, /oauth, /session | +3 |
| `API_ADMIN` | /admin, /internal, /manage, /dashboard | +3 |
| `API_SEARCH` | Search params, query endpoints, pagination | +1 |
| `API_UPLOAD` | File upload, multipart/form-data | +2 |
| `GRAPHQL` | /graphql endpoint, query/mutation bodies | +2 |
| `WEBHOOK` | Callback URLs, async endpoints | +1 |
| `STATIC` | Images, scripts, styles | -5 |
| `UNKNOWN` | Doesn't match other categories | 0 |

### Step 6: Interest Scoring

Calculate interest score (0-10) for each endpoint:

```
Base Score: 5

ADDITIONS:
+3  Contains numeric ID in path (/users/123)
+3  Contains UUID in path (/orders/550e8400-...)
+2  Contains ID in query params (?user_id=123)
+2  Accepts POST/PUT/PATCH/DELETE methods
+2  Returns JSON with object data
+2  Has custom headers (X-*, non-standard)
+1  Multiple HTTP methods observed
+1  Returns large response (>1KB JSON)
+1  Contains sensitive-looking field names

SUBTRACTIONS:
-3  Static asset pattern
-2  Third-party domain (if somehow still present)
-2  Cached response indicators (304, strong ETag)
-1  Returns empty or minimal response
-1  Generic error responses only
```

### Step 7: Indicator Tagging

Tag endpoints with potential vulnerability indicators:

| Indicator | Detection Rules |
|-----------|-----------------|
| `idor` | Numeric/UUID ID in path or params; Returns user-specific data |
| `bola` | Object reference + ownership implied; Multi-tenant patterns |
| `auth_bypass` | Auth endpoints; Session management; Token handling |
| `ssrf` | URL params (url=, redirect=, callback=); Fetch/proxy patterns |
| `injection` | Search params; Filter params; Sort params; Free-text input |
| `info_disclosure` | Verbose errors; Debug endpoints; Stack traces |
| `rate_limit` | High-value operations; Auth attempts; Data export |

### Step 8: Prioritization

Sort endpoints by:

```
1. Interest score (descending)
2. Number of indicators tagged (descending)
3. Category priority boost (descending)
4. Request count (descending) - more traffic = more tested
```

### Step 9: Output Generation

Generate `output/endpoints.json`:

```json
{
  "metadata": {
    "generated_at": "2024-01-15T10:30:00Z",
    "scope": {
      "target": "api.example.com",
      "include_patterns": ["/api/*", "/v1/*"],
      "exclude_patterns": ["/static/*"]
    },
    "statistics": {
      "total_requests": 1247,
      "after_scope_filter": 312,
      "unique_endpoints": 47,
      "by_category": {
        "API_DATA": 23,
        "API_AUTH": 5,
        "API_ADMIN": 3,
        "API_SEARCH": 8,
        "API_UPLOAD": 2,
        "GRAPHQL": 1,
        "UNKNOWN": 5
      }
    }
  },
  
  "endpoints": {
    "high_priority": [
      {
        "signature": "GET /api/users/{id}",
        "method": "GET",
        "path_pattern": "/api/users/{id}",
        "example_paths": ["/api/users/123", "/api/users/456"],
        "category": "API_DATA",
        "interest_score": 9,
        "indicators": ["idor", "bola"],
        "observations": [
          "Returns full user object including PII",
          "No apparent ownership check in responses"
        ],
        "request_ids": [1001, 1002, 1003],
        "auth_contexts_seen": ["user_a", "user_b"]
      }
    ],
    
    "medium_priority": [...],
    
    "low_priority": [...],
    
    "filtered_out": {
      "count": 935,
      "by_reason": {
        "domain_mismatch": 234,
        "path_excluded": 156,
        "static_asset": 412,
        "third_party": 133
      }
    }
  }
}
```

---

## Classification Rules Detail

### API_DATA Detection

```
Positive signals:
- Path contains resource nouns: /users, /orders, /products, /accounts
- Returns JSON with object structure
- Supports multiple HTTP methods
- Contains ID references

Negative signals:
- Path is /health, /status, /ping
- Returns simple string/boolean
- No data payload
```

### API_AUTH Detection

```
Positive signals:
- Path contains: login, logout, auth, token, session, oauth, sso, saml
- Path contains: password, reset, verify, confirm, activate
- Request contains credentials in body
- Response sets auth cookies/tokens
- Authorization header manipulation

Endpoints to flag:
- POST /login
- POST /auth/token
- POST /oauth/authorize
- GET /oauth/callback
- POST /password/reset
- GET /session
- DELETE /logout
```

### API_ADMIN Detection

```
Positive signals:
- Path contains: admin, internal, manage, dashboard, console
- Path contains: config, settings, system, debug
- Elevated permission responses
- User management operations

Endpoints to flag:
- GET /admin/*
- POST /internal/*
- GET /manage/users
- PUT /system/config
```

### SSRF Indicator Detection

```
High confidence:
- Parameter named: url, uri, link, src, href
- Parameter named: redirect, callback, return, next, target
- Parameter named: proxy, fetch, load, request
- Parameter contains URL pattern: http://, https://

Medium confidence:
- Parameter named: path, file, page, document
- Parameter contains domain-like pattern
- Endpoint described as "webhook" or "callback"
```

### IDOR Indicator Detection

```
High confidence:
- Numeric ID in URL path: /resource/123
- UUID in URL path: /resource/550e8400-e29b-41d4-a716-446655440000
- ID parameter: ?id=123, ?user_id=456
- Response contains object owned by specific user

Medium confidence:
- Any identifier that could reference cross-user data
- Endpoints returning user-specific data
- CRUD operations on resources
```

---

## Path Normalization Rules

Replace dynamic segments with placeholders:

| Pattern | Replacement | Example |
|---------|-------------|---------|
| `/\d+` | `/{id}` | /users/123 → /users/{id} |
| `/[a-f0-9-]{36}` | `/{uuid}` | /orders/550e8400-... → /orders/{uuid} |
| `/[a-f0-9]{24}` | `/{objectid}` | MongoDB ObjectID |
| `/[A-Za-z0-9_-]{20,}` | `/{token}` | JWT segments, API keys |
| Timestamps | `/{timestamp}` | Unix timestamps in path |

---

## Quality Checks

Before outputting endpoints.json, verify:

1. **No scope violations** - All endpoints within defined scope
2. **No duplicates** - Each signature appears once
3. **Indicators validated** - Only tag indicators with evidence
4. **Scores reasonable** - No scores outside 0-10 range
5. **Examples present** - Each endpoint has at least one example request ID

---

## Common Pitfalls

### Over-filtering
- Don't filter too aggressively in early passes
- Keep borderline endpoints in low_priority, not filtered_out
- User can always ignore, but can't recover filtered data

### Under-classifying
- Don't leave too many endpoints as UNKNOWN
- Re-examine UNKNOWN endpoints for missed patterns
- Ask user for guidance on domain-specific patterns

### Indicator Spam
- Don't tag every endpoint with every indicator
- Require actual evidence for tagging
- Better to miss than to false positive

### Missing Context
- Always note auth contexts seen per endpoint
- Track which user tokens accessed which endpoints
- This is critical for IDOR/BOLA analysis later
