# SKILL: Burp MCP Query Patterns

This skill defines how to effectively query Burp Suite via MCP to extract relevant security data.

## MCP Tool Reference

### Core Tools

| Tool | Purpose | When to Use |
|------|---------|-------------|
| `get_proxy_history` | Retrieve all intercepted HTTP traffic | Phase 2 triage, Phase 3 analysis |
| `get_sitemap` | Get hierarchical site structure | Initial reconnaissance |
| `get_scope` | View Burp's scope configuration | Scope validation |
| `send_to_repeater` | Queue request for manual testing | Follow-up on findings |
| `send_to_intruder` | Queue request for automated testing | Fuzzing, enumeration |

### Query Strategies

## Strategy 1: Bulk Retrieval (Triage Phase)

When triaging, get everything in scope first, then filter locally:

```
# Get all proxy history
result = get_proxy_history()

# Filter in your analysis:
# - By host (scope.target)
# - By path (scope.include patterns)
# - Exclude noise (scope.exclude patterns)
```

**Why**: Single query, local filtering is faster than many filtered queries.

## Strategy 2: Targeted Retrieval (Analysis Phase)

When analyzing specific indicators, query for relevant patterns:

```
# For IDOR analysis - get requests with ID patterns
# Look for: /users/123, /orders/456, ?id=789

# For Auth analysis - get auth-related endpoints
# Look for: /login, /auth, /token, /session, Authorization headers

# For SSRF - get requests with URL parameters
# Look for: url=, redirect=, callback=, next=
```

## Strategy 3: Comparative Retrieval (Multi-Context Testing)

When testing authorization, compare requests across user contexts:

```
# Identify requests with auth tokens
# Group by endpoint
# Compare: Same endpoint + Different auth = Different response?
```

## Data Structure Reference

### Proxy History Entry

Each entry from `get_proxy_history` typically contains:

```json
{
  "id": 1234,
  "host": "api.example.com",
  "port": 443,
  "protocol": "https",
  "method": "GET",
  "path": "/api/users/123",
  "request": {
    "headers": [...],
    "body": "..."
  },
  "response": {
    "status_code": 200,
    "headers": [...],
    "body": "..."
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Key Fields for Analysis

| Field | Use Case |
|-------|----------|
| `path` | Endpoint classification, ID extraction |
| `method` | CRUD operation identification |
| `request.headers` | Auth tokens, custom headers |
| `request.body` | POST data, JSON payloads |
| `response.status_code` | Success/failure, auth state |
| `response.body` | Data exposure, error messages |

## Filtering Patterns

### Scope Filtering (Always Apply First)

```python
def is_in_scope(entry, scope):
    # Check host matches target
    if entry['host'] not in scope['targets']:
        return False
    
    # Check path matches include patterns
    path = entry['path']
    if not any(re.match(p, path) for p in scope['include']):
        return False
    
    # Check path doesn't match exclude patterns
    if any(re.match(p, path) for p in scope['exclude']):
        return False
    
    return True
```

### Noise Filtering

Always exclude these patterns unless specifically relevant:

```
# Static assets
.*\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)$

# Framework noise
^/_next/.*
^/__webpack_hmr.*
^/sockjs-node/.*

# Common third-party
.*google-analytics\.com.*
.*googleapis\.com.*
.*cloudflare\.com.*
.*sentry\.io.*
.*segment\.io.*
```

### Interest Filtering

Prioritize these patterns:

```
# High Interest - API endpoints with IDs
/api/.*/[0-9]+
/api/.*/[a-f0-9-]{36}  # UUID
/v[0-9]+/.*/[0-9]+

# High Interest - Auth endpoints
/auth/.*
/login
/logout
/token
/oauth/.*
/session/.*

# High Interest - Admin/internal
/admin/.*
/internal/.*
/manage/.*
/dashboard/.*

# Medium Interest - Data operations
.*\?.*id=
.*\?.*user=
.*\?.*account=
```

## Efficient Query Patterns

### Pattern 1: Get Unique Endpoints

```python
# From all proxy history, extract unique endpoint signatures
endpoints = {}
for entry in proxy_history:
    # Normalize path (replace IDs with placeholders)
    normalized = normalize_path(entry['path'])
    key = f"{entry['method']} {normalized}"
    
    if key not in endpoints:
        endpoints[key] = {
            'method': entry['method'],
            'path_pattern': normalized,
            'example_ids': [],
            'request_ids': []
        }
    
    endpoints[key]['request_ids'].append(entry['id'])
```

### Pattern 2: Group by Auth Context

```python
# Group requests by authentication token
contexts = {}
for entry in proxy_history:
    auth_header = get_header(entry, 'Authorization')
    token_hash = hash(auth_header) if auth_header else 'anonymous'
    
    if token_hash not in contexts:
        contexts[token_hash] = []
    
    contexts[token_hash].append(entry)
```

### Pattern 3: Extract Object References

```python
# Find all object IDs in requests
import re

id_patterns = [
    r'/(\d+)',                    # Numeric in path
    r'/([a-f0-9-]{36})',          # UUID in path
    r'[?&]id=(\d+)',              # Numeric in query
    r'[?&]id=([a-f0-9-]{36})',    # UUID in query
    r'"id"\s*:\s*(\d+)',          # Numeric in JSON
    r'"id"\s*:\s*"([^"]+)"',      # String in JSON
]

def extract_ids(entry):
    ids = []
    text = entry['path'] + entry.get('request', {}).get('body', '')
    
    for pattern in id_patterns:
        matches = re.findall(pattern, text)
        ids.extend(matches)
    
    return ids
```

## Response Analysis Patterns

### Detect Sensitive Data Exposure

```python
sensitive_patterns = [
    r'"email"\s*:\s*"[^"]+"',
    r'"password"\s*:',
    r'"ssn"\s*:\s*"[^"]+"',
    r'"credit_card"\s*:',
    r'"api_key"\s*:\s*"[^"]+"',
    r'"secret"\s*:\s*"[^"]+"',
    r'"token"\s*:\s*"[^"]+"',
    r'"private_key"\s*:',
]

def check_sensitive_data(response_body):
    findings = []
    for pattern in sensitive_patterns:
        if re.search(pattern, response_body, re.IGNORECASE):
            findings.append(pattern)
    return findings
```

### Detect Error Information Disclosure

```python
error_patterns = [
    r'stack\s*trace',
    r'exception',
    r'sql.*error',
    r'mysql.*error',
    r'postgres.*error',
    r'ORA-\d+',
    r'at\s+[\w.]+\([\w.]+:\d+\)',  # Stack frames
    r'File\s+"[^"]+",\s+line\s+\d+',  # Python traces
]
```

## Rate Limiting Considerations

- Burp MCP queries are local, but excessive queries slow analysis
- Batch operations where possible
- Cache results between phases (endpoints.json)
- Don't re-query for data you already have

## Troubleshooting

### No Data Returned
1. Check Burp proxy is running
2. Check MCP server is connected
3. Check scope is set in Burp
4. Check traffic was captured (Proxy > HTTP history)

### Partial Data
1. Check filters in Burp aren't hiding traffic
2. Check MCP query isn't being limited
3. Check timestamp range if time-filtered

### Connection Issues
1. Verify MCP server URL (default: http://127.0.0.1:9876)
2. Check Caddy proxy if using (for CORS issues)
3. Restart Burp MCP extension

## Output Format

When passing data to other phases, normalize to:

```json
{
  "id": "burp_request_id",
  "endpoint": "GET /api/users/{id}",
  "method": "GET",
  "path": "/api/users/123",
  "path_normalized": "/api/users/{id}",
  "params": {"id": "123"},
  "auth_context": "user_a|user_b|anonymous",
  "request_summary": {
    "content_type": "application/json",
    "has_body": false,
    "custom_headers": ["X-Custom-Header"]
  },
  "response_summary": {
    "status": 200,
    "content_type": "application/json",
    "size_bytes": 1234,
    "sensitive_data_flags": []
  }
}
```
