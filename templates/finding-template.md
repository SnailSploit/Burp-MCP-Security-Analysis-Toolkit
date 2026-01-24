# Finding Template

Use this template when documenting findings in output/findings/{indicator}.md

---

## Finding: {Title}

**Severity**: {Critical|High|Medium|Low|Informational}
**Indicator**: {idor|bola|auth_bypass|ssrf|injection|etc}
**Endpoint**: {METHOD} {path}
**Parameter**: {affected parameter if applicable}

### Description

{2-4 sentences explaining:
- What the vulnerability is
- What the application fails to do
- What an attacker can achieve}

### Evidence

**Setup/Context**:
{Explain the test setup - user contexts, prerequisites}

**Request**:
```http
{Full HTTP request that demonstrates the vulnerability}
```

**Response**:
```http
{Relevant portion of HTTP response}
```

**Proof of Vulnerability**:
{Explain why this proves the issue - e.g., "User A successfully accessed User B's data"}

**Burp Request ID**: #{id}

### Impact

{Specific impacts of this vulnerability}

- {Impact 1 - e.g., "Attacker can access any user's profile data"}
- {Impact 2 - e.g., "PII including email, phone, address exposed"}
- {Impact 3 - e.g., "Enumeration of all user IDs is possible"}

### Remediation

**Primary Fix**:
{Main remediation approach}

**Code Example** (if applicable):
```{language}
{Example of secure implementation}
```

**Additional Recommendations**:
- {Recommendation 1}
- {Recommendation 2}

### References

- {OWASP reference if applicable}
- {CWE reference if applicable}
- {Relevant documentation}

---

<!-- 
Checklist before submitting finding:
[ ] Severity accurately reflects impact
[ ] Evidence clearly demonstrates vulnerability
[ ] Request/response captured from Burp
[ ] Burp ID recorded for traceability
[ ] Impact is specific to this vulnerability
[ ] Remediation is actionable
[ ] No sensitive data left unredacted (if report will be shared)
-->
