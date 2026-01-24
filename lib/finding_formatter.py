#!/usr/bin/env python3
"""
Finding Formatter - Consistent finding output generation.

Creates structured markdown findings from raw analysis data.

Usage:
    from finding_formatter import FindingFormatter, Finding, Severity
    
    finding = Finding(
        title="IDOR in /api/users/{id}",
        indicator="idor",
        severity=Severity.HIGH,
        endpoint="/api/users/123",
        method="GET",
        description="User A can access User B's profile data...",
        evidence=[...],
        ...
    )
    
    formatter = FindingFormatter()
    markdown = formatter.format(finding)
"""

import re
import json
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from pathlib import Path


class Severity(Enum):
    """Finding severity levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"
    
    @property
    def color(self) -> str:
        """Return color for severity badge."""
        colors = {
            "Critical": "red",
            "High": "orange", 
            "Medium": "yellow",
            "Low": "blue",
            "Informational": "gray"
        }
        return colors.get(self.value, "gray")
    
    @property
    def priority(self) -> int:
        """Return numeric priority for sorting (lower = more severe)."""
        priorities = {
            "Critical": 1,
            "High": 2,
            "Medium": 3,
            "Low": 4,
            "Informational": 5
        }
        return priorities.get(self.value, 5)


@dataclass
class Evidence:
    """Evidence item for a finding."""
    type: str  # "request", "response", "comparison", "screenshot"
    description: str
    content: str
    burp_request_id: Optional[str] = None
    redacted: bool = False


@dataclass
class Finding:
    """Security finding data structure."""
    # Required
    title: str
    indicator: str
    severity: Severity
    endpoint: str
    method: str
    description: str
    
    # Evidence
    evidence: List[Evidence] = field(default_factory=list)
    
    # Context
    affected_parameter: Optional[str] = None
    affected_object_type: Optional[str] = None
    auth_context: Optional[str] = None
    
    # Technical details
    request_sample: Optional[str] = None
    response_sample: Optional[str] = None
    burp_request_ids: List[str] = field(default_factory=list)
    
    # Impact
    impact: Optional[str] = None
    affected_data: Optional[str] = None
    
    # Remediation
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    cwe_id: Optional[str] = None
    
    # Metadata
    confidence: str = "High"  # High, Medium, Low
    false_positive_risk: str = "Low"
    timestamp: datetime = field(default_factory=datetime.now)
    analyst_notes: Optional[str] = None
    
    # ID for deduplication
    finding_id: Optional[str] = None
    
    def __post_init__(self):
        """Generate finding ID if not provided."""
        if not self.finding_id:
            # Create deterministic ID from key fields
            key = f"{self.indicator}:{self.endpoint}:{self.method}:{self.affected_parameter or ''}"
            self.finding_id = f"F-{hash(key) % 100000:05d}"


class FindingFormatter:
    """Formats findings into markdown output."""
    
    # Default remediation suggestions by indicator
    DEFAULT_REMEDIATION = {
        "idor": "Implement proper authorization checks that verify the requesting user has access to the requested resource. Use indirect references (mapping tables) instead of exposing internal IDs directly.",
        "bola": "Implement object-level authorization checks on every API endpoint that accesses resources. Verify user permissions for the specific object being accessed, not just authentication status.",
        "auth_bypass": "Review authentication flow for bypasses. Ensure all sensitive endpoints require valid authentication. Implement proper session management with secure token generation and validation.",
        "ssrf": "Validate and sanitize all user-supplied URLs. Use allowlists for permitted hosts/protocols. Disable unnecessary URL schemes. Implement network segmentation to limit internal access.",
        "injection": "Use parameterized queries or prepared statements. Implement input validation with allowlists. Apply context-appropriate output encoding. Use ORM frameworks that handle escaping automatically."
    }
    
    # CWE mappings
    CWE_MAPPINGS = {
        "idor": "CWE-639",
        "bola": "CWE-639", 
        "auth_bypass": "CWE-287",
        "ssrf": "CWE-918",
        "injection": "CWE-89"  # SQL, could also be CWE-78 for command
    }
    
    def __init__(self, redact_sensitive: bool = True):
        self.redact_sensitive = redact_sensitive
        self.sensitive_patterns = [
            (r'(Bearer\s+)[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+', r'\1[REDACTED_JWT]'),
            (r'(Authorization:\s*)[^\n]+', r'\1[REDACTED]'),
            (r'(api[_-]?key["\']?\s*[:=]\s*["\']?)[A-Za-z0-9\-_]+', r'\1[REDACTED]'),
            (r'(password["\']?\s*[:=]\s*["\']?)[^\s"\'&]+', r'\1[REDACTED]'),
            (r'(token["\']?\s*[:=]\s*["\']?)[A-Za-z0-9\-_]+', r'\1[REDACTED]'),
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[REDACTED_EMAIL]'),
        ]
    
    def format(self, finding: Finding) -> str:
        """Format a finding as markdown."""
        lines = []
        
        # Header
        lines.append(f"## {finding.finding_id}: {finding.title}")
        lines.append("")
        
        # Severity badge
        lines.append(f"**Severity:** {finding.severity.value} | **Indicator:** {finding.indicator.upper()} | **Confidence:** {finding.confidence}")
        lines.append("")
        
        # Summary table
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append(f"| Endpoint | `{finding.method} {finding.endpoint}` |")
        if finding.affected_parameter:
            lines.append(f"| Parameter | `{finding.affected_parameter}` |")
        if finding.auth_context:
            lines.append(f"| Auth Context | {finding.auth_context} |")
        if finding.cwe_id or self.CWE_MAPPINGS.get(finding.indicator):
            cwe = finding.cwe_id or self.CWE_MAPPINGS.get(finding.indicator)
            lines.append(f"| CWE | [{cwe}](https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html) |")
        lines.append("")
        
        # Description
        lines.append("### Description")
        lines.append("")
        lines.append(finding.description)
        lines.append("")
        
        # Impact
        if finding.impact:
            lines.append("### Impact")
            lines.append("")
            lines.append(finding.impact)
            lines.append("")
        
        # Evidence
        if finding.evidence:
            lines.append("### Evidence")
            lines.append("")
            for i, ev in enumerate(finding.evidence, 1):
                lines.append(f"**Evidence {i}:** {ev.description}")
                if ev.burp_request_id:
                    lines.append(f"*Burp Request ID: {ev.burp_request_id}*")
                lines.append("")
                content = self._redact(ev.content) if self.redact_sensitive else ev.content
                lines.append("```")
                lines.append(content)
                lines.append("```")
                lines.append("")
        
        # Request/Response samples (if not already in evidence)
        if finding.request_sample and not finding.evidence:
            lines.append("### Request Sample")
            lines.append("")
            content = self._redact(finding.request_sample) if self.redact_sensitive else finding.request_sample
            lines.append("```http")
            lines.append(content)
            lines.append("```")
            lines.append("")
        
        if finding.response_sample and not finding.evidence:
            lines.append("### Response Sample")
            lines.append("")
            content = self._redact(finding.response_sample) if self.redact_sensitive else finding.response_sample
            lines.append("```http")
            lines.append(content)
            lines.append("```")
            lines.append("")
        
        # Remediation
        lines.append("### Remediation")
        lines.append("")
        remediation = finding.remediation or self.DEFAULT_REMEDIATION.get(finding.indicator, "Review and fix the identified vulnerability.")
        lines.append(remediation)
        lines.append("")
        
        # References
        if finding.references:
            lines.append("### References")
            lines.append("")
            for ref in finding.references:
                lines.append(f"- {ref}")
            lines.append("")
        
        # Analyst notes
        if finding.analyst_notes:
            lines.append("### Analyst Notes")
            lines.append("")
            lines.append(finding.analyst_notes)
            lines.append("")
        
        # Footer
        lines.append("---")
        lines.append(f"*Generated: {finding.timestamp.strftime('%Y-%m-%d %H:%M:%S')}*")
        if finding.burp_request_ids:
            lines.append(f"*Burp Request IDs: {', '.join(finding.burp_request_ids)}*")
        lines.append("")
        
        return "\n".join(lines)
    
    def format_multiple(self, findings: List[Finding]) -> str:
        """Format multiple findings into a single document."""
        if not findings:
            return "# Findings Report\n\nNo findings to report.\n"
        
        lines = []
        
        # Sort by severity
        sorted_findings = sorted(findings, key=lambda f: f.severity.priority)
        
        # Header
        lines.append("# Security Findings Report")
        lines.append("")
        lines.append(f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
        lines.append("")
        
        # Summary
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"Total findings: **{len(findings)}**")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in Severity:
            count = len([f for f in findings if f.severity == sev])
            if count > 0:
                lines.append(f"| {sev.value} | {count} |")
        lines.append("")
        
        # Table of contents
        lines.append("## Table of Contents")
        lines.append("")
        for finding in sorted_findings:
            lines.append(f"- [{finding.finding_id}: {finding.title}](#{finding.finding_id.lower()}-{self._slugify(finding.title)})")
        lines.append("")
        
        # Individual findings
        lines.append("---")
        lines.append("")
        
        for finding in sorted_findings:
            lines.append(self.format(finding))
        
        return "\n".join(lines)
    
    def _redact(self, content: str) -> str:
        """Redact sensitive information from content."""
        for pattern, replacement in self.sensitive_patterns:
            content = re.sub(pattern, replacement, content, flags=re.IGNORECASE)
        return content
    
    def _slugify(self, text: str) -> str:
        """Convert text to URL-friendly slug."""
        text = text.lower()
        text = re.sub(r'[^a-z0-9\s-]', '', text)
        text = re.sub(r'[\s_]+', '-', text)
        return text.strip('-')


def finding_from_dict(data: Dict[str, Any]) -> Finding:
    """Create a Finding from a dictionary (e.g., from JSON)."""
    # Convert severity string to enum
    severity = Severity(data.get("severity", "Medium"))
    
    # Convert evidence dicts to Evidence objects
    evidence = []
    for ev in data.get("evidence", []):
        evidence.append(Evidence(
            type=ev.get("type", "request"),
            description=ev.get("description", ""),
            content=ev.get("content", ""),
            burp_request_id=ev.get("burp_request_id"),
            redacted=ev.get("redacted", False)
        ))
    
    return Finding(
        title=data["title"],
        indicator=data["indicator"],
        severity=severity,
        endpoint=data["endpoint"],
        method=data["method"],
        description=data["description"],
        evidence=evidence,
        affected_parameter=data.get("affected_parameter"),
        affected_object_type=data.get("affected_object_type"),
        auth_context=data.get("auth_context"),
        request_sample=data.get("request_sample"),
        response_sample=data.get("response_sample"),
        burp_request_ids=data.get("burp_request_ids", []),
        impact=data.get("impact"),
        affected_data=data.get("affected_data"),
        remediation=data.get("remediation"),
        references=data.get("references", []),
        cwe_id=data.get("cwe_id"),
        confidence=data.get("confidence", "High"),
        false_positive_risk=data.get("false_positive_risk", "Low"),
        analyst_notes=data.get("analyst_notes"),
        finding_id=data.get("finding_id")
    )


def main():
    """Demo usage."""
    # Example finding
    finding = Finding(
        title="IDOR in User Profile Endpoint",
        indicator="idor",
        severity=Severity.HIGH,
        endpoint="/api/v1/users/123/profile",
        method="GET",
        description="The user profile endpoint exposes sensitive user data without proper authorization checks. User A can access User B's profile by modifying the user ID parameter.",
        evidence=[
            Evidence(
                type="request",
                description="Request as User A accessing User B's profile",
                content="GET /api/v1/users/456/profile HTTP/1.1\nHost: api.example.com\nAuthorization: Bearer eyJhbG...\n",
                burp_request_id="12345"
            ),
            Evidence(
                type="response",
                description="Response containing User B's sensitive data",
                content="HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"id\": 456, \"email\": \"userb@example.com\", \"ssn\": \"123-45-6789\"}",
                burp_request_id="12345"
            )
        ],
        affected_parameter="user_id (path)",
        impact="An attacker can access any user's profile data including PII (email, SSN) by iterating through user IDs.",
        burp_request_ids=["12345", "12346"],
        references=[
            "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"
        ]
    )
    
    formatter = FindingFormatter(redact_sensitive=True)
    print(formatter.format(finding))


if __name__ == "__main__":
    main()
