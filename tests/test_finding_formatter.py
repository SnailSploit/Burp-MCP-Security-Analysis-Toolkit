#!/usr/bin/env python3
"""Tests for finding_formatter module."""

import pytest

from lib.finding_formatter import (
    Finding,
    Evidence,
    Severity,
    FindingFormatter,
    finding_from_dict,
)


@pytest.fixture
def sample_finding():
    """Return a sample finding."""
    return Finding(
        title="IDOR in User Profile Endpoint",
        indicator="idor",
        severity=Severity.HIGH,
        endpoint="/api/v1/users/123/profile",
        method="GET",
        description="User A can access User B's profile data by modifying the user ID.",
        evidence=[
            Evidence(
                type="request",
                description="Request as User A for User B's profile",
                content="GET /api/v1/users/456/profile HTTP/1.1\nHost: api.example.com\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.test.sig\n",
                burp_request_id="12345",
            ),
            Evidence(
                type="response",
                description="Response with User B's data",
                content='HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"id": 456, "email": "userb@example.com"}',
                burp_request_id="12345",
            ),
        ],
        affected_parameter="user_id (path)",
        impact="Attacker can access any user's PII.",
        burp_request_ids=["12345", "12346"],
        references=[
            "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
        ],
    )


@pytest.fixture
def formatter():
    """Return a FindingFormatter with redaction enabled."""
    return FindingFormatter(redact_sensitive=True)


class TestSeverity:
    def test_values(self):
        assert Severity.CRITICAL.value == "Critical"
        assert Severity.HIGH.value == "High"
        assert Severity.MEDIUM.value == "Medium"
        assert Severity.LOW.value == "Low"
        assert Severity.INFO.value == "Informational"

    def test_priority_ordering(self):
        assert Severity.CRITICAL.priority < Severity.HIGH.priority
        assert Severity.HIGH.priority < Severity.MEDIUM.priority
        assert Severity.MEDIUM.priority < Severity.LOW.priority
        assert Severity.LOW.priority < Severity.INFO.priority

    def test_colors(self):
        assert Severity.CRITICAL.color == "red"
        assert Severity.HIGH.color == "orange"
        assert Severity.MEDIUM.color == "yellow"
        assert Severity.LOW.color == "blue"
        assert Severity.INFO.color == "gray"


class TestEvidence:
    def test_creation(self):
        ev = Evidence(
            type="request",
            description="Test request",
            content="GET /test HTTP/1.1",
            burp_request_id="1",
        )
        assert ev.type == "request"
        assert ev.burp_request_id == "1"
        assert ev.redacted is False


class TestFinding:
    def test_auto_id(self, sample_finding):
        assert sample_finding.finding_id is not None
        assert sample_finding.finding_id.startswith("F-")

    def test_deterministic_id(self):
        f1 = Finding(
            title="Test",
            indicator="idor",
            severity=Severity.HIGH,
            endpoint="/test",
            method="GET",
            description="desc",
        )
        f2 = Finding(
            title="Different Title",
            indicator="idor",
            severity=Severity.HIGH,
            endpoint="/test",
            method="GET",
            description="different desc",
        )
        # Same indicator+endpoint+method+param -> same ID
        assert f1.finding_id == f2.finding_id

    def test_custom_id(self):
        f = Finding(
            title="Test",
            indicator="idor",
            severity=Severity.HIGH,
            endpoint="/test",
            method="GET",
            description="desc",
            finding_id="F-CUSTOM",
        )
        assert f.finding_id == "F-CUSTOM"

    def test_default_confidence(self, sample_finding):
        assert sample_finding.confidence == "High"


class TestFindingFormatter:
    def test_format_contains_title(self, formatter, sample_finding):
        md = formatter.format(sample_finding)
        assert sample_finding.title in md

    def test_format_contains_severity(self, formatter, sample_finding):
        md = formatter.format(sample_finding)
        assert "High" in md

    def test_format_contains_endpoint(self, formatter, sample_finding):
        md = formatter.format(sample_finding)
        assert sample_finding.endpoint in md

    def test_format_contains_evidence(self, formatter, sample_finding):
        md = formatter.format(sample_finding)
        assert "Evidence 1" in md
        assert "Evidence 2" in md

    def test_format_contains_cwe(self, formatter, sample_finding):
        md = formatter.format(sample_finding)
        assert "CWE-639" in md

    def test_format_contains_remediation(self, formatter, sample_finding):
        md = formatter.format(sample_finding)
        assert "Remediation" in md

    def test_format_contains_references(self, formatter, sample_finding):
        md = formatter.format(sample_finding)
        assert "owasp.org" in md

    def test_format_contains_impact(self, formatter, sample_finding):
        md = formatter.format(sample_finding)
        assert "Impact" in md
        assert "PII" in md

    def test_format_contains_burp_ids(self, formatter, sample_finding):
        md = formatter.format(sample_finding)
        assert "12345" in md

    def test_redaction_jwt(self, formatter):
        finding = Finding(
            title="Test",
            indicator="idor",
            severity=Severity.MEDIUM,
            endpoint="/test",
            method="GET",
            description="test",
            evidence=[
                Evidence(
                    type="request",
                    description="test",
                    content="Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                )
            ],
        )
        md = formatter.format(finding)
        assert "REDACTED" in md

    def test_redaction_email(self, formatter):
        finding = Finding(
            title="Test",
            indicator="idor",
            severity=Severity.MEDIUM,
            endpoint="/test",
            method="GET",
            description="test",
            evidence=[
                Evidence(
                    type="response",
                    description="test",
                    content='{"email": "user@example.com"}',
                )
            ],
        )
        md = formatter.format(finding)
        assert "REDACTED_EMAIL" in md

    def test_no_redaction_when_disabled(self):
        formatter = FindingFormatter(redact_sensitive=False)
        finding = Finding(
            title="Test",
            indicator="idor",
            severity=Severity.MEDIUM,
            endpoint="/test",
            method="GET",
            description="test",
            evidence=[
                Evidence(
                    type="response",
                    description="test",
                    content='{"email": "user@example.com"}',
                )
            ],
        )
        md = formatter.format(finding)
        assert "user@example.com" in md

    def test_format_multiple(self, formatter):
        findings = [
            Finding(
                title="Critical Issue",
                indicator="injection",
                severity=Severity.CRITICAL,
                endpoint="/api/search",
                method="GET",
                description="SQL injection found",
            ),
            Finding(
                title="Low Issue",
                indicator="idor",
                severity=Severity.LOW,
                endpoint="/api/info",
                method="GET",
                description="Minor info leak",
            ),
        ]
        md = formatter.format_multiple(findings)
        assert "Executive Summary" in md
        assert "Table of Contents" in md
        # Critical should appear before Low
        critical_pos = md.index("Critical Issue")
        low_pos = md.index("Low Issue")
        assert critical_pos < low_pos

    def test_format_multiple_empty(self, formatter):
        md = formatter.format_multiple([])
        assert "No findings" in md

    def test_format_request_sample_fallback(self, formatter):
        finding = Finding(
            title="Test",
            indicator="ssrf",
            severity=Severity.HIGH,
            endpoint="/proxy",
            method="GET",
            description="SSRF found",
            request_sample="GET /proxy?url=http://169.254.169.254 HTTP/1.1",
            response_sample="HTTP/1.1 200 OK\n\nmetadata",
        )
        md = formatter.format(finding)
        assert "Request Sample" in md
        assert "Response Sample" in md

    def test_slugify(self, formatter):
        assert formatter._slugify("Hello World!") == "hello-world"
        assert formatter._slugify("IDOR in /api/users") == "idor-in-apiusers"


class TestFindingFromDict:
    def test_basic(self):
        data = {
            "title": "Test Finding",
            "indicator": "idor",
            "severity": "High",
            "endpoint": "/api/test",
            "method": "GET",
            "description": "A test finding",
        }
        f = finding_from_dict(data)
        assert f.title == "Test Finding"
        assert f.severity == Severity.HIGH
        assert f.indicator == "idor"

    def test_with_evidence(self):
        data = {
            "title": "Test",
            "indicator": "bola",
            "severity": "Medium",
            "endpoint": "/test",
            "method": "POST",
            "description": "test",
            "evidence": [
                {
                    "type": "request",
                    "description": "test request",
                    "content": "GET /test",
                    "burp_request_id": "100",
                }
            ],
        }
        f = finding_from_dict(data)
        assert len(f.evidence) == 1
        assert f.evidence[0].burp_request_id == "100"

    def test_all_optional_fields(self):
        data = {
            "title": "Full Finding",
            "indicator": "ssrf",
            "severity": "Critical",
            "endpoint": "/proxy",
            "method": "GET",
            "description": "SSRF",
            "affected_parameter": "url",
            "affected_object_type": "url_param",
            "auth_context": "user_a",
            "request_sample": "GET /proxy",
            "response_sample": "200 OK",
            "burp_request_ids": ["1", "2"],
            "impact": "Internal access",
            "affected_data": "metadata",
            "remediation": "Validate URLs",
            "references": ["https://owasp.org"],
            "cwe_id": "CWE-918",
            "confidence": "Medium",
            "false_positive_risk": "Medium",
            "analyst_notes": "Needs review",
            "finding_id": "F-99999",
        }
        f = finding_from_dict(data)
        assert f.finding_id == "F-99999"
        assert f.cwe_id == "CWE-918"
        assert f.confidence == "Medium"
