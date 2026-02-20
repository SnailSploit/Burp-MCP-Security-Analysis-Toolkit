#!/usr/bin/env python3
"""Tests for report_generator module."""

import json
import os
import pytest

from lib.finding_formatter import Finding, Evidence, Severity, FindingFormatter
from lib.report_generator import ReportGenerator, ReportConfig


@pytest.fixture
def output_dir(tmp_path):
    """Create a temporary output directory with sample findings."""
    findings_dir = tmp_path / "findings"
    findings_dir.mkdir()

    # Create a sample finding markdown file
    formatter = FindingFormatter(redact_sensitive=False)
    finding = Finding(
        title="IDOR in User API",
        indicator="idor",
        severity=Severity.HIGH,
        endpoint="/api/users/123",
        method="GET",
        description="User can access other users' data.",
        evidence=[
            Evidence(
                type="request",
                description="Cross-user request",
                content="GET /api/users/456 HTTP/1.1",
                burp_request_id="100",
            )
        ],
        impact="Data exposure",
        burp_request_ids=["100"],
    )
    md = formatter.format(finding)
    (findings_dir / "idor.md").write_text(md)

    # Create a JSON finding file
    json_finding = {
        "findings": [
            {
                "title": "Auth Bypass via Token Reuse",
                "indicator": "auth_bypass",
                "severity": "Critical",
                "endpoint": "/api/auth/refresh",
                "method": "POST",
                "description": "Expired tokens are still accepted.",
            }
        ]
    }
    (findings_dir / "auth.json").write_text(json.dumps(json_finding))

    # Create an endpoints.json
    endpoints = {
        "total": 15,
        "by_category": {"auth": 3, "user": 5, "api": 7},
        "by_indicator": {"idor": 4, "auth_bypass": 3, "injection": 8},
        "endpoints": [],
    }
    (tmp_path / "endpoints.json").write_text(json.dumps(endpoints))

    return str(tmp_path)


@pytest.fixture
def empty_output_dir(tmp_path):
    """Create an empty output directory."""
    return str(tmp_path)


class TestReportConfig:
    def test_defaults(self):
        config = ReportConfig()
        assert config.title == "Security Assessment Report"
        assert config.include_evidence is True
        assert config.redact_sensitive is True

    def test_custom(self):
        config = ReportConfig(
            title="Custom Report",
            target="https://example.com",
            analyst="SnailSploit",
            include_evidence=False,
        )
        assert config.title == "Custom Report"
        assert config.analyst == "SnailSploit"


class TestReportGenerator:
    def test_load_findings(self, output_dir):
        gen = ReportGenerator(output_dir)
        findings = gen.load_findings()
        assert len(findings) >= 2  # 1 from md + 1 from json

    def test_load_findings_empty(self, empty_output_dir):
        gen = ReportGenerator(empty_output_dir)
        findings = gen.load_findings()
        assert len(findings) == 0

    def test_load_endpoints(self, output_dir):
        gen = ReportGenerator(output_dir)
        endpoints = gen.load_endpoints()
        assert endpoints["total"] == 15

    def test_load_endpoints_missing(self, empty_output_dir):
        gen = ReportGenerator(empty_output_dir)
        endpoints = gen.load_endpoints()
        assert endpoints == {}

    def test_deduplicate(self, output_dir):
        gen = ReportGenerator(output_dir)
        gen.load_findings()
        # Add a duplicate with lower severity
        gen.findings.append(
            Finding(
                title="IDOR in User API (dup)",
                indicator="idor",
                severity=Severity.LOW,
                endpoint="/api/users/123",
                method="GET",
                description="Duplicate",
                affected_parameter=None,
            )
        )
        before = len(gen.findings)
        gen.deduplicate()
        after = len(gen.findings)
        assert after < before

    def test_deduplicate_keeps_higher_severity(self, output_dir):
        gen = ReportGenerator(output_dir)
        gen.findings = [
            Finding(
                title="Issue Low",
                indicator="idor",
                severity=Severity.LOW,
                endpoint="/test",
                method="GET",
                description="low",
            ),
            Finding(
                title="Issue High",
                indicator="idor",
                severity=Severity.HIGH,
                endpoint="/test",
                method="GET",
                description="high",
            ),
        ]
        gen.deduplicate()
        assert len(gen.findings) == 1
        assert gen.findings[0].severity == Severity.HIGH

    def test_generate_report(self, output_dir):
        gen = ReportGenerator(output_dir)
        gen.load_findings()
        gen.load_endpoints()
        gen.deduplicate()
        report = gen.generate_report()

        assert "Security Assessment Report" in report
        assert "Executive Summary" in report
        assert "Findings Summary" in report
        assert "Detailed Findings" in report
        assert "Methodology" in report
        assert "Recommendations" in report
        assert "SnailSploit Edition" in report

    def test_generate_report_empty(self, empty_output_dir):
        gen = ReportGenerator(empty_output_dir)
        gen.load_findings()
        report = gen.generate_report()
        assert "No security findings" in report

    def test_generate_report_no_evidence(self, output_dir):
        config = ReportConfig(include_evidence=False)
        gen = ReportGenerator(output_dir, config)
        gen.load_findings()
        gen.deduplicate()
        report = gen.generate_report()
        assert "Detailed Findings" in report

    def test_save_report(self, output_dir):
        gen = ReportGenerator(output_dir)
        gen.load_findings()
        gen.load_endpoints()
        gen.deduplicate()
        path = gen.save_report()
        assert os.path.exists(path)
        with open(path) as f:
            content = f.read()
        assert "Security Assessment Report" in content

    def test_custom_config(self, output_dir):
        config = ReportConfig(
            title="SnailSploit Pentest Report",
            target="https://target.example.com",
            analyst="SnailSploit Team",
            date_range="2026-01-01 to 2026-02-20",
        )
        gen = ReportGenerator(output_dir, config)
        gen.load_findings()
        gen.load_endpoints()
        gen.deduplicate()
        report = gen.generate_report()
        assert "SnailSploit Pentest Report" in report
        assert "target.example.com" in report
        assert "SnailSploit Team" in report

    def test_statistics_section(self, output_dir):
        gen = ReportGenerator(output_dir)
        gen.load_findings()
        gen.deduplicate()
        report = gen.generate_report()
        assert "By Severity" in report
        assert "By Indicator" in report

    def test_scope_summary_section(self, output_dir):
        gen = ReportGenerator(output_dir)
        gen.load_findings()
        gen.load_endpoints()
        gen.deduplicate()
        report = gen.generate_report()
        assert "Assessment Scope" in report
        assert "Total Endpoints Analyzed" in report

    def test_recommendations_grouped_by_indicator(self, output_dir):
        gen = ReportGenerator(output_dir)
        gen.load_findings()
        gen.deduplicate()
        report = gen.generate_report()
        assert "Recommendations" in report
