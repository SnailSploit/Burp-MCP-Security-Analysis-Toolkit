#!/usr/bin/env python3
"""
Report Generator - Aggregate findings into final security report.

Reads finding files from output/findings/ and generates a consolidated
markdown report with executive summary, statistics, and recommendations.

Usage:
    python report_generator.py [output_dir]
    
    # Default: ../output relative to this script
    python report_generator.py
    
    # Custom directory
    python report_generator.py /path/to/output
"""

import re
import json
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime
from collections import defaultdict

# Import sibling modules
try:
    from finding_formatter import Finding, Severity, Evidence, finding_from_dict, FindingFormatter
except ImportError:
    from lib.finding_formatter import Finding, Severity, Evidence, finding_from_dict, FindingFormatter


@dataclass
class ReportConfig:
    """Report generation configuration."""
    title: str = "Security Assessment Report"
    target: str = ""
    analyst: str = ""
    date_range: str = ""
    include_evidence: bool = True
    redact_sensitive: bool = True
    include_methodology: bool = True
    include_recommendations: bool = True


class ReportGenerator:
    """Generate consolidated security report from findings."""
    
    def __init__(self, output_dir: str = None, config: ReportConfig = None):
        self.output_dir = Path(output_dir) if output_dir else Path(__file__).parent.parent / "output"
        self.config = config or ReportConfig()
        self.findings: List[Finding] = []
        self.endpoints_data: Dict[str, Any] = {}
        self.formatter = FindingFormatter(redact_sensitive=self.config.redact_sensitive)
        
    def load_findings(self) -> List[Finding]:
        """Load all findings from output/findings/ directory."""
        findings_dir = self.output_dir / "findings"
        
        if not findings_dir.exists():
            print(f"No findings directory: {findings_dir}")
            return []
        
        self.findings = []
        
        for file_path in findings_dir.glob("*.md"):
            findings = self._parse_findings_file(file_path)
            self.findings.extend(findings)
        
        # Also check for JSON findings
        for file_path in findings_dir.glob("*.json"):
            with open(file_path) as f:
                data = json.load(f)
            
            if isinstance(data, list):
                for item in data:
                    self.findings.append(finding_from_dict(item))
            elif isinstance(data, dict) and "findings" in data:
                for item in data["findings"]:
                    self.findings.append(finding_from_dict(item))
        
        return self.findings
    
    def load_endpoints(self) -> Dict[str, Any]:
        """Load endpoints.json if available."""
        endpoints_file = self.output_dir / "endpoints.json"
        
        if endpoints_file.exists():
            with open(endpoints_file) as f:
                self.endpoints_data = json.load(f)
        
        return self.endpoints_data
    
    def deduplicate(self) -> List[Finding]:
        """Remove duplicate findings based on key fields."""
        seen = {}
        unique = []
        
        for finding in self.findings:
            # Key is indicator + endpoint + parameter
            key = (
                finding.indicator,
                finding.endpoint,
                finding.affected_parameter or ""
            )
            
            if key not in seen:
                seen[key] = finding
                unique.append(finding)
            else:
                # Keep the one with higher severity
                existing = seen[key]
                if finding.severity.priority < existing.severity.priority:
                    unique.remove(existing)
                    unique.append(finding)
                    seen[key] = finding
        
        self.findings = unique
        return unique
    
    def generate_report(self) -> str:
        """Generate the full report."""
        lines = []
        
        # Header
        lines.extend(self._generate_header())
        
        # Executive Summary
        lines.extend(self._generate_executive_summary())
        
        # Statistics
        lines.extend(self._generate_statistics())
        
        # Scope (if endpoints available)
        if self.endpoints_data:
            lines.extend(self._generate_scope_summary())
        
        # Findings
        lines.extend(self._generate_findings_section())
        
        # Methodology
        if self.config.include_methodology:
            lines.extend(self._generate_methodology())
        
        # Recommendations
        if self.config.include_recommendations:
            lines.extend(self._generate_recommendations())
        
        # Footer
        lines.extend(self._generate_footer())
        
        return "\n".join(lines)
    
    def save_report(self, filename: str = "report.md") -> str:
        """Generate and save report to file."""
        report = self.generate_report()
        
        output_path = self.output_dir / filename
        output_path.write_text(report)
        
        return str(output_path)
    
    def _parse_findings_file(self, file_path: Path) -> List[Finding]:
        """Parse findings from a markdown file."""
        content = file_path.read_text()
        findings = []
        
        # Split by finding headers (## F-XXXXX: Title)
        finding_pattern = r'## (F-\d+): (.+?)(?=\n## F-|\Z)'
        matches = re.findall(finding_pattern, content, re.DOTALL)
        
        for finding_id, finding_content in matches:
            finding = self._parse_single_finding(finding_id, finding_content, file_path.stem)
            if finding:
                findings.append(finding)
        
        # If no structured findings, create a placeholder from the file
        if not findings and "No findings" not in content and len(content) > 100:
            indicator = file_path.stem  # filename is indicator name
            findings.append(Finding(
                title=f"Findings from {indicator} analysis",
                indicator=indicator,
                severity=Severity.INFO,
                endpoint="Various",
                method="Various",
                description=f"See {file_path.name} for details.",
                analyst_notes=content[:500]
            ))
        
        return findings
    
    def _parse_single_finding(self, finding_id: str, content: str, indicator: str) -> Optional[Finding]:
        """Parse a single finding from content."""
        try:
            # Extract title (first line after ##)
            title_match = re.search(r'^(.+?)(?:\n|$)', content.strip())
            title = title_match.group(1).strip() if title_match else "Unknown"
            
            # Extract severity
            severity = Severity.MEDIUM
            severity_match = re.search(r'\*\*Severity:\*\*\s*(\w+)', content)
            if severity_match:
                try:
                    severity = Severity(severity_match.group(1))
                except ValueError:
                    pass
            
            # Extract endpoint
            endpoint = ""
            endpoint_match = re.search(r'Endpoint\s*\|\s*`([^`]+)`', content)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
            
            # Extract method
            method = "GET"
            if endpoint:
                parts = endpoint.split()
                if len(parts) >= 2:
                    method = parts[0]
                    endpoint = " ".join(parts[1:])
            
            # Extract description
            description = ""
            desc_match = re.search(r'### Description\s*\n+(.+?)(?=\n###|\Z)', content, re.DOTALL)
            if desc_match:
                description = desc_match.group(1).strip()
            
            # Extract impact
            impact = None
            impact_match = re.search(r'### Impact\s*\n+(.+?)(?=\n###|\Z)', content, re.DOTALL)
            if impact_match:
                impact = impact_match.group(1).strip()
            
            return Finding(
                finding_id=finding_id,
                title=title,
                indicator=indicator,
                severity=severity,
                endpoint=endpoint,
                method=method,
                description=description,
                impact=impact
            )
            
        except Exception as e:
            print(f"Error parsing finding: {e}")
            return None
    
    def _generate_header(self) -> List[str]:
        """Generate report header."""
        lines = [
            f"# {self.config.title}",
            "",
            f"**Target:** {self.config.target or 'Not specified'}",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d')}",
        ]
        
        if self.config.analyst:
            lines.append(f"**Analyst:** {self.config.analyst}")
        
        if self.config.date_range:
            lines.append(f"**Assessment Period:** {self.config.date_range}")
        
        lines.extend(["", "---", ""])
        
        return lines
    
    def _generate_executive_summary(self) -> List[str]:
        """Generate executive summary section."""
        lines = [
            "## Executive Summary",
            ""
        ]
        
        if not self.findings:
            lines.append("No security findings were identified during this assessment.")
            lines.append("")
            return lines
        
        # Count by severity
        severity_counts = defaultdict(int)
        for f in self.findings:
            severity_counts[f.severity] += 1
        
        # Critical findings summary
        critical_high = [f for f in self.findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]
        
        if critical_high:
            lines.append(f"This assessment identified **{len(self.findings)} security findings**, including **{len(critical_high)} high-severity issues** that require immediate attention.")
            lines.append("")
            lines.append("**Key Findings:**")
            lines.append("")
            for f in critical_high[:5]:  # Top 5
                lines.append(f"- **{f.severity.value}**: {f.title}")
            lines.append("")
        else:
            lines.append(f"This assessment identified **{len(self.findings)} security findings**. No critical or high-severity issues were found.")
            lines.append("")
        
        return lines
    
    def _generate_statistics(self) -> List[str]:
        """Generate findings statistics."""
        lines = [
            "## Findings Summary",
            "",
            "### By Severity",
            "",
            "| Severity | Count | Percentage |",
            "|----------|-------|------------|"
        ]
        
        total = len(self.findings) or 1
        for sev in Severity:
            count = len([f for f in self.findings if f.severity == sev])
            if count > 0:
                pct = (count / total) * 100
                lines.append(f"| {sev.value} | {count} | {pct:.1f}% |")
        
        lines.append("")
        
        # By indicator
        lines.extend([
            "### By Indicator",
            "",
            "| Indicator | Count |",
            "|-----------|-------|"
        ])
        
        indicator_counts = defaultdict(int)
        for f in self.findings:
            indicator_counts[f.indicator] += 1
        
        for indicator, count in sorted(indicator_counts.items(), key=lambda x: -x[1]):
            lines.append(f"| {indicator.upper()} | {count} |")
        
        lines.append("")
        
        return lines
    
    def _generate_scope_summary(self) -> List[str]:
        """Generate scope summary from endpoints data."""
        lines = [
            "## Assessment Scope",
            ""
        ]
        
        total = self.endpoints_data.get("total", 0)
        by_category = self.endpoints_data.get("by_category", {})
        by_indicator = self.endpoints_data.get("by_indicator", {})
        
        lines.append(f"**Total Endpoints Analyzed:** {total}")
        lines.append("")
        
        if by_category:
            lines.append("**By Category:**")
            for cat, count in sorted(by_category.items(), key=lambda x: -x[1]):
                lines.append(f"- {cat}: {count}")
            lines.append("")
        
        if by_indicator:
            lines.append("**By Indicator Coverage:**")
            for ind, count in sorted(by_indicator.items(), key=lambda x: -x[1]):
                lines.append(f"- {ind}: {count} endpoints")
            lines.append("")
        
        return lines
    
    def _generate_findings_section(self) -> List[str]:
        """Generate detailed findings section."""
        lines = [
            "## Detailed Findings",
            ""
        ]
        
        if not self.findings:
            lines.append("No findings to report.")
            lines.append("")
            return lines
        
        # Sort by severity
        sorted_findings = sorted(self.findings, key=lambda f: f.severity.priority)
        
        # Table of contents
        lines.append("### Table of Contents")
        lines.append("")
        for f in sorted_findings:
            lines.append(f"- [{f.finding_id}: {f.title}](#{f.finding_id.lower()})")
        lines.append("")
        lines.append("---")
        lines.append("")
        
        # Individual findings
        for finding in sorted_findings:
            if self.config.include_evidence:
                lines.append(self.formatter.format(finding))
            else:
                # Abbreviated format
                lines.append(f"### {finding.finding_id}: {finding.title}")
                lines.append("")
                lines.append(f"**Severity:** {finding.severity.value} | **Indicator:** {finding.indicator}")
                lines.append("")
                lines.append(f"**Endpoint:** `{finding.method} {finding.endpoint}`")
                lines.append("")
                lines.append(finding.description)
                lines.append("")
                lines.append("---")
                lines.append("")
        
        return lines
    
    def _generate_methodology(self) -> List[str]:
        """Generate methodology section."""
        return [
            "## Methodology",
            "",
            "This assessment was conducted using the Burp MCP Security Analysis Toolkit with the following approach:",
            "",
            "1. **Scope Definition**: Target boundaries were defined in scope.yaml",
            "2. **Endpoint Triage**: HTTP traffic was analyzed and endpoints were classified by category and interest score",
            "3. **Indicator-Based Analysis**: Each enabled indicator (IDOR, BOLA, Auth Bypass, SSRF, Injection) was tested using structured methodology",
            "4. **Evidence Collection**: All findings include supporting evidence from actual HTTP traffic",
            "5. **Report Generation**: Findings were deduplicated, sorted by severity, and consolidated",
            "",
            "### Indicators Tested",
            "",
            "| Indicator | Description |",
            "|-----------|-------------|",
            "| IDOR | Insecure Direct Object Reference |",
            "| BOLA | Broken Object Level Authorization |",
            "| Auth Bypass | Authentication and session issues |",
            "| SSRF | Server-Side Request Forgery |",
            "| Injection | SQL/XSS/Command injection points |",
            "",
        ]
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations section."""
        lines = [
            "## Recommendations",
            ""
        ]
        
        if not self.findings:
            lines.append("No specific recommendations based on findings.")
            lines.append("")
            return lines
        
        # Group findings by indicator
        by_indicator = defaultdict(list)
        for f in self.findings:
            by_indicator[f.indicator].append(f)
        
        # Generate recommendations per indicator type
        recommendations = {
            "idor": {
                "title": "Access Control",
                "recs": [
                    "Implement server-side authorization checks for all object access",
                    "Use indirect object references (mapping tables) instead of direct database IDs",
                    "Log and monitor access patterns for anomaly detection"
                ]
            },
            "bola": {
                "title": "Object-Level Authorization",
                "recs": [
                    "Implement authorization middleware that validates object ownership",
                    "Use attribute-based access control (ABAC) for complex permission models",
                    "Add authorization unit tests for all API endpoints"
                ]
            },
            "auth_bypass": {
                "title": "Authentication Security",
                "recs": [
                    "Review all authentication flows for bypass vulnerabilities",
                    "Implement consistent authentication checks across all endpoints",
                    "Use security frameworks with built-in auth protection"
                ]
            },
            "ssrf": {
                "title": "SSRF Prevention",
                "recs": [
                    "Validate and sanitize all user-supplied URLs",
                    "Implement allowlists for permitted hosts and protocols",
                    "Use network segmentation to limit internal access from web servers"
                ]
            },
            "injection": {
                "title": "Injection Prevention",
                "recs": [
                    "Use parameterized queries or prepared statements for all database operations",
                    "Implement strict input validation with allowlists",
                    "Apply context-appropriate output encoding"
                ]
            }
        }
        
        lines.append("Based on the findings, the following remediations are recommended:")
        lines.append("")
        
        for indicator in sorted(by_indicator.keys()):
            if indicator in recommendations:
                rec = recommendations[indicator]
                count = len(by_indicator[indicator])
                lines.append(f"### {rec['title']} ({count} finding{'s' if count > 1 else ''})")
                lines.append("")
                for r in rec['recs']:
                    lines.append(f"- {r}")
                lines.append("")
        
        return lines
    
    def _generate_footer(self) -> List[str]:
        """Generate report footer."""
        return [
            "---",
            "",
            f"*Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*",
            "",
            "*Generated by Burp MCP Security Analysis Toolkit (SnailSploit Edition)*",
            ""
        ]


def main():
    """CLI entry point."""
    output_dir = sys.argv[1] if len(sys.argv) > 1 else None
    
    generator = ReportGenerator(output_dir)
    
    print("Loading findings...")
    findings = generator.load_findings()
    print(f"Loaded {len(findings)} findings")
    
    print("Loading endpoints...")
    endpoints = generator.load_endpoints()
    print(f"Loaded {endpoints.get('total', 0)} endpoints")
    
    print("Deduplicating...")
    unique = generator.deduplicate()
    print(f"After dedup: {len(unique)} unique findings")
    
    print("Generating report...")
    output_path = generator.save_report()
    print(f"Report saved to: {output_path}")


if __name__ == "__main__":
    main()
