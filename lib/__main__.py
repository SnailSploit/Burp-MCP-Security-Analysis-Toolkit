#!/usr/bin/env python3
"""
Burp MCP Toolkit CLI (SnailSploit Edition)

Unified command-line interface for all toolkit operations.

Usage:
    python -m lib validate [scope_file]
    python -m lib report [output_dir]
    python -m lib demo
    python -m lib version
"""

import sys
import json
from pathlib import Path


def cmd_validate(args):
    """Validate a scope.yaml file."""
    from .scope_validator import ScopeValidator

    scope_path = args[0] if args else None
    validator = ScopeValidator(scope_path)
    valid = validator.validate()

    validator.print_errors()

    if valid:
        validator.print_summary()
        print("\nScope configuration is valid")
        return 0
    else:
        print("\nScope configuration has errors")
        return 1


def cmd_report(args):
    """Generate a report from findings."""
    from .report_generator import ReportGenerator, ReportConfig

    output_dir = args[0] if args else None
    config = ReportConfig()

    if len(args) > 1:
        config.target = args[1]
    if len(args) > 2:
        config.analyst = args[2]

    generator = ReportGenerator(output_dir, config)

    print("Loading findings...")
    findings = generator.load_findings()
    print(f"  Found {len(findings)} findings")

    print("Loading endpoints...")
    endpoints = generator.load_endpoints()
    print(f"  Found {endpoints.get('total', 0)} endpoints")

    print("Deduplicating...")
    unique = generator.deduplicate()
    print(f"  {len(unique)} unique findings")

    print("Generating report...")
    output_path = generator.save_report()
    print(f"  Report saved to: {output_path}")

    return 0


def cmd_demo(args):
    """Run a demo with sample data."""
    from .endpoint_filter import EndpointFilter
    from .finding_formatter import Finding, Evidence, Severity, FindingFormatter

    print("=" * 60)
    print("Burp MCP Toolkit - SnailSploit Edition - Demo")
    print("=" * 60)

    # Demo endpoint filtering
    print("\n--- Endpoint Filtering Demo ---\n")
    entries = [
        {
            "id": "1",
            "method": "GET",
            "url": "https://api.example.com/users/123/profile",
            "host": "api.example.com",
            "path": "/users/123/profile",
            "status": 200,
            "content_type": "application/json",
            "headers": {"Authorization": "Bearer xxx"},
        },
        {
            "id": "2",
            "method": "POST",
            "url": "https://api.example.com/admin/settings",
            "host": "api.example.com",
            "path": "/admin/settings",
            "status": 403,
            "content_type": "application/json",
            "headers": {},
            "request_body": '{"config": "value"}',
        },
        {
            "id": "3",
            "method": "GET",
            "url": "https://api.example.com/export?url=https://internal.corp",
            "host": "api.example.com",
            "path": "/export",
            "status": 200,
            "content_type": "application/json",
            "headers": {"Authorization": "Bearer yyy"},
        },
    ]

    ef = EndpointFilter()
    for entry in entries:
        ef.add_entry(entry)

    endpoints = ef.prioritize()
    for ep in endpoints:
        print(f"  [Score: {ep.interest_score:2d}] {ep.method:6s} {ep.path}")
        print(f"           Category: {ep.category} | Indicators: {', '.join(ep.indicators) or 'none'}")

    # Demo finding formatting
    print("\n--- Finding Formatting Demo ---\n")
    finding = Finding(
        title="IDOR in User Profile",
        indicator="idor",
        severity=Severity.HIGH,
        endpoint="/api/v1/users/123/profile",
        method="GET",
        description="User A can access User B's profile by changing the ID parameter.",
        evidence=[
            Evidence(
                type="request",
                description="Cross-user access request",
                content="GET /api/v1/users/456/profile HTTP/1.1\nAuthorization: Bearer token_user_a",
                burp_request_id="12345",
            )
        ],
        impact="Any authenticated user can read other users' PII.",
        burp_request_ids=["12345"],
    )

    formatter = FindingFormatter(redact_sensitive=True)
    print(formatter.format(finding))

    print("Demo complete.")
    return 0


def cmd_version(args):
    """Print version info."""
    from . import __version__, __author__

    print(f"Burp MCP Security Analysis Toolkit v{__version__}")
    print(f"SnailSploit Edition")
    print(f"Author: {__author__}")
    return 0


COMMANDS = {
    "validate": ("Validate scope.yaml", cmd_validate),
    "report": ("Generate security report", cmd_report),
    "demo": ("Run demo with sample data", cmd_demo),
    "version": ("Show version", cmd_version),
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print("Burp MCP Toolkit CLI (SnailSploit Edition)")
        print()
        print("Usage: python -m lib <command> [args...]")
        print()
        print("Commands:")
        for name, (desc, _) in COMMANDS.items():
            print(f"  {name:12s}  {desc}")
        print()
        print("Examples:")
        print("  python -m lib validate scope.yaml")
        print("  python -m lib report ./output")
        print("  python -m lib demo")
        print("  python -m lib version")
        sys.exit(0)

    command = sys.argv[1]
    if command not in COMMANDS:
        print(f"Unknown command: {command}")
        print(f"Available: {', '.join(COMMANDS.keys())}")
        sys.exit(1)

    _, handler = COMMANDS[command]
    exit_code = handler(sys.argv[2:])
    sys.exit(exit_code or 0)


if __name__ == "__main__":
    main()
