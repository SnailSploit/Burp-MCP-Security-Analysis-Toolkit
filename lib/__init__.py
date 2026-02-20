"""
Burp MCP Toolkit - Python Helper Library (SnailSploit Edition)

A security analysis framework by SnailSploit that combines Burp Suite's HTTP
traffic capture with Claude Code's reasoning via MCP (Model Context Protocol).

Modules:
    scope_validator: Validate and parse scope.yaml configuration files
    endpoint_filter: Filter and prioritize endpoints from Burp traffic
    finding_formatter: Format findings into structured markdown output
    report_generator: Aggregate findings into final security reports

Usage:
    from lib.scope_validator import ScopeValidator
    from lib.endpoint_filter import EndpointFilter, Endpoint
    from lib.finding_formatter import FindingFormatter, Finding, Severity
    from lib.report_generator import ReportGenerator
"""

from .scope_validator import ScopeValidator, ScopeConfig, ValidationError
from .endpoint_filter import EndpointFilter, Endpoint
from .finding_formatter import Finding, Evidence, Severity, FindingFormatter, finding_from_dict
from .report_generator import ReportGenerator, ReportConfig

__version__ = "2.1.0"
__author__ = "SnailSploit"
__all__ = [
    # Scope
    "ScopeValidator",
    "ScopeConfig", 
    "ValidationError",
    
    # Endpoints
    "EndpointFilter",
    "Endpoint",
    
    # Findings
    "Finding",
    "Evidence",
    "Severity",
    "FindingFormatter",
    "finding_from_dict",
    
    # Report
    "ReportGenerator",
    "ReportConfig",
]
