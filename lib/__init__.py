"""
Burp MCP Toolkit - Python Helper Library

This library provides Python utilities for the Burp MCP Security Analysis Toolkit.

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

__version__ = "2.0.0"
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
