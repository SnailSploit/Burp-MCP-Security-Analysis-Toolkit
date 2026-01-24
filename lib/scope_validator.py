#!/usr/bin/env python3
"""
Scope Validator - Validates and parses scope.yaml configuration files.

Usage:
    python scope_validator.py [scope_file]
    
    # Default: scope.yaml in parent directory
    python scope_validator.py
    
    # Specific file
    python scope_validator.py ../my-scope.yaml
"""

import re
import sys
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse


@dataclass
class ValidationError:
    """Represents a validation error."""
    field: str
    message: str
    severity: str = "error"  # error, warning
    
    def __str__(self):
        icon = "❌" if self.severity == "error" else "⚠️"
        return f"{icon} [{self.field}] {self.message}"


@dataclass
class ScopeConfig:
    """Parsed and validated scope configuration."""
    # Target
    primary_target: str
    additional_targets: List[str] = field(default_factory=list)
    
    # Scope patterns
    include_patterns: List[re.Pattern] = field(default_factory=list)
    exclude_patterns: List[re.Pattern] = field(default_factory=list)
    exclude_extensions: List[str] = field(default_factory=list)
    exclude_domains: List[str] = field(default_factory=list)
    
    # Indicators
    enabled_indicators: List[str] = field(default_factory=list)
    indicator_config: Dict[str, Dict] = field(default_factory=dict)
    
    # Auth
    auth_type: str = "bearer"
    auth_header: str = "Authorization"
    auth_prefix: str = "Bearer "
    auth_contexts: Dict[str, Dict] = field(default_factory=dict)
    
    # Output
    output_dir: str = "./output"
    output_format: str = "markdown"
    include_evidence: bool = True
    redact_sensitive: bool = True
    
    # Advanced
    max_endpoints: int = 0
    min_interest_score: int = 3
    request_timeout: int = 30
    rate_limit: int = 0
    
    # Raw config
    raw: Dict[str, Any] = field(default_factory=dict)


class ScopeValidator:
    """Validates scope.yaml configuration files."""
    
    VALID_AUTH_TYPES = ["bearer", "cookie", "api_key", "basic", "custom"]
    VALID_OUTPUT_FORMATS = ["markdown", "json", "html"]
    KNOWN_INDICATORS = ["idor", "bola", "auth_bypass", "ssrf", "injection", "rate_limit", "info_disclosure"]
    
    def __init__(self, scope_path: str = None):
        self.scope_path = Path(scope_path) if scope_path else Path(__file__).parent.parent / "scope.yaml"
        self.errors: List[ValidationError] = []
        self.warnings: List[ValidationError] = []
        self.config: Optional[ScopeConfig] = None
        
    def validate(self) -> bool:
        """Validate the scope file. Returns True if valid (no errors)."""
        self.errors = []
        self.warnings = []
        
        # Check file exists
        if not self.scope_path.exists():
            self.errors.append(ValidationError(
                "file", 
                f"Scope file not found: {self.scope_path}"
            ))
            return False
        
        # Parse YAML
        try:
            with open(self.scope_path, 'r') as f:
                raw = yaml.safe_load(f)
        except yaml.YAMLError as e:
            self.errors.append(ValidationError("yaml", f"Invalid YAML: {e}"))
            return False
        
        if not raw:
            self.errors.append(ValidationError("file", "Empty configuration file"))
            return False
        
        # Validate sections
        self._validate_target(raw)
        self._validate_scope(raw)
        self._validate_indicators(raw)
        self._validate_auth(raw)
        self._validate_output(raw)
        self._validate_advanced(raw)
        
        # Build config object if no errors
        if not self.errors:
            self._build_config(raw)
        
        return len(self.errors) == 0
    
    def _validate_target(self, raw: Dict):
        """Validate target section."""
        if "target" not in raw:
            self.errors.append(ValidationError("target", "Missing required 'target' section"))
            return
        
        target = raw["target"]
        
        # Primary target required
        if "primary" not in target:
            self.errors.append(ValidationError("target.primary", "Primary target URL is required"))
        else:
            url = target["primary"]
            if not self._is_valid_url(url):
                self.errors.append(ValidationError("target.primary", f"Invalid URL: {url}"))
        
        # Validate additional targets
        additional = target.get("additional", [])
        if additional:
            for i, url in enumerate(additional):
                if not self._is_valid_url(url):
                    self.errors.append(ValidationError(
                        f"target.additional[{i}]", 
                        f"Invalid URL: {url}"
                    ))
    
    def _validate_scope(self, raw: Dict):
        """Validate scope section."""
        if "scope" not in raw:
            self.warnings.append(ValidationError(
                "scope", 
                "Missing 'scope' section - all traffic will be analyzed",
                severity="warning"
            ))
            return
        
        scope = raw["scope"]
        
        # Validate include patterns
        for i, pattern in enumerate(scope.get("include", [])):
            try:
                re.compile(pattern)
            except re.error as e:
                self.errors.append(ValidationError(
                    f"scope.include[{i}]", 
                    f"Invalid regex pattern: {e}"
                ))
        
        # Validate exclude patterns
        for i, pattern in enumerate(scope.get("exclude", [])):
            try:
                re.compile(pattern)
            except re.error as e:
                self.errors.append(ValidationError(
                    f"scope.exclude[{i}]", 
                    f"Invalid regex pattern: {e}"
                ))
        
        # Validate extensions format
        extensions = scope.get("exclude_extensions", [])
        for i, ext in enumerate(extensions):
            if not ext.startswith("."):
                self.warnings.append(ValidationError(
                    f"scope.exclude_extensions[{i}]",
                    f"Extension '{ext}' should start with '.'",
                    severity="warning"
                ))
    
    def _validate_indicators(self, raw: Dict):
        """Validate indicators section."""
        if "indicators" not in raw:
            self.warnings.append(ValidationError(
                "indicators",
                "Missing 'indicators' section - no vulnerability testing will occur",
                severity="warning"
            ))
            return
        
        indicators = raw["indicators"]
        enabled = indicators.get("enabled", [])
        
        if not enabled:
            self.warnings.append(ValidationError(
                "indicators.enabled",
                "No indicators enabled - no vulnerability testing will occur",
                severity="warning"
            ))
        
        # Check for unknown indicators
        for ind in enabled:
            if ind not in self.KNOWN_INDICATORS:
                self.warnings.append(ValidationError(
                    f"indicators.enabled",
                    f"Unknown indicator '{ind}' - ensure skill file exists",
                    severity="warning"
                ))
        
        # Validate SSRF callback if SSRF enabled
        if "ssrf" in enabled:
            ssrf_config = indicators.get("ssrf", {})
            callback = ssrf_config.get("callback_url")
            if not callback:
                self.warnings.append(ValidationError(
                    "indicators.ssrf.callback_url",
                    "No callback URL configured for SSRF testing - blind SSRF won't be detectable",
                    severity="warning"
                ))
    
    def _validate_auth(self, raw: Dict):
        """Validate auth section."""
        if "auth" not in raw:
            self.warnings.append(ValidationError(
                "auth",
                "Missing 'auth' section - IDOR/BOLA testing may be limited",
                severity="warning"
            ))
            return
        
        auth = raw["auth"]
        
        # Validate auth type
        auth_type = auth.get("type", "bearer")
        if auth_type not in self.VALID_AUTH_TYPES:
            self.errors.append(ValidationError(
                "auth.type",
                f"Invalid auth type '{auth_type}'. Valid: {self.VALID_AUTH_TYPES}"
            ))
        
        # Validate contexts for IDOR/BOLA testing
        contexts = auth.get("contexts", {})
        indicators = raw.get("indicators", {}).get("enabled", [])
        
        if ("idor" in indicators or "bola" in indicators) and len(contexts) < 2:
            self.warnings.append(ValidationError(
                "auth.contexts",
                "IDOR/BOLA testing requires at least 2 auth contexts (user_a, user_b)",
                severity="warning"
            ))
        
        # Validate each context
        for name, ctx in contexts.items():
            if "token" not in ctx:
                self.warnings.append(ValidationError(
                    f"auth.contexts.{name}.token",
                    f"Missing token for context '{name}'",
                    severity="warning"
                ))
    
    def _validate_output(self, raw: Dict):
        """Validate output section."""
        if "output" not in raw:
            return  # All defaults are fine
        
        output = raw["output"]
        
        # Validate format
        fmt = output.get("format", "markdown")
        if fmt not in self.VALID_OUTPUT_FORMATS:
            self.errors.append(ValidationError(
                "output.format",
                f"Invalid output format '{fmt}'. Valid: {self.VALID_OUTPUT_FORMATS}"
            ))
    
    def _validate_advanced(self, raw: Dict):
        """Validate advanced section."""
        if "advanced" not in raw:
            return
        
        advanced = raw["advanced"]
        
        # Validate numeric fields
        for field in ["max_endpoints", "min_interest_score", "request_timeout", "rate_limit"]:
            value = advanced.get(field)
            if value is not None and not isinstance(value, int):
                self.errors.append(ValidationError(
                    f"advanced.{field}",
                    f"Must be an integer, got: {type(value).__name__}"
                ))
            elif value is not None and value < 0:
                self.errors.append(ValidationError(
                    f"advanced.{field}",
                    f"Must be non-negative, got: {value}"
                ))
    
    def _build_config(self, raw: Dict) -> ScopeConfig:
        """Build ScopeConfig from validated raw config."""
        target = raw.get("target", {})
        scope = raw.get("scope", {})
        indicators = raw.get("indicators", {})
        auth = raw.get("auth", {})
        output = raw.get("output", {})
        advanced = raw.get("advanced", {})
        
        self.config = ScopeConfig(
            # Target
            primary_target=target.get("primary", ""),
            additional_targets=target.get("additional", []) or [],
            
            # Scope
            include_patterns=[re.compile(p) for p in scope.get("include", [])],
            exclude_patterns=[re.compile(p) for p in scope.get("exclude", [])],
            exclude_extensions=scope.get("exclude_extensions", []),
            exclude_domains=scope.get("exclude_domains", []),
            
            # Indicators
            enabled_indicators=indicators.get("enabled", []),
            indicator_config={k: v for k, v in indicators.items() if k != "enabled"},
            
            # Auth
            auth_type=auth.get("type", "bearer"),
            auth_header=auth.get("header", "Authorization"),
            auth_prefix=auth.get("prefix", "Bearer "),
            auth_contexts=auth.get("contexts", {}),
            
            # Output
            output_dir=output.get("directory", "./output"),
            output_format=output.get("format", "markdown"),
            include_evidence=output.get("include_evidence", True),
            redact_sensitive=output.get("redact_sensitive", True),
            
            # Advanced
            max_endpoints=advanced.get("max_endpoints", 0),
            min_interest_score=advanced.get("min_interest_score", 3),
            request_timeout=advanced.get("request_timeout", 30),
            rate_limit=advanced.get("rate_limit", 0),
            
            # Raw
            raw=raw
        )
        
        return self.config
    
    def _is_valid_url(self, url: str) -> bool:
        """Check if URL is valid."""
        try:
            result = urlparse(url)
            return all([result.scheme in ("http", "https"), result.netloc])
        except Exception:
            return False
    
    def matches_scope(self, path: str, host: str = None) -> bool:
        """Check if a path/host matches the current scope configuration."""
        if not self.config:
            return True  # No config = match everything
        
        # Check excluded domains
        if host:
            for pattern in self.config.exclude_domains:
                if pattern.startswith("*"):
                    if host.endswith(pattern[1:]):
                        return False
                elif host == pattern:
                    return False
        
        # Check excluded extensions
        for ext in self.config.exclude_extensions:
            if path.lower().endswith(ext.lower()):
                return False
        
        # Check excluded patterns
        for pattern in self.config.exclude_patterns:
            if pattern.search(path):
                return False
        
        # Check included patterns (if any defined, must match at least one)
        if self.config.include_patterns:
            for pattern in self.config.include_patterns:
                if pattern.search(path):
                    return True
            return False
        
        return True
    
    def print_summary(self):
        """Print a summary of the scope configuration."""
        if not self.config:
            print("❌ No valid configuration loaded")
            return
        
        print("=" * 60)
        print("SCOPE CONFIGURATION SUMMARY")
        print("=" * 60)
        
        # Target
        print(f"\n📎 Target: {self.config.primary_target}")
        if self.config.additional_targets:
            print(f"   Additional: {', '.join(self.config.additional_targets)}")
        
        # Scope
        print(f"\n🎯 Scope:")
        print(f"   Include patterns: {len(self.config.include_patterns)}")
        print(f"   Exclude patterns: {len(self.config.exclude_patterns)}")
        print(f"   Exclude extensions: {len(self.config.exclude_extensions)}")
        print(f"   Exclude domains: {len(self.config.exclude_domains)}")
        
        # Indicators
        print(f"\n🔍 Indicators: {', '.join(self.config.enabled_indicators) or 'None'}")
        
        # Auth
        print(f"\n🔐 Auth: {self.config.auth_type}")
        print(f"   Contexts: {', '.join(self.config.auth_contexts.keys()) or 'None'}")
        
        # Output
        print(f"\n📁 Output: {self.config.output_dir}")
        print(f"   Format: {self.config.output_format}")
        
        print("=" * 60)
    
    def print_errors(self):
        """Print all errors and warnings."""
        if self.errors:
            print("\n❌ ERRORS:")
            for err in self.errors:
                print(f"   {err}")
        
        if self.warnings:
            print("\n⚠️  WARNINGS:")
            for warn in self.warnings:
                print(f"   {warn}")


def main():
    """CLI entry point."""
    scope_path = sys.argv[1] if len(sys.argv) > 1 else None
    
    validator = ScopeValidator(scope_path)
    valid = validator.validate()
    
    validator.print_errors()
    
    if valid:
        validator.print_summary()
        print("\n✅ Scope configuration is valid")
        sys.exit(0)
    else:
        print("\n❌ Scope configuration has errors")
        sys.exit(1)


if __name__ == "__main__":
    main()
