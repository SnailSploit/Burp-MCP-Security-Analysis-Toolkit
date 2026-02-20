#!/usr/bin/env python3
"""Tests for scope_validator module."""

import os
import tempfile
import pytest
import yaml

from lib.scope_validator import ScopeValidator, ScopeConfig, ValidationError


@pytest.fixture
def valid_scope_yaml():
    """Return a valid scope.yaml content."""
    return {
        "target": {
            "primary": "https://api.example.com",
            "additional": ["https://cdn.example.com"],
        },
        "scope": {
            "include": [r"^/api/"],
            "exclude": [r"^/api/docs"],
            "exclude_extensions": [".css", ".js", ".png"],
            "exclude_domains": ["*.googleapis.com"],
        },
        "indicators": {
            "enabled": ["idor", "bola", "auth_bypass", "ssrf", "injection"],
            "ssrf": {"callback_url": "https://callback.example.com"},
        },
        "auth": {
            "type": "bearer",
            "header": "Authorization",
            "prefix": "Bearer ",
            "contexts": {
                "user_a": {"token": "token_a", "role": "user"},
                "user_b": {"token": "token_b", "role": "user"},
            },
        },
        "output": {
            "directory": "./output",
            "format": "markdown",
            "include_evidence": True,
            "redact_sensitive": True,
        },
        "advanced": {
            "max_endpoints": 100,
            "min_interest_score": 3,
            "request_timeout": 30,
            "rate_limit": 10,
        },
    }


@pytest.fixture
def scope_file(valid_scope_yaml):
    """Create a temporary scope.yaml file."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as f:
        yaml.dump(valid_scope_yaml, f)
        path = f.name
    yield path
    os.unlink(path)


class TestScopeValidator:
    def test_valid_scope(self, scope_file):
        validator = ScopeValidator(scope_file)
        assert validator.validate() is True
        assert len(validator.errors) == 0

    def test_missing_file(self):
        validator = ScopeValidator("/nonexistent/scope.yaml")
        assert validator.validate() is False
        assert any("not found" in str(e) for e in validator.errors)

    def test_empty_file(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write("")
            path = f.name
        try:
            validator = ScopeValidator(path)
            assert validator.validate() is False
        finally:
            os.unlink(path)

    def test_missing_target(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump({"scope": {"include": [".*"]}}, f)
            path = f.name
        try:
            validator = ScopeValidator(path)
            assert validator.validate() is False
            assert any("target" in str(e) for e in validator.errors)
        finally:
            os.unlink(path)

    def test_invalid_target_url(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump({"target": {"primary": "not-a-url"}}, f)
            path = f.name
        try:
            validator = ScopeValidator(path)
            assert validator.validate() is False
            assert any("Invalid URL" in str(e) for e in validator.errors)
        finally:
            os.unlink(path)

    def test_invalid_regex_pattern(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump(
                {
                    "target": {"primary": "https://example.com"},
                    "scope": {"include": ["[invalid regex"]},
                },
                f,
            )
            path = f.name
        try:
            validator = ScopeValidator(path)
            assert validator.validate() is False
            assert any("regex" in str(e).lower() for e in validator.errors)
        finally:
            os.unlink(path)

    def test_invalid_auth_type(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump(
                {
                    "target": {"primary": "https://example.com"},
                    "auth": {"type": "invalid_type"},
                },
                f,
            )
            path = f.name
        try:
            validator = ScopeValidator(path)
            assert validator.validate() is False
            assert any("auth type" in str(e).lower() for e in validator.errors)
        finally:
            os.unlink(path)

    def test_invalid_output_format(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump(
                {
                    "target": {"primary": "https://example.com"},
                    "output": {"format": "pdf"},
                },
                f,
            )
            path = f.name
        try:
            validator = ScopeValidator(path)
            assert validator.validate() is False
            assert any("output format" in str(e).lower() for e in validator.errors)
        finally:
            os.unlink(path)

    def test_negative_advanced_value(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump(
                {
                    "target": {"primary": "https://example.com"},
                    "advanced": {"max_endpoints": -1},
                },
                f,
            )
            path = f.name
        try:
            validator = ScopeValidator(path)
            assert validator.validate() is False
        finally:
            os.unlink(path)

    def test_warning_unknown_indicator(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump(
                {
                    "target": {"primary": "https://example.com"},
                    "indicators": {"enabled": ["idor", "fake_indicator"]},
                },
                f,
            )
            path = f.name
        try:
            validator = ScopeValidator(path)
            validator.validate()
            assert any("Unknown indicator" in str(w) for w in validator.warnings)
        finally:
            os.unlink(path)

    def test_warning_idor_without_two_contexts(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump(
                {
                    "target": {"primary": "https://example.com"},
                    "indicators": {"enabled": ["idor"]},
                    "auth": {
                        "type": "bearer",
                        "contexts": {"user_a": {"token": "t1"}},
                    },
                },
                f,
            )
            path = f.name
        try:
            validator = ScopeValidator(path)
            validator.validate()
            assert any("2 auth contexts" in str(w) for w in validator.warnings)
        finally:
            os.unlink(path)

    def test_warning_ssrf_without_callback(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump(
                {
                    "target": {"primary": "https://example.com"},
                    "indicators": {"enabled": ["ssrf"]},
                },
                f,
            )
            path = f.name
        try:
            validator = ScopeValidator(path)
            validator.validate()
            assert any("callback" in str(w).lower() for w in validator.warnings)
        finally:
            os.unlink(path)


class TestScopeConfig:
    def test_config_built_on_valid(self, scope_file):
        validator = ScopeValidator(scope_file)
        validator.validate()
        config = validator.config
        assert config is not None
        assert config.primary_target == "https://api.example.com"
        assert "idor" in config.enabled_indicators
        assert config.auth_type == "bearer"
        assert config.output_format == "markdown"

    def test_matches_scope_included(self, scope_file):
        validator = ScopeValidator(scope_file)
        validator.validate()
        assert validator.matches_scope("/api/users/123") is True

    def test_matches_scope_excluded_path(self, scope_file):
        validator = ScopeValidator(scope_file)
        validator.validate()
        assert validator.matches_scope("/api/docs") is False

    def test_matches_scope_excluded_extension(self, scope_file):
        validator = ScopeValidator(scope_file)
        validator.validate()
        assert validator.matches_scope("/api/style.css") is False

    def test_matches_scope_excluded_domain(self, scope_file):
        validator = ScopeValidator(scope_file)
        validator.validate()
        assert (
            validator.matches_scope("/api/v1", host="fonts.googleapis.com")
            is False
        )

    def test_matches_scope_no_config(self):
        validator = ScopeValidator("/nonexistent")
        # No config loaded, should match everything
        assert validator.matches_scope("/anything") is True


class TestValidationError:
    def test_error_str(self):
        err = ValidationError("test.field", "Something went wrong")
        assert "test.field" in str(err)
        assert "Something went wrong" in str(err)

    def test_warning_str(self):
        warn = ValidationError("test.field", "Consider this", severity="warning")
        assert "test.field" in str(warn)
