#!/usr/bin/env python3
"""Tests for endpoint_filter module."""

import json
import pytest

from lib.endpoint_filter import EndpointFilter, Endpoint


@pytest.fixture
def sample_entries():
    """Return sample Burp proxy history entries."""
    return [
        {
            "id": "1",
            "method": "GET",
            "url": "https://api.example.com/users/123/profile?include=email",
            "host": "api.example.com",
            "path": "/users/123/profile",
            "status": 200,
            "content_type": "application/json",
            "headers": {"Authorization": "Bearer xxx"},
        },
        {
            "id": "2",
            "method": "POST",
            "url": "https://api.example.com/users/456/profile",
            "host": "api.example.com",
            "path": "/users/456/profile",
            "status": 200,
            "content_type": "application/json",
            "headers": {"Authorization": "Bearer yyy"},
            "request_body": '{"name": "test", "email": "test@example.com"}',
        },
        {
            "id": "3",
            "method": "GET",
            "url": "https://api.example.com/admin/config",
            "host": "api.example.com",
            "path": "/admin/config",
            "status": 403,
            "content_type": "application/json",
            "headers": {},
        },
        {
            "id": "4",
            "method": "POST",
            "url": "https://api.example.com/auth/login",
            "host": "api.example.com",
            "path": "/auth/login",
            "status": 200,
            "content_type": "application/json",
            "headers": {},
            "request_body": "username=admin&password=secret",
        },
        {
            "id": "5",
            "method": "GET",
            "url": "https://api.example.com/export/data?url=https://internal.example.com",
            "host": "api.example.com",
            "path": "/export/data",
            "status": 200,
            "content_type": "application/json",
            "headers": {"Authorization": "Bearer zzz"},
        },
        {
            "id": "6",
            "method": "PUT",
            "url": "https://api.example.com/payment/order/789",
            "host": "api.example.com",
            "path": "/payment/order/789",
            "status": 200,
            "content_type": "application/json",
            "headers": {"Authorization": "Bearer zzz"},
            "request_body": '{"amount": 100}',
        },
    ]


@pytest.fixture
def filter_with_entries(sample_entries):
    """Return an EndpointFilter with sample entries loaded."""
    ef = EndpointFilter()
    for entry in sample_entries:
        ef.add_entry(entry)
    return ef


class TestEndpoint:
    def test_key(self):
        ep = Endpoint(method="GET", path="/users/{id}", host="api.example.com")
        assert ep.key == "GET:api.example.com:/users/{id}"

    def test_has_id_param(self):
        ep = Endpoint(
            method="GET",
            path="/users",
            host="api.example.com",
            query_params={"user_id", "include"},
        )
        assert ep.has_id_param is True

    def test_has_no_id_param(self):
        ep = Endpoint(
            method="GET",
            path="/users",
            host="api.example.com",
            query_params={"search", "page"},
        )
        assert ep.has_id_param is False

    def test_has_url_param(self):
        ep = Endpoint(
            method="GET",
            path="/proxy",
            host="api.example.com",
            query_params={"url", "format"},
        )
        assert ep.has_url_param is True

    def test_has_no_url_param(self):
        ep = Endpoint(
            method="GET",
            path="/search",
            host="api.example.com",
            query_params={"query", "page"},
        )
        assert ep.has_url_param is False

    def test_to_dict(self):
        ep = Endpoint(
            method="GET",
            path="/test",
            host="example.com",
            category="api",
            interest_score=7,
        )
        d = ep.to_dict()
        assert d["method"] == "GET"
        assert d["path"] == "/test"
        assert d["category"] == "api"
        assert d["interest_score"] == 7

    def test_from_dict(self):
        data = {
            "method": "POST",
            "path": "/users",
            "host": "api.example.com",
            "query_params": ["search"],
            "body_params": ["name", "email"],
            "auth_headers": ["Authorization"],
            "content_types": ["application/json"],
            "response_codes": [200, 201],
            "category": "user",
            "interest_score": 8,
            "indicators": ["idor"],
            "request_ids": ["1", "2"],
            "sample_request_id": "1",
        }
        ep = Endpoint.from_dict(data)
        assert ep.method == "POST"
        assert ep.path == "/users"
        assert "name" in ep.body_params
        assert ep.interest_score == 8

    def test_roundtrip(self):
        ep = Endpoint(
            method="DELETE",
            path="/items/{id}",
            host="api.example.com",
            query_params={"force"},
            body_params=set(),
            auth_headers={"Authorization"},
            content_types={"application/json"},
            response_codes={200, 204},
            category="api",
            interest_score=9,
            indicators=["idor", "bola"],
            request_ids=["10"],
            sample_request_id="10",
        )
        d = ep.to_dict()
        ep2 = Endpoint.from_dict(d)
        assert ep2.method == ep.method
        assert ep2.path == ep.path
        assert ep2.host == ep.host


class TestEndpointFilter:
    def test_add_entry(self, filter_with_entries):
        assert len(filter_with_entries.endpoints) > 0

    def test_deduplication(self, sample_entries):
        """Entries with same normalized path should be merged."""
        ef = EndpointFilter()
        # Add two GET requests to /users/{id}/profile
        ef.add_entry(sample_entries[0])  # /users/123/profile
        ef.add_entry(sample_entries[1])  # POST /users/456/profile - different method
        # GET and POST to same normalized path are different endpoints
        # But /users/123 and /users/456 normalize to /users/{id}
        # so GET:/users/{id}/profile should be one endpoint
        # and POST:/users/{id}/profile should be another
        keys = list(ef.endpoints.keys())
        get_keys = [k for k in keys if k.startswith("GET")]
        assert len(get_keys) == 1  # Only one GET:/users/{id}/profile

    def test_parse_entry_no_path(self):
        ef = EndpointFilter()
        result = ef.parse_burp_entry({"method": "GET"})
        assert result is None

    def test_parse_entry_url_fallback(self):
        ef = EndpointFilter()
        result = ef.parse_burp_entry(
            {
                "id": "1",
                "method": "GET",
                "url": "https://api.example.com/test?q=1",
            }
        )
        assert result is not None
        key, data = result
        assert data["path"] == "/test"
        assert "q" in data["query_params"]

    def test_normalize_path_uuid(self):
        ef = EndpointFilter()
        path = ef._normalize_path(
            "/users/550e8400-e29b-41d4-a716-446655440000/profile"
        )
        assert "{uuid}" in path

    def test_normalize_path_numeric_id(self):
        ef = EndpointFilter()
        path = ef._normalize_path("/users/12345/profile")
        assert "{id}" in path
        assert "12345" not in path

    def test_normalize_path_query_removed(self):
        ef = EndpointFilter()
        path = ef._normalize_path("/search?q=test&page=1")
        assert "?" not in path
        assert path == "/search"

    def test_classify_auth(self, filter_with_entries):
        endpoints = list(filter_with_entries.endpoints.values())
        filter_with_entries.classify_and_score(endpoints)
        auth_eps = [ep for ep in endpoints if ep.category == "auth"]
        assert len(auth_eps) > 0

    def test_classify_admin(self, filter_with_entries):
        endpoints = list(filter_with_entries.endpoints.values())
        filter_with_entries.classify_and_score(endpoints)
        admin_eps = [ep for ep in endpoints if ep.category == "admin"]
        assert len(admin_eps) > 0

    def test_classify_payment(self, filter_with_entries):
        endpoints = list(filter_with_entries.endpoints.values())
        filter_with_entries.classify_and_score(endpoints)
        payment_eps = [ep for ep in endpoints if ep.category == "payment"]
        assert len(payment_eps) > 0

    def test_score_admin_high(self, filter_with_entries):
        endpoints = filter_with_entries.classify_and_score()
        admin_eps = [ep for ep in endpoints if ep.category == "admin"]
        for ep in admin_eps:
            assert ep.interest_score >= 9  # base 5 + admin 4

    def test_score_mutation_bonus(self):
        ef = EndpointFilter()
        ep = Endpoint(method="POST", path="/api/data", host="example.com")
        ef.endpoints[ep.key] = ep
        scored = ef.classify_and_score()
        assert scored[0].interest_score >= 7  # base 5 + mutation 2

    def test_tag_indicators_idor(self):
        ef = EndpointFilter()
        ep = Endpoint(
            method="GET",
            path="/users/{id}",
            host="example.com",
            query_params={"user_id"},
        )
        indicators = ef._tag_indicators(ep)
        assert "idor" in indicators

    def test_tag_indicators_ssrf(self):
        ef = EndpointFilter()
        ep = Endpoint(
            method="GET",
            path="/proxy",
            host="example.com",
            query_params={"url"},
        )
        indicators = ef._tag_indicators(ep)
        assert "ssrf" in indicators

    def test_tag_indicators_auth_bypass(self):
        ef = EndpointFilter()
        ep = Endpoint(
            method="POST", path="/auth/login", host="example.com", category="auth"
        )
        indicators = ef._tag_indicators(ep)
        assert "auth_bypass" in indicators

    def test_prioritize_order(self, filter_with_entries):
        prioritized = filter_with_entries.prioritize()
        for i in range(len(prioritized) - 1):
            assert prioritized[i].interest_score >= prioritized[i + 1].interest_score

    def test_to_json(self, filter_with_entries):
        json_str = filter_with_entries.to_json()
        data = json.loads(json_str)
        assert "total" in data
        assert "endpoints" in data
        assert "by_category" in data
        assert "by_indicator" in data
        assert data["total"] > 0

    def test_to_json_file(self, filter_with_entries, tmp_path):
        output_path = str(tmp_path / "endpoints.json")
        filter_with_entries.to_json(path=output_path)
        with open(output_path) as f:
            data = json.load(f)
        assert data["total"] > 0

    def test_extract_body_params_json(self):
        ef = EndpointFilter()
        params = ef._extract_body_params(
            '{"name": "test", "nested": {"key": "val"}}',
            "application/json",
        )
        assert "name" in params
        assert "nested.key" in params

    def test_extract_body_params_form(self):
        ef = EndpointFilter()
        params = ef._extract_body_params(
            "username=admin&password=secret",
            "application/x-www-form-urlencoded",
        )
        assert "username" in params
        assert "password" in params

    def test_extract_body_params_invalid_json(self):
        ef = EndpointFilter()
        params = ef._extract_body_params("not json", "application/json")
        assert len(params) == 0

    def test_group_by_category(self, filter_with_entries):
        endpoints = filter_with_entries.classify_and_score()
        groups = filter_with_entries._group_by_category(endpoints)
        assert isinstance(groups, dict)
        total = sum(groups.values())
        assert total == len(endpoints)

    def test_group_by_indicator(self, filter_with_entries):
        endpoints = filter_with_entries.classify_and_score()
        groups = filter_with_entries._group_by_indicator(endpoints)
        assert isinstance(groups, dict)
