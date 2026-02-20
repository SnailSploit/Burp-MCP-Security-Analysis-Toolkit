#!/usr/bin/env python3
"""
Endpoint Filter - Filter and prioritize endpoints from Burp traffic.

Works with the output from Burp MCP to filter endpoints based on scope.yaml
configuration and assign interest scores.

Usage:
    from endpoint_filter import EndpointFilter, Endpoint
    
    filter = EndpointFilter(scope_config)
    filtered = filter.filter_endpoints(raw_endpoints)
    prioritized = filter.prioritize(filtered)
"""

import re
import json
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any, Tuple
from urllib.parse import urlparse, parse_qs
from pathlib import Path
from collections import defaultdict


@dataclass
class Endpoint:
    """Represents a unique API endpoint."""
    method: str
    path: str
    host: str
    
    # Query parameters seen
    query_params: Set[str] = field(default_factory=set)
    
    # Body parameters seen
    body_params: Set[str] = field(default_factory=set)
    
    # Headers of interest
    auth_headers: Set[str] = field(default_factory=set)
    
    # Content types seen
    content_types: Set[str] = field(default_factory=set)
    
    # Response codes seen
    response_codes: Set[int] = field(default_factory=set)
    
    # Classification
    category: str = "unknown"
    interest_score: int = 0
    indicators: List[str] = field(default_factory=list)
    
    # Burp request IDs for this endpoint
    request_ids: List[str] = field(default_factory=list)
    
    # Sample request/response (first seen)
    sample_request_id: Optional[str] = None
    
    @property
    def key(self) -> str:
        """Unique key for deduplication."""
        return f"{self.method}:{self.host}:{self.path}"
    
    @property
    def has_id_param(self) -> bool:
        """Check if endpoint has ID-like parameters."""
        id_patterns = ['id', 'user_id', 'account_id', 'order_id', 'uuid', 'uid']
        all_params = self.query_params | self.body_params
        return any(
            any(pattern in param.lower() for pattern in id_patterns)
            for param in all_params
        )
    
    @property  
    def has_url_param(self) -> bool:
        """Check if endpoint has URL-like parameters (SSRF indicator)."""
        url_patterns = ['url', 'uri', 'link', 'redirect', 'callback', 'next', 'return', 'dest', 'target']
        all_params = self.query_params | self.body_params
        return any(
            any(pattern in param.lower() for pattern in url_patterns)
            for param in all_params
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "method": self.method,
            "path": self.path,
            "host": self.host,
            "query_params": list(self.query_params),
            "body_params": list(self.body_params),
            "auth_headers": list(self.auth_headers),
            "content_types": list(self.content_types),
            "response_codes": list(self.response_codes),
            "category": self.category,
            "interest_score": self.interest_score,
            "indicators": self.indicators,
            "request_ids": self.request_ids,
            "sample_request_id": self.sample_request_id
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Endpoint':
        """Create from dictionary."""
        return cls(
            method=data["method"],
            path=data["path"],
            host=data["host"],
            query_params=set(data.get("query_params", [])),
            body_params=set(data.get("body_params", [])),
            auth_headers=set(data.get("auth_headers", [])),
            content_types=set(data.get("content_types", [])),
            response_codes=set(data.get("response_codes", [])),
            category=data.get("category", "unknown"),
            interest_score=data.get("interest_score", 0),
            indicators=data.get("indicators", []),
            request_ids=data.get("request_ids", []),
            sample_request_id=data.get("sample_request_id")
        )


class EndpointFilter:
    """Filter and prioritize endpoints based on scope configuration."""
    
    # Endpoint categories - ordered by security priority (higher-risk first)
    CATEGORIES = {
        "admin": ["admin", "manage", "dashboard", "internal", "config", "system"],
        "auth": ["login", "logout", "register", "signup", "signin", "oauth", "token", "session", "password", "reset", "verify", "confirm", "2fa", "mfa"],
        "payment": ["payment", "checkout", "billing", "invoice", "subscription", "order"],
        "upload": ["upload", "file", "image", "document", "attachment", "media"],
        "data": ["export", "download", "report", "data", "backup"],
        "user": ["user", "profile", "account", "me", "self", "settings", "preferences"],
        "api": ["api", "graphql", "rest", "v1", "v2", "v3"],
    }
    
    # Interest score modifiers
    SCORE_MODIFIERS = {
        "has_id_param": 3,
        "has_url_param": 3,
        "is_mutation": 2,  # POST, PUT, PATCH, DELETE
        "auth_endpoint": 2,
        "admin_endpoint": 4,
        "payment_endpoint": 3,
        "data_endpoint": 2,
        "upload_endpoint": 2,
        "has_body": 1,
        "returns_json": 1,
        "returns_sensitive_code": 2,  # 403, 401
    }
    
    def __init__(self, scope_config: Optional[Any] = None):
        """
        Initialize with scope configuration.
        
        Args:
            scope_config: ScopeConfig object from scope_validator.py
        """
        self.scope_config = scope_config
        self.endpoints: Dict[str, Endpoint] = {}
        
    def parse_burp_entry(self, entry: Dict[str, Any]) -> Optional[Tuple[str, Dict]]:
        """
        Parse a single Burp proxy history entry.
        
        Expected format from Burp MCP:
        {
            "id": "12345",
            "method": "GET",
            "url": "https://api.example.com/users/123?include=profile",
            "host": "api.example.com",
            "path": "/users/123",
            "request": "GET /users/123...",
            "response": "HTTP/1.1 200 OK...",
            "status": 200,
            "content_type": "application/json"
        }
        """
        try:
            method = entry.get("method", "GET").upper()
            url = entry.get("url", "")
            host = entry.get("host", "")
            path = entry.get("path", "")
            
            # Parse URL if path not directly available
            if not path and url:
                parsed = urlparse(url)
                path = parsed.path
                host = parsed.netloc
            
            if not path:
                return None
            
            # Normalize path (remove query string, normalize IDs)
            normalized_path = self._normalize_path(path)
            key = f"{method}:{host}:{normalized_path}"
            
            # Extract parameters
            query_params = set()
            if url:
                parsed = urlparse(url)
                query_params = set(parse_qs(parsed.query).keys())
            
            # Extract body params (simplified - assumes JSON or form)
            body_params = set()
            request_body = entry.get("request_body", "")
            if request_body:
                body_params = self._extract_body_params(request_body, entry.get("content_type", ""))
            
            # Auth headers
            auth_headers = set()
            headers = entry.get("headers", {})
            for header in ["Authorization", "Cookie", "X-API-Key", "X-Auth-Token"]:
                if header.lower() in [h.lower() for h in headers.keys()]:
                    auth_headers.add(header)
            
            return key, {
                "method": method,
                "path": normalized_path,
                "host": host,
                "query_params": query_params,
                "body_params": body_params,
                "auth_headers": auth_headers,
                "content_type": entry.get("content_type", ""),
                "status": entry.get("status", 0),
                "request_id": entry.get("id", ""),
            }
            
        except Exception as e:
            print(f"Error parsing entry: {e}")
            return None
    
    def add_entry(self, entry: Dict[str, Any]):
        """Add a Burp entry, merging with existing endpoint if duplicate."""
        result = self.parse_burp_entry(entry)
        if not result:
            return
        
        key, data = result
        
        if key in self.endpoints:
            # Merge with existing
            ep = self.endpoints[key]
            ep.query_params.update(data["query_params"])
            ep.body_params.update(data["body_params"])
            ep.auth_headers.update(data["auth_headers"])
            if data["content_type"]:
                ep.content_types.add(data["content_type"])
            if data["status"]:
                ep.response_codes.add(data["status"])
            if data["request_id"]:
                ep.request_ids.append(data["request_id"])
        else:
            # Create new
            ep = Endpoint(
                method=data["method"],
                path=data["path"],
                host=data["host"],
                query_params=data["query_params"],
                body_params=data["body_params"],
                auth_headers=data["auth_headers"],
                content_types={data["content_type"]} if data["content_type"] else set(),
                response_codes={data["status"]} if data["status"] else set(),
                request_ids=[data["request_id"]] if data["request_id"] else [],
                sample_request_id=data["request_id"]
            )
            self.endpoints[key] = ep
    
    def filter_in_scope(self) -> List[Endpoint]:
        """Filter endpoints to only those in scope."""
        if not self.scope_config:
            return list(self.endpoints.values())
        
        filtered = []
        for ep in self.endpoints.values():
            if self._matches_scope(ep):
                filtered.append(ep)
        
        return filtered
    
    def classify_and_score(self, endpoints: List[Endpoint] = None) -> List[Endpoint]:
        """Classify endpoints and calculate interest scores."""
        if endpoints is None:
            endpoints = list(self.endpoints.values())
        
        for ep in endpoints:
            # Classify
            ep.category = self._classify(ep)
            
            # Calculate score
            ep.interest_score = self._calculate_score(ep)
            
            # Tag indicators
            ep.indicators = self._tag_indicators(ep)
        
        return endpoints
    
    def prioritize(self, endpoints: List[Endpoint] = None) -> List[Endpoint]:
        """Sort endpoints by interest score (descending)."""
        if endpoints is None:
            endpoints = self.filter_in_scope()
            endpoints = self.classify_and_score(endpoints)
        
        return sorted(endpoints, key=lambda e: e.interest_score, reverse=True)
    
    def to_json(self, endpoints: List[Endpoint] = None, path: str = None) -> str:
        """Export endpoints to JSON."""
        if endpoints is None:
            endpoints = self.prioritize()
        
        data = {
            "total": len(endpoints),
            "by_category": self._group_by_category(endpoints),
            "by_indicator": self._group_by_indicator(endpoints),
            "endpoints": [ep.to_dict() for ep in endpoints]
        }
        
        json_str = json.dumps(data, indent=2)
        
        if path:
            Path(path).write_text(json_str)
        
        return json_str
    
    def _normalize_path(self, path: str) -> str:
        """Normalize path by replacing IDs with placeholders."""
        # Remove query string
        path = path.split("?")[0]
        
        # Replace UUIDs
        path = re.sub(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            '{uuid}',
            path,
            flags=re.IGNORECASE
        )
        
        # Replace numeric IDs in path segments
        path = re.sub(r'/(\d+)(/|$)', r'/{id}\2', path)
        
        # Replace base64-looking segments
        path = re.sub(r'/[A-Za-z0-9+/]{20,}={0,2}(/|$)', r'/{encoded}\1', path)
        
        return path
    
    def _extract_body_params(self, body: str, content_type: str) -> Set[str]:
        """Extract parameter names from request body."""
        params = set()
        
        if not body:
            return params
        
        # JSON body
        if "json" in content_type.lower():
            try:
                data = json.loads(body)
                params = self._extract_json_keys(data)
            except (json.JSONDecodeError, TypeError, ValueError):
                pass
        
        # Form body
        elif "form" in content_type.lower():
            for part in body.split("&"):
                if "=" in part:
                    params.add(part.split("=")[0])
        
        return params
    
    def _extract_json_keys(self, data: Any, prefix: str = "") -> Set[str]:
        """Recursively extract keys from JSON structure."""
        keys = set()
        
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                keys.add(full_key)
                keys.update(self._extract_json_keys(value, full_key))
        elif isinstance(data, list) and data:
            keys.update(self._extract_json_keys(data[0], prefix))
        
        return keys
    
    def _matches_scope(self, endpoint: Endpoint) -> bool:
        """Check if endpoint matches scope configuration."""
        if not self.scope_config:
            return True
        
        # Check excluded domains
        for pattern in self.scope_config.exclude_domains:
            if pattern.startswith("*"):
                if endpoint.host.endswith(pattern[1:]):
                    return False
            elif endpoint.host == pattern:
                return False
        
        # Check excluded extensions
        for ext in self.scope_config.exclude_extensions:
            if endpoint.path.lower().endswith(ext.lower()):
                return False
        
        # Check excluded patterns
        for pattern in self.scope_config.exclude_patterns:
            if pattern.search(endpoint.path):
                return False
        
        # Check included patterns
        if self.scope_config.include_patterns:
            for pattern in self.scope_config.include_patterns:
                if pattern.search(endpoint.path):
                    return True
            return False
        
        return True
    
    def _classify(self, endpoint: Endpoint) -> str:
        """Classify endpoint into a category.

        Uses word-boundary matching on path segments to avoid false positives
        from substring matches (e.g. 'me' matching inside 'payment').
        """
        # Split path into segments for accurate matching
        path_segments = [s.lower() for s in endpoint.path.split("/") if s and not s.startswith("{")]
        path_lower = endpoint.path.lower()

        best_category = "general"
        best_score = 0

        for category, patterns in self.CATEGORIES.items():
            score = 0
            for pattern in patterns:
                # Prefer exact segment match over substring
                if pattern in path_segments:
                    score += 2
                elif pattern in path_lower and len(pattern) > 2:
                    # Only allow substring match for patterns longer than 2 chars
                    # to avoid false positives like 'me' in 'payment'
                    score += 1
            if score > best_score:
                best_score = score
                best_category = category

        return best_category
    
    def _calculate_score(self, endpoint: Endpoint) -> int:
        """Calculate interest score for an endpoint."""
        score = 5  # Base score
        
        # ID parameters
        if endpoint.has_id_param:
            score += self.SCORE_MODIFIERS["has_id_param"]
        
        # URL parameters (SSRF)
        if endpoint.has_url_param:
            score += self.SCORE_MODIFIERS["has_url_param"]
        
        # Mutation methods
        if endpoint.method in ["POST", "PUT", "PATCH", "DELETE"]:
            score += self.SCORE_MODIFIERS["is_mutation"]
        
        # Category bonuses
        category_bonuses = {
            "auth": "auth_endpoint",
            "admin": "admin_endpoint", 
            "payment": "payment_endpoint",
            "data": "data_endpoint",
            "upload": "upload_endpoint"
        }
        if endpoint.category in category_bonuses:
            score += self.SCORE_MODIFIERS[category_bonuses[endpoint.category]]
        
        # Has body
        if endpoint.body_params:
            score += self.SCORE_MODIFIERS["has_body"]
        
        # Returns JSON
        if any("json" in ct.lower() for ct in endpoint.content_types):
            score += self.SCORE_MODIFIERS["returns_json"]
        
        # Sensitive response codes
        if endpoint.response_codes & {401, 403}:
            score += self.SCORE_MODIFIERS["returns_sensitive_code"]
        
        return score
    
    def _tag_indicators(self, endpoint: Endpoint) -> List[str]:
        """Tag endpoint with relevant vulnerability indicators."""
        indicators = []
        
        # IDOR - ID parameters
        if endpoint.has_id_param:
            indicators.append("idor")
        
        # BOLA - Object references + auth
        if endpoint.has_id_param and endpoint.auth_headers:
            indicators.append("bola")
        
        # SSRF - URL parameters
        if endpoint.has_url_param:
            indicators.append("ssrf")
        
        # Auth bypass - auth endpoints
        if endpoint.category == "auth":
            indicators.append("auth_bypass")
        
        # Injection - data input endpoints
        if endpoint.body_params or endpoint.query_params:
            indicators.append("injection")
        
        return indicators
    
    def _group_by_category(self, endpoints: List[Endpoint]) -> Dict[str, int]:
        """Group endpoint counts by category."""
        groups = defaultdict(int)
        for ep in endpoints:
            groups[ep.category] += 1
        return dict(groups)
    
    def _group_by_indicator(self, endpoints: List[Endpoint]) -> Dict[str, int]:
        """Group endpoint counts by indicator."""
        groups = defaultdict(int)
        for ep in endpoints:
            for ind in ep.indicators:
                groups[ind] += 1
        return dict(groups)


def main():
    """Demo usage."""
    # Example Burp entries
    entries = [
        {
            "id": "1",
            "method": "GET",
            "url": "https://api.example.com/users/123/profile",
            "host": "api.example.com",
            "path": "/users/123/profile",
            "status": 200,
            "content_type": "application/json",
            "headers": {"Authorization": "Bearer xxx"}
        },
        {
            "id": "2",
            "method": "POST",
            "url": "https://api.example.com/users/456/profile",
            "host": "api.example.com",
            "path": "/users/456/profile",
            "status": 200,
            "content_type": "application/json",
            "headers": {"Authorization": "Bearer yyy"}
        },
        {
            "id": "3",
            "method": "GET",
            "url": "https://api.example.com/admin/config",
            "host": "api.example.com",
            "path": "/admin/config",
            "status": 403,
            "content_type": "application/json",
            "headers": {}
        },
        {
            "id": "4",
            "method": "POST",
            "url": "https://api.example.com/auth/login",
            "host": "api.example.com",
            "path": "/auth/login",
            "status": 200,
            "content_type": "application/json",
            "headers": {}
        }
    ]
    
    filter = EndpointFilter()
    
    # Add entries
    for entry in entries:
        filter.add_entry(entry)
    
    # Process
    endpoints = filter.prioritize()
    
    # Output
    print("=" * 60)
    print("ENDPOINT ANALYSIS")
    print("=" * 60)
    
    for ep in endpoints:
        print(f"\n[Score: {ep.interest_score}] {ep.method} {ep.path}")
        print(f"  Category: {ep.category}")
        print(f"  Indicators: {', '.join(ep.indicators) or 'None'}")
        print(f"  Params: {ep.query_params | ep.body_params or 'None'}")
    
    print("\n" + "=" * 60)
    print("JSON OUTPUT:")
    print(filter.to_json(endpoints))


if __name__ == "__main__":
    main()
