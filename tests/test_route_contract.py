"""Unit tests for Route Table Configuration Schema Contract & Rules Sanitizer."""

import pytest
from scripts.route_contract import (
    sanitize_path_prefix,
    validate_upstream_url,
    validate_and_sanitize_route,
    validate_route_table,
)


def test_sanitize_path_prefix():
    # Valid normalizations
    ok, p, err = sanitize_path_prefix("/api/v1/users")
    assert ok and p == "/api/v1/users"

    ok, p, err = sanitize_path_prefix("///api///v1//service/")
    assert ok and p == "/api/v1/service"

    ok, p, err = sanitize_path_prefix("/")
    assert ok and p == "/"

    # Rejections
    ok, _, err = sanitize_path_prefix("api/v1")
    assert not ok and "must begin with '/'" in err

    ok, _, err = sanitize_path_prefix("/api/../etc/passwd")
    assert not ok and "traversal" in err

    ok, _, err = sanitize_path_prefix("/api/v1?filter=true")
    assert not ok and "query strings" in err

    ok, _, err = sanitize_path_prefix("/api/v1\r\nHost: evil.com")
    assert not ok and "CRLF" in err


def test_validate_upstream_url():
    ok, u, err = validate_upstream_url("http://auth-service.internal:8080/v1")
    assert ok and u == "http://auth-service.internal:8080/v1"

    ok, u, err = validate_upstream_url("https://api.gateway.prod")
    assert ok and u == "https://api.gateway.prod"

    # Injections and invalid schemes
    ok, _, err = validate_upstream_url("ftp://upstream.local")
    assert not ok and "Unsupported upstream protocol" in err

    ok, _, err = validate_upstream_url("http://upstream.local:99999")
    assert not ok and "out of range" in err

    ok, _, err = validate_upstream_url("http://upstream.local\r\nEvil: True")
    assert not ok and "CRLF" in err


def test_validate_and_sanitize_route_success():
    spec = {
        "route_id": "auth-service-v1",
        "prefix": "/api/v1/auth",
        "target_upstream": "http://10.0.1.50:8081",
        "weight": 80,
        "priority": 500,
        "timeout_ms": 3000,
        "strip_prefix": True,
        "retry_policy": {
            "max_retries": 4,
            "backoff_multiplier": 2.0,
            "retryable_status_codes": [502, 503],
        },
        "headers_policy": {
            "add": {"X-Forwarded-By": "RouteKernel", "X-Request-Mode": "Proxy"},
            "remove": ["Server", "X-Powered-By"],
        },
    }

    ok, route, errors = validate_and_sanitize_route(spec)
    assert ok
    assert len(errors) == 0
    assert route.route_id == "auth-service-v1"
    assert route.prefix == "/api/v1/auth"
    assert route.weight == 80
    assert route.priority == 500
    assert route.timeout_ms == 3000
    assert route.strip_prefix is True
    assert route.retry_policy.max_retries == 4
    assert route.headers_policy.add["x-forwarded-by"] == "RouteKernel"
    assert "server" in route.headers_policy.remove


def test_validate_and_sanitize_route_failures():
    spec = {
        "route_id": "bad route id with spaces!",
        "prefix": "invalid-prefix-no-slash",
        "target_upstream": "not-a-url",
        "weight": 999,  # > 100
        "timeout_ms": 5,  # < 10ms
        "headers_policy": {
            "add": {"X-Bad-Header": "value\r\nSet-Cookie: pwned"},
        },
    }

    ok, route, errors = validate_and_sanitize_route(spec)
    assert not ok
    assert route is None
    assert len(errors) >= 5


def test_validate_route_table_sorting_and_conflicts():
    routes = [
        {
            "route_id": "r1",
            "prefix": "/api/v1/users",
            "target_upstream": "http://users:8080",
            "priority": 200,
        },
        {
            "route_id": "r2",
            "prefix": "/api/v1",
            "target_upstream": "http://general:8080",
            "priority": 100,
        },
        {
            "route_id": "r3",
            "prefix": "/auth",
            "target_upstream": "http://auth:8080",
            "priority": 300,
        },
    ]

    ok, table, errors = validate_route_table(routes)
    assert ok
    assert len(table) == 3
    # Sorted descending by priority: r3 (300) -> r1 (200) -> r2 (100)
    assert table[0].route_id == "r3"
    assert table[1].route_id == "r1"
    assert table[2].route_id == "r2"

    # Duplicate route_id test
    duplicate_routes = [
        {"route_id": "r1", "prefix": "/a", "target_upstream": "http://a:80"},
        {"route_id": "r1", "prefix": "/b", "target_upstream": "http://b:80"},
    ]
    ok, _, errors = validate_route_table(duplicate_routes)
    assert not ok
    assert any("Duplicate route_id 'r1'" in e for e in errors)

    # Collision test: identical prefix and equal priority
    collision_routes = [
        {"route_id": "r1", "prefix": "/api", "target_upstream": "http://a:80", "priority": 100},
        {"route_id": "r2", "prefix": "/api", "target_upstream": "http://b:80", "priority": 100},
    ]
    ok, _, errors = validate_route_table(collision_routes)
    assert not ok
    assert any("Routing conflict" in e for e in errors)
