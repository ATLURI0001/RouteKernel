"""Dynamic Route Table Configuration Schema Contract & Forwarding Rules Sanitizer."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse


ROUTE_ID_REGEX = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
HEADER_NAME_REGEX = re.compile(r"^[a-zA-Z0-9!#$%&'*+\-.^_`|~]+$")

MIN_TIMEOUT_MS = 10
MAX_TIMEOUT_MS = 60_000
MIN_WEIGHT = 1
MAX_WEIGHT = 100
MIN_PRIORITY = 0
MAX_PRIORITY = 1000
MAX_RETRIES = 10


@dataclass
class RetryPolicy:
    max_retries: int = 3
    backoff_multiplier: float = 1.5
    retryable_status_codes: List[int] = field(default_factory=lambda: [502, 503, 504])


@dataclass
class HeadersPolicy:
    add: Dict[str, str] = field(default_factory=dict)
    remove: List[str] = field(default_factory=list)


@dataclass
class SanitizedRoute:
    route_id: str
    prefix: str
    target_upstream: str
    weight: int = 100
    priority: int = 100
    timeout_ms: int = 5000
    strip_prefix: bool = False
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    headers_policy: HeadersPolicy = field(default_factory=HeadersPolicy)


def sanitize_path_prefix(raw_prefix: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """Sanitizes route prefix against directory traversal and control characters."""
    if not raw_prefix or not isinstance(raw_prefix, str):
        return False, None, "Path prefix must be a non-empty string"

    # Block control characters, null bytes, and newlines
    if any(ord(c) < 32 or c in "\r\n\0" for c in raw_prefix):
        return False, None, "Path prefix contains prohibited control characters or CRLF"

    # Must begin with forward slash
    cleaned = raw_prefix.strip()
    if not cleaned.startswith("/"):
        return False, None, "Path prefix must begin with '/'"

    # Block query strings or fragments
    if "?" in cleaned or "#" in cleaned:
        return False, None, "Path prefix cannot contain query strings or hash fragments"

    # Block directory traversal sequences: /../ or \..\
    if ".." in cleaned or "\\" in cleaned:
        return False, None, "Path prefix cannot contain directory traversal sequences ('..' or '\\')"

    # Collapse multiple consecutive slashes: e.g. ///api//v1 -> /api/v1
    normalized = re.sub(r"/+", "/", cleaned)
    # Strip trailing slash unless it's root
    if len(normalized) > 1 and normalized.endswith("/"):
        normalized = normalized[:-1]

    return True, normalized, None


def validate_upstream_url(raw_url: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """Validates upstream target URL for protocol, host, port, and CRLF injection."""
    if not raw_url or not isinstance(raw_url, str):
        return False, None, "Upstream URL must be a non-empty string"

    trimmed = raw_url.strip()
    if re.search(r"[\r\n\0]", trimmed):
        return False, None, "Upstream URL contains illegal CRLF or null bytes"

    try:
        parsed = urlparse(trimmed)
        port = parsed.port
    except ValueError as ve:
        return False, None, f"Invalid upstream port: {ve}"
    except Exception as e:
        return False, None, f"Malformed upstream URL: {e}"

    if parsed.scheme not in ("http", "https"):
        return False, None, f"Unsupported upstream protocol '{parsed.scheme}': only http and https allowed"

    if not parsed.hostname:
        return False, None, "Upstream URL missing valid hostname"

    if port is not None:
        if not (1 <= port <= 65535):
            return False, None, f"Port {port} out of range [1, 65535]"

    # Reconstruct normalized URL
    normalized = f"{parsed.scheme}://{parsed.hostname}"
    if port:
        normalized += f":{port}"
    if parsed.path:
        normalized += parsed.path.rstrip("/")

    return True, normalized, None


def validate_and_sanitize_route(spec: Dict[str, Any]) -> Tuple[bool, Optional[SanitizedRoute], List[str]]:
    """Validates a single route specification against the ingress contract."""
    errors: List[str] = []

    if not isinstance(spec, dict):
        return False, None, ["Route specification must be a dictionary"]

    # 1. Route ID
    route_id = spec.get("route_id")
    if not route_id or not isinstance(route_id, str) or not ROUTE_ID_REGEX.match(route_id):
        errors.append(f"Invalid route_id '{route_id}': must match ^[a-zA-Z0-9_-]{{1,64}}$")

    # 2. Path prefix
    prefix_ok, prefix, prefix_err = sanitize_path_prefix(spec.get("prefix", ""))
    if not prefix_ok:
        errors.append(prefix_err)

    # 3. Upstream URL
    upstream_ok, upstream, upstream_err = validate_upstream_url(spec.get("target_upstream", ""))
    if not upstream_ok:
        errors.append(upstream_err)

    # 4. Weight
    weight = spec.get("weight", 100)
    if not isinstance(weight, int) or not (MIN_WEIGHT <= weight <= MAX_WEIGHT):
        errors.append(f"Weight ({weight}) must be integer in [{MIN_WEIGHT}, {MAX_WEIGHT}]")

    # 5. Priority
    priority = spec.get("priority", 100)
    if not isinstance(priority, int) or not (MIN_PRIORITY <= priority <= MAX_PRIORITY):
        errors.append(f"Priority ({priority}) must be integer in [{MIN_PRIORITY}, {MAX_PRIORITY}]")

    # 6. Timeout
    timeout_ms = spec.get("timeout_ms", 5000)
    if not isinstance(timeout_ms, int) or not (MIN_TIMEOUT_MS <= timeout_ms <= MAX_TIMEOUT_MS):
        errors.append(f"Timeout ({timeout_ms}ms) must be integer in [{MIN_TIMEOUT_MS}, {MAX_TIMEOUT_MS}]")

    strip_prefix = bool(spec.get("strip_prefix", False))

    # 7. Retry policy
    raw_retry = spec.get("retry_policy", {})
    retry_policy = RetryPolicy()
    if isinstance(raw_retry, dict):
        if "max_retries" in raw_retry:
            mr = raw_retry["max_retries"]
            if not isinstance(mr, int) or not (0 <= mr <= MAX_RETRIES):
                errors.append(f"max_retries ({mr}) must be integer in [0, {MAX_RETRIES}]")
            else:
                retry_policy.max_retries = mr

        if "backoff_multiplier" in raw_retry:
            bm = raw_retry["backoff_multiplier"]
            if not isinstance(bm, (int, float)) or not (1.0 <= float(bm) <= 5.0):
                errors.append(f"backoff_multiplier ({bm}) must be in [1.0, 5.0]")
            else:
                retry_policy.backoff_multiplier = float(bm)

        if "retryable_status_codes" in raw_retry:
            codes = raw_retry["retryable_status_codes"]
            if not isinstance(codes, list) or not all(isinstance(c, int) and 500 <= c <= 599 for c in codes):
                errors.append("retryable_status_codes must be a list of 5xx HTTP status integers")
            else:
                retry_policy.retryable_status_codes = list(codes)

    # 8. Headers policy
    raw_headers = spec.get("headers_policy", {})
    headers_policy = HeadersPolicy()
    if isinstance(raw_headers, dict):
        add_headers = raw_headers.get("add", {})
        if isinstance(add_headers, dict):
            for hk, hv in add_headers.items():
                if not HEADER_NAME_REGEX.match(str(hk)):
                    errors.append(f"Invalid header name to add: '{hk}'")
                elif re.search(r"[\r\n\0]", str(hv)):
                    errors.append(f"CRLF injection detected in header value for '{hk}'")
                else:
                    headers_policy.add[str(hk).lower()] = str(hv).strip()

        rem_headers = raw_headers.get("remove", [])
        if isinstance(rem_headers, list):
            for hk in rem_headers:
                if not HEADER_NAME_REGEX.match(str(hk)):
                    errors.append(f"Invalid header name to remove: '{hk}'")
                else:
                    headers_policy.remove.append(str(hk).lower())

    if errors:
        return False, None, errors

    sanitized = SanitizedRoute(
        route_id=route_id,
        prefix=prefix,
        target_upstream=upstream,
        weight=weight,
        priority=priority,
        timeout_ms=timeout_ms,
        strip_prefix=strip_prefix,
        retry_policy=retry_policy,
        headers_policy=headers_policy,
    )
    return True, sanitized, []


def validate_route_table(routes: List[Dict[str, Any]]) -> Tuple[bool, List[SanitizedRoute], List[str]]:
    """Validates an entire route table, detecting duplicate IDs and ambiguous prefix collisions."""
    if not isinstance(routes, list):
        return False, [], ["Route table must be a list of route definitions"]

    sanitized_routes: List[SanitizedRoute] = []
    all_errors: List[str] = []
    seen_ids: Set[str] = set()
    prefix_priority_map: Dict[Tuple[str, int], str] = {}

    for i, spec in enumerate(routes):
        ok, sanitized, errs = validate_and_sanitize_route(spec)
        if not ok:
            all_errors.extend([f"Route[{i}]: {e}" for e in errs])
            continue

        # Check duplicate ID
        if sanitized.route_id in seen_ids:
            all_errors.append(f"Duplicate route_id '{sanitized.route_id}' detected at index {i}")
        seen_ids.add(sanitized.route_id)

        # Check collision: identical prefix AND priority creates routing ambiguity
        key = (sanitized.prefix, sanitized.priority)
        if key in prefix_priority_map:
            all_errors.append(
                f"Routing conflict: routes '{prefix_priority_map[key]}' and '{sanitized.route_id}' share prefix '{sanitized.prefix}' with equal priority ({sanitized.priority})"
            )
        else:
            prefix_priority_map[key] = sanitized.route_id

        sanitized_routes.append(sanitized)

    if all_errors:
        return False, [], all_errors

    # Sort descending by priority (higher priority evaluated first)
    sanitized_routes.sort(key=lambda r: r.priority, reverse=True)
    return True, sanitized_routes, []
