"""
BGP Peer Session Ingress Contract & Route Policy Sanitizer.

Enforces ASN validity, peer IP address formatting, hold-time/keepalive invariants,
bogon prefix filtering, max-prefix bounds, and MD5 authentication security.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


class BGPSessionContractError(Exception):
    """Raised when a BGP session specification violates contract invariants."""
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message


SUPPORTED_VERSIONS: Set[str] = {"routekernel/v1", "routekernel/v2"}
ALLOWED_PEER_TYPES: Set[str] = {"ebgp", "ibgp"}
SESSION_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]{3,64}$")

# Bogon / Martian network prefixes prohibited in public eBGP advertisement filters
BOGON_V4_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),   # Multicast
    ipaddress.ip_network("240.0.0.0/4"),   # Reserved
]


def is_valid_asn(asn: int, allow_private: bool = True) -> bool:
    """Validates Autonomous System Number (16-bit and 32-bit boundaries)."""
    if not isinstance(asn, int) or asn < 1 or asn > 4294967294:
        return False
    if asn == 23456:
        # RFC 4893 AS_TRANS reserved for transitioning
        return False
    if not allow_private:
        # RFC 6996 private 16-bit: 64512-65534, 32-bit: 4200000000-4294967294
        if 64512 <= asn <= 65534 or 4200000000 <= asn <= 4294967294:
            return False
    return True


@dataclass
class BGPSessionSpec:
    version: str
    session_id: str
    peer_asn: int
    local_asn: int
    peer_ip: str
    peer_type: str
    hold_time_sec: int
    keepalive_sec: int
    max_prefixes: int
    enable_md5_auth: bool
    md5_secret_hash: str
    allowed_prefix_filters: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


def validate_and_sanitize_bgp_session(
    raw_spec: Dict[str, Any],
    options: Optional[Dict[str, Any]] = None,
) -> BGPSessionSpec:
    """Validates and normalizes an inbound BGP peer session specification."""
    opts = options or {}
    allow_private_asn = opts.get("allow_private_asn", True)
    allow_bogons = opts.get("allow_bogons", False)
    max_prefix_ceiling = opts.get("max_prefix_ceiling", 500000)

    if not isinstance(raw_spec, dict):
        raise BGPSessionContractError("ERR_INVALID_SCHEMA", "BGP session manifest must be a non-null dictionary")

    # 1. Version enforcement
    version = raw_spec.get("version", "routekernel/v1")
    if not isinstance(version, str) or version not in SUPPORTED_VERSIONS:
        raise BGPSessionContractError(
            "ERR_INVALID_VERSION",
            f"Unsupported BGP session schema version '{version}'. Allowed: {sorted(list(SUPPORTED_VERSIONS))}",
        )

    # 2. Session ID validation
    session_id = str(raw_spec.get("session_id", "")).strip()
    if not SESSION_ID_REGEX.match(session_id):
        raise BGPSessionContractError(
            "ERR_INVALID_SESSION_ID",
            f"Invalid session_id '{session_id}'. Must be 3-64 alphanumeric chars, dots, dashes, or underscores.",
        )

    # 3. ASN Validation (Peer and Local)
    try:
        peer_asn = int(raw_spec.get("peer_asn", 0))
        local_asn = int(raw_spec.get("local_asn", 0))
    except (TypeError, ValueError):
        raise BGPSessionContractError("ERR_INVALID_ASN", "peer_asn and local_asn must be valid integers")

    if not is_valid_asn(peer_asn, allow_private=allow_private_asn):
        raise BGPSessionContractError("ERR_INVALID_ASN", f"peer_asn {peer_asn} is outside permitted ASN ranges")
    if not is_valid_asn(local_asn, allow_private=allow_private_asn):
        raise BGPSessionContractError("ERR_INVALID_ASN", f"local_asn {local_asn} is outside permitted ASN ranges")

    # 4. Peer type & ASN relationship
    peer_type = str(raw_spec.get("peer_type", "")).strip().lower()
    if peer_type not in ALLOWED_PEER_TYPES:
        peer_type = "ibgp" if peer_asn == local_asn else "ebgp"

    if peer_type == "ibgp" and peer_asn != local_asn:
        raise BGPSessionContractError("ERR_PEER_TYPE_MISMATCH", "iBGP session requires peer_asn == local_asn")
    if peer_type == "ebgp" and peer_asn == local_asn:
        raise BGPSessionContractError("ERR_PEER_TYPE_MISMATCH", "eBGP session requires peer_asn != local_asn")

    # 5. Peer IP address validation
    peer_ip_str = str(raw_spec.get("peer_ip", "")).strip()
    try:
        parsed_ip = ipaddress.ip_address(peer_ip_str)
    except ValueError:
        raise BGPSessionContractError("ERR_INVALID_PEER_IP", f"Malformed peer_ip '{peer_ip_str}'")

    if parsed_ip.is_loopback:
        raise BGPSessionContractError("ERR_INVALID_PEER_IP", "Peer IP cannot be a loopback address")
    if parsed_ip.is_multicast or parsed_ip.is_unspecified:
        raise BGPSessionContractError("ERR_INVALID_PEER_IP", "Peer IP cannot be multicast or unspecified (0.0.0.0)")

    # 6. Timer invariants (hold_time and keepalive)
    hold_time = int(raw_spec.get("hold_time_sec", 90))
    if hold_time != 0 and (hold_time < 3 or hold_time > 65535):
        raise BGPSessionContractError("ERR_INVALID_TIMERS", "hold_time_sec must be 0 (disabled) or between 3 and 65535")

    keepalive = int(raw_spec.get("keepalive_sec", hold_time // 3 if hold_time > 0 else 0))
    if hold_time > 0:
        if keepalive <= 0 or keepalive > hold_time // 3:
            raise BGPSessionContractError(
                "ERR_INVALID_TIMERS",
                f"keepalive_sec ({keepalive}) must be positive and <= hold_time_sec / 3 ({hold_time // 3})",
            )

    # 7. Max prefixes safety ceiling
    max_prefixes = int(raw_spec.get("max_prefixes", 10000))
    if max_prefixes < 1 or max_prefixes > max_prefix_ceiling:
        raise BGPSessionContractError(
            "ERR_BOUNDARY_EXCEEDED",
            f"max_prefixes ({max_prefixes}) must be between 1 and {max_prefix_ceiling}",
        )

    # 8. MD5 authentication
    raw_password = raw_spec.get("md5_password")
    enable_md5 = bool(raw_spec.get("enable_md5_auth", bool(raw_password)))
    md5_hash = ""
    if enable_md5:
        if not raw_password or not isinstance(raw_password, str) or len(raw_password) < 8:
            raise BGPSessionContractError(
                "ERR_AUTH_HARDENING",
                "MD5 authentication enabled but password is missing or shorter than 8 characters",
            )
        if any(c in raw_password for c in ["\r", "\n", "\x00"]):
            raise BGPSessionContractError("ERR_AUTH_HARDENING", "MD5 password contains illegal control characters")
        md5_hash = hashlib.sha256(raw_password.encode("utf-8")).hexdigest()

    # 9. Allowed prefix filters & bogon scrubbing
    raw_filters = raw_spec.get("allowed_prefix_filters", [])
    sanitized_filters: List[str] = []
    if isinstance(raw_filters, list):
        for prefix in raw_filters:
            prefix_str = str(prefix).strip()
            try:
                net = ipaddress.ip_network(prefix_str, strict=True)
            except ValueError:
                raise BGPSessionContractError("ERR_MALFORMED_PREFIX", f"Invalid CIDR prefix filter '{prefix_str}'")

            if not allow_bogons and isinstance(net, ipaddress.IPv4Network):
                for bogon in BOGON_V4_NETWORKS:
                    if net.subnet_of(bogon) or bogon.subnet_of(net):
                        raise BGPSessionContractError(
                            "ERR_BOGON_PREFIX",
                            f"Prefix filter '{prefix_str}' overlaps with bogon/private network {bogon}",
                        )

            sanitized_filters.append(str(net))

    return BGPSessionSpec(
        version=version,
        session_id=session_id,
        peer_asn=peer_asn,
        local_asn=local_asn,
        peer_ip=str(parsed_ip),
        peer_type=peer_type,
        hold_time_sec=hold_time,
        keepalive_sec=keepalive,
        max_prefixes=max_prefixes,
        enable_md5_auth=enable_md5,
        md5_secret_hash=md5_hash,
        allowed_prefix_filters=sanitized_filters,
        metadata=raw_spec.get("metadata", {}),
    )
