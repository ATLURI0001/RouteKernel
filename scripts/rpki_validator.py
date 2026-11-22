"""
RouteKernel - BGP Prefix Hijack Detection & RPKI ROA Validation Engine

Implements RFC 6811 BGP Prefix Origin Validation (ROA state machines), sub-prefix
hijack identification, autonomous system path (AS-Path) sanitization, and route leak
detection across IPv4 and IPv6 routing table feeds.
"""

from __future__ import annotations

import enum
import ipaddress
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


class RPKIStatus(str, enum.Enum):
    VALID = "VALID"
    INVALID_ASN = "INVALID_ASN"
    INVALID_LENGTH = "INVALID_LENGTH"
    NOT_FOUND = "NOT_FOUND"


@dataclass(frozen=True)
class ROARecord:
    prefix: str
    max_length: int
    asn: int

    def __post_init__(self):
        network = ipaddress.ip_network(self.prefix, strict=True)
        if self.max_length < network.prefixlen:
            raise ValueError(f"max_length ({self.max_length}) cannot be less than prefix length ({network.prefixlen})")
        if self.max_length > network.max_prefixlen:
            raise ValueError(f"max_length ({self.max_length}) exceeds IP family max ({network.max_prefixlen})")
        if not (0 < self.asn <= 4294967295):
            raise ValueError(f"ASN {self.asn} outside valid 32-bit range")


@dataclass
class ValidationResult:
    status: RPKIStatus
    matched_roas: List[ROARecord] = field(default_factory=list)
    reason: str = ""
    is_hijack_risk: bool = False


class RPKIRouteValidator:
    """RFC 6811 Route Origin Authorization validator and BGP hijack detector."""

    # RFC 6996 / RFC 5398 Reserved & Private ASNs
    RESERVED_PRIVATE_ASNS: Set[int] = {
        0, 23456, 64496, 64511, 65535,
    }

    def __init__(self) -> None:
        self._lock = threading.RWMutex() if hasattr(threading, "RWMutex") else threading.RLock()
        self._roas: List[Tuple[ipaddress._BaseNetwork, ROARecord]] = []
        self._telemetry = {
            "total_validated": 0,
            "valid_count": 0,
            "invalid_asn_count": 0,
            "invalid_length_count": 0,
            "not_found_count": 0,
            "hijacks_flagged": 0,
        }

    def add_roa(self, prefix: str, max_length: int, asn: int) -> None:
        """Registers a signed ROA record into the validation table."""
        record = ROARecord(prefix=prefix, max_length=max_length, asn=asn)
        net = ipaddress.ip_network(prefix, strict=True)
        with self._lock:
            self._roas.append((net, record))

    def bulk_load_roas(self, roas: List[Dict[str, Any]]) -> int:
        """Loads a list of dictionary ROA definitions."""
        loaded = 0
        for r in roas:
            self.add_roa(
                prefix=r["prefix"],
                max_length=int(r["max_length"]),
                asn=int(r["asn"]),
            )
            loaded += 1
        return loaded

    def validate_announcement(self, announced_prefix: str, origin_asn: int) -> ValidationResult:
        """Validates a BGP route announcement against active ROA records according to RFC 6811."""
        ann_net = ipaddress.ip_network(announced_prefix, strict=True)
        matching_roas: List[ROARecord] = []

        with self._lock:
            self._telemetry["total_validated"] += 1
            for roa_net, roa in self._roas:
                # Subnet containment: announced prefix must be within ROA network
                if ann_net.subnet_of(roa_net):
                    matching_roas.append(roa)

        if not matching_roas:
            with self._lock:
                self._telemetry["not_found_count"] += 1
            return ValidationResult(
                status=RPKIStatus.NOT_FOUND,
                reason="No covering ROA found for announced prefix",
                is_hijack_risk=False,
            )

        # RFC 6811 validation rule:
        # A route is VALID if AT LEAST ONE covering ROA matches both ASN and prefix length <= max_length
        for roa in matching_roas:
            if roa.asn == origin_asn and ann_net.prefixlen <= roa.max_length:
                with self._lock:
                    self._telemetry["valid_count"] += 1
                return ValidationResult(
                    status=RPKIStatus.VALID,
                    matched_roas=matching_roas,
                    reason=f"Covering ROA matches ASN {origin_asn} and length {ann_net.prefixlen} <= {roa.max_length}",
                    is_hijack_risk=False,
                )

        # If we reach here, ROAs cover the prefix, but none produced VALID.
        # Check if length breach occurred on matching ASN
        asn_matched_but_length_exceeded = any(
            roa.asn == origin_asn and ann_net.prefixlen > roa.max_length
            for roa in matching_roas
        )

        with self._lock:
            self._telemetry["hijacks_flagged"] += 1

        if asn_matched_but_length_exceeded:
            with self._lock:
                self._telemetry["invalid_length_count"] += 1
            return ValidationResult(
                status=RPKIStatus.INVALID_LENGTH,
                matched_roas=matching_roas,
                reason=f"Announced length /{ann_net.prefixlen} exceeds ROA max_length constraint",
                is_hijack_risk=True,
            )

        with self._lock:
            self._telemetry["invalid_asn_count"] += 1
        return ValidationResult(
            status=RPKIStatus.INVALID_ASN,
            matched_roas=matching_roas,
            reason=f"Origin ASN {origin_asn} does not match any covering ROA authorized ASN",
            is_hijack_risk=True,
        )

    def analyze_as_path(self, as_path: List[int]) -> Dict[str, Any]:
        """Audits BGP AS-Path for route leaks, loops, and private ASN leaks."""
        if not as_path:
            return {"valid": False, "reason": "Empty AS-Path"}

        # Loop detection
        seen = set()
        for asn in as_path:
            if asn in seen:
                return {
                    "valid": False,
                    "reason": f"Routing loop detected: ASN {asn} appears multiple times in path",
                    "loop_asn": asn,
                }
            seen.add(asn)

        # Private ASN in public route leak check
        private_leaks = [asn for asn in as_path if 64512 <= asn <= 65534 or 4200000000 <= asn <= 4294967294]
        if private_leaks:
            return {
                "valid": False,
                "reason": f"Private ASN leak detected in public path: {private_leaks}",
                "private_asns": private_leaks,
            }

        return {"valid": True, "hop_count": len(as_path), "origin_asn": as_path[-1]}

    def get_telemetry(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._telemetry)

    def clear(self) -> None:
        with self._lock:
            self._roas.clear()
            for k in self._telemetry:
                self._telemetry[k] = 0
