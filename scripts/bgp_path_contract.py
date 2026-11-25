"""
BGP Route Announcement Policy & AS-Path Loop Boundary Contract.

Enforces schema validation, AS-path length constraints, cycle/loop detection,
consecutive prepending limits, community attribute formatting, and schema evolution
for ingress/egress BGP route propagation in RouteKernel.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


class BGPPathContractError(Exception):
    """Raised when a route announcement policy violates BGP contract invariants."""
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message


SUPPORTED_VERSIONS: Set[str] = {"routekernel/path-v1", "routekernel/path-v2"}
VALID_ORIGINS: Set[str] = {"IGP", "EGP", "INCOMPLETE"}
COMMUNITY_STANDARD_REGEX = re.compile(r"^(\d{1,5}):(\d{1,5})$")
COMMUNITY_LARGE_REGEX = re.compile(r"^(\d{1,10}):(\d{1,10}):(\d{1,10})$")

MAX_DEFAULT_AS_PATH_LEN = 32
MAX_PREPEND_RUN_LEN = 10

# BGP well-known communities (RFC 1997)
WELL_KNOWN_COMMUNITIES = {
    "NO_EXPORT": "65535:65281",
    "NO_ADVERTISE": "65535:65282",
    "NO_EXPORT_SUBCONFED": "65535:65283",
}


def is_valid_asn(asn: int) -> bool:
    """Validates Autonomous System Number within standard 16-bit and 32-bit ranges."""
    if not isinstance(asn, int) or isinstance(asn, bool):
        return False
    if asn < 1 or asn > 4294967294:
        return False
    if asn == 23456:  # AS_TRANS (RFC 4893) prohibited as operational origin
        return False
    return True


def detect_as_loop(as_path: List[int]) -> Tuple[bool, Optional[int]]:
    """
    Detects whether an AS path contains any cyclic loops.
    Consecutive duplicate ASNs represent legitimate AS-path prepending.
    Non-consecutive recurring ASNs constitute illegal routing loops.
    """
    seen_asns: Set[int] = set()
    prev_asn: Optional[int] = None

    for asn in as_path:
        if asn != prev_asn:
            if asn in seen_asns:
                return True, asn
            seen_asns.add(asn)
            prev_asn = asn
    return False, None


def validate_community_string(comm: str) -> str:
    """Validates and normalizes standard or large BGP community strings."""
    if not isinstance(comm, str):
        raise BGPPathContractError("INVALID_COMMUNITY", f"Community must be a string, got {type(comm)}")
    
    comm_upper = comm.strip().upper()
    if comm_upper in WELL_KNOWN_COMMUNITIES:
        return WELL_KNOWN_COMMUNITIES[comm_upper]

    comm_clean = comm.strip()
    if COMMUNITY_STANDARD_REGEX.match(comm_clean):
        parts = [int(p) for p in comm_clean.split(":")]
        if all(0 <= p <= 65535 for p in parts):
            return comm_clean
        raise BGPPathContractError("INVALID_COMMUNITY", f"Standard community out of 16-bit range: {comm_clean}")

    if COMMUNITY_LARGE_REGEX.match(comm_clean):
        parts = [int(p) for p in comm_clean.split(":")]
        if all(0 <= p <= 4294967295 for p in parts):
            return comm_clean
        raise BGPPathContractError("INVALID_COMMUNITY", f"Large community out of 32-bit range: {comm_clean}")

    raise BGPPathContractError("INVALID_COMMUNITY", f"Malformed community format: {comm}")


def migrate_bgp_path_schema(raw_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Migrates legacy v1 schemas to modern v2 format.
    Handles legacy keys:
      - 'asPath' -> 'as_path'
      - 'localPref' -> 'local_preference'
      - 'nextHop' -> 'next_hop'
    """
    if not isinstance(raw_dict, dict):
        raise BGPPathContractError("INVALID_PAYLOAD", "Payload must be a dictionary")

    migrated = dict(raw_dict)
    version = migrated.get("version", "routekernel/path-v1")
    if version not in SUPPORTED_VERSIONS:
        raise BGPPathContractError("UNSUPPORTED_VERSION", f"Version '{version}' is not supported")

    if version == "routekernel/path-v1":
        if "asPath" in migrated and "as_path" not in migrated:
            migrated["as_path"] = migrated.pop("asPath")
        if "localPref" in migrated and "local_preference" not in migrated:
            migrated["local_preference"] = migrated.pop("localPref")
        if "nextHop" in migrated and "next_hop" not in migrated:
            migrated["next_hop"] = migrated.pop("nextHop")
        migrated["version"] = "routekernel/path-v2"

    return migrated


@dataclass
class BGPPathAnnouncementSpec:
    version: str
    prefix: str
    normalized_prefix: str
    origin: str
    as_path: List[int]
    next_hop: str
    med: int = 0
    local_preference: int = 100
    communities: List[str] = field(default_factory=list)
    enforce_strict_loop_check: bool = True
    max_path_length: int = MAX_DEFAULT_AS_PATH_LEN

    @property
    def origin_asn(self) -> int:
        return self.as_path[-1]

    @property
    def peer_asn(self) -> int:
        return self.as_path[0]

    @property
    def prepend_count(self) -> int:
        """Returns the number of synthetic prepended ASNs (total length minus distinct segments)."""
        if not self.as_path:
            return 0
        distinct_runs = 1
        for i in range(1, len(self.as_path)):
            if self.as_path[i] != self.as_path[i - 1]:
                distinct_runs += 1
        return len(self.as_path) - distinct_runs

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "prefix": self.normalized_prefix,
            "origin": self.origin,
            "as_path": list(self.as_path),
            "next_hop": self.next_hop,
            "med": self.med,
            "local_preference": self.local_preference,
            "communities": list(self.communities),
            "origin_asn": self.origin_asn,
            "peer_asn": self.peer_asn,
            "prepend_count": self.prepend_count,
        }


def validate_and_sanitize_path_announcement(
    raw_payload: Dict[str, Any],
    max_path_length: int = MAX_DEFAULT_AS_PATH_LEN,
    disallowed_asns: Optional[Set[int]] = None,
) -> BGPPathAnnouncementSpec:
    """
    Validates, sanitizes, and normalizes a BGP route announcement policy specification.
    """
    payload = migrate_bgp_path_schema(raw_payload)

    version = payload.get("version", "routekernel/path-v2")
    if version not in SUPPORTED_VERSIONS:
        raise BGPPathContractError("UNSUPPORTED_VERSION", f"Invalid schema version: {version}")

    raw_prefix = payload.get("prefix")
    if not raw_prefix or not isinstance(raw_prefix, str):
        raise BGPPathContractError("MISSING_PREFIX", "Announcement missing valid prefix string")

    try:
        net = ipaddress.ip_network(raw_prefix.strip(), strict=False)
        normalized_prefix = str(net)
    except ValueError as e:
        raise BGPPathContractError("INVALID_PREFIX", f"Invalid IP network prefix: {raw_prefix} ({e})")

    origin = str(payload.get("origin", "IGP")).strip().upper()
    if origin not in VALID_ORIGINS:
        raise BGPPathContractError("INVALID_ORIGIN", f"Origin '{origin}' not in {sorted(VALID_ORIGINS)}")

    raw_as_path = payload.get("as_path")
    if not isinstance(raw_as_path, list) or len(raw_as_path) == 0:
        raise BGPPathContractError("EMPTY_AS_PATH", "AS path must be a non-empty list of ASNs")

    if len(raw_as_path) > max_path_length:
        raise BGPPathContractError(
            "AS_PATH_OVERFLOW",
            f"AS path length {len(raw_as_path)} exceeds allowed maximum of {max_path_length}",
        )

    validated_as_path: List[int] = []
    consecutive_run = 1
    prev_asn = None

    for asn in raw_as_path:
        if not is_valid_asn(asn):
            raise BGPPathContractError("INVALID_ASN", f"Invalid ASN value in path: {asn}")
        if disallowed_asns and asn in disallowed_asns:
            raise BGPPathContractError("DISALLOWED_ASN", f"ASN {asn} is explicitly barred by policy")

        if prev_asn is not None and asn == prev_asn:
            consecutive_run += 1
            if consecutive_run > MAX_PREPEND_RUN_LEN:
                raise BGPPathContractError(
                    "PREPEND_LIMIT_EXCEEDED",
                    f"ASN {asn} prepended {consecutive_run} times, exceeding limit of {MAX_PREPEND_RUN_LEN}",
                )
        else:
            consecutive_run = 1
            prev_asn = asn

        validated_as_path.append(asn)

    # Loop detection
    has_loop, looping_asn = detect_as_loop(validated_as_path)
    if has_loop:
        raise BGPPathContractError("AS_LOOP_DETECTED", f"Routing cycle detected on ASN {looping_asn}")

    # Next-hop address validation
    raw_next_hop = payload.get("next_hop")
    if not raw_next_hop or not isinstance(raw_next_hop, str):
        raise BGPPathContractError("MISSING_NEXT_HOP", "Announcement must specify next_hop address")

    try:
        nh_ip = ipaddress.ip_address(raw_next_hop.strip())
        normalized_next_hop = str(nh_ip)
        if nh_ip.version != net.version:
            raise BGPPathContractError(
                "ADDRESS_FAMILY_MISMATCH",
                f"Prefix family IPv{net.version} does not match next-hop IPv{nh_ip.version}",
            )
    except ValueError as e:
        raise BGPPathContractError("INVALID_NEXT_HOP", f"Malformed next-hop address: {raw_next_hop} ({e})")

    # MED & Local Preference bounds
    med = payload.get("med", 0)
    if not isinstance(med, int) or med < 0 or med > 4294967295:
        raise BGPPathContractError("INVALID_MED", f"MED must be uint32 [0, 4294967295], got {med}")

    local_preference = payload.get("local_preference", 100)
    if not isinstance(local_preference, int) or local_preference < 0 or local_preference > 4294967295:
        raise BGPPathContractError(
            "INVALID_LOCAL_PREF",
            f"Local preference must be uint32 [0, 4294967295], got {local_preference}",
        )

    # Communities validation
    raw_communities = payload.get("communities", [])
    if not isinstance(raw_communities, list):
        raise BGPPathContractError("INVALID_COMMUNITY_LIST", "Communities must be a list of strings")

    sanitized_communities: List[str] = []
    seen_communities: Set[str] = set()
    for comm in raw_communities:
        validated_comm = validate_community_string(comm)
        if validated_comm not in seen_communities:
            seen_communities.add(validated_comm)
            sanitized_communities.append(validated_comm)

    return BGPPathAnnouncementSpec(
        version=version,
        prefix=raw_prefix,
        normalized_prefix=normalized_prefix,
        origin=origin,
        as_path=validated_as_path,
        next_hop=normalized_next_hop,
        med=med,
        local_preference=local_preference,
        communities=sanitized_communities,
        max_path_length=max_path_length,
    )
