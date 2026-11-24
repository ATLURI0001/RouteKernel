"""
BGP AS-Path Loop Mitigation & Routing Table Poisoning Defense.

Implements RFC 4271 §9.2 AS-Path loop detection, AS-Path prepending stuffing defense,
Bogon/Reserved ASN filtering, private ASN leakage mitigation, and routing table poisoning quarantine.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class ASPathViolationCode(str, Enum):
    LOOP_DETECTED = "ERR_AS_PATH_LOOP"
    MAX_LENGTH_EXCEEDED = "ERR_AS_PATH_OVERLENGTH"
    EXCESSIVE_PREPENDING = "ERR_EXCESSIVE_PREPENDING"
    BOGON_ASN = "ERR_BOGON_OR_RESERVED_ASN"
    PRIVATE_ASN_LEAK = "ERR_PRIVATE_ASN_LEAK"
    MALFORMED_PATH = "ERR_MALFORMED_AS_PATH"


class ASPathStatus(str, Enum):
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"


# RFC 6996 & RFC 7300 Private and Reserved ASNs
RESERVED_BOGON_ASNS: Set[int] = {
    0,          # RFC 7607 Reserved by IANA
    23456,      # RFC 4893 AS_TRANS
    65535,      # RFC 7300 Reserved
    4294967295, # RFC 7300 Reserved 32-bit max
}


def is_private_asn(asn: int) -> bool:
    """Checks whether an ASN falls within RFC 6996 designated private ranges."""
    return (64512 <= asn <= 65534) or (4200000000 <= asn <= 4294967294)


def is_bogon_or_reserved_asn(asn: int) -> bool:
    """Checks whether an ASN is reserved, unallocated, or prohibited from public routing."""
    if asn in RESERVED_BOGON_ASNS:
        return True
    if asn < 0 or asn > 4294967295:
        return True
    # RFC 6598 / RFC 5398 documentation ASNs
    if 64496 <= asn <= 64511 or 65536 <= asn <= 65551:
        return True
    return False


@dataclass(frozen=True)
class ASPathVerdict:
    status: ASPathStatus
    prefix: str
    as_path: List[int]
    peer_asn: int
    violation_code: Optional[ASPathViolationCode] = None
    violating_asn: Optional[int] = None
    reason: str = "Route AS-Path satisfies all defensive invariants"


@dataclass(frozen=True)
class QuarantinedRoute:
    prefix: str
    as_path: List[int]
    peer_asn: int
    verdict: ASPathVerdict
    quarantined_at: float = field(default_factory=time.time)


class ASPathLoopGuard:
    """
    Defensive BGP AS-Path analyzer protecting FIB and RIB from poisoning, loops,
    and memory exhaustion via path stuffing.
    """

    def __init__(
        self,
        local_asn: int,
        max_path_length: int = 32,
        max_prepending: int = 10,
        allow_private_asn: bool = False,
        quarantine_capacity: int = 500,
    ) -> None:
        if not isinstance(local_asn, int) or local_asn <= 0 or local_asn > 4294967295:
            raise ValueError(f"local_asn must be a valid 16-bit or 32-bit ASN, got {local_asn}")
        self.local_asn = local_asn
        self.max_path_length = max_path_length
        self.max_prepending = max_prepending
        self.allow_private_asn = allow_private_asn
        self.quarantine_capacity = quarantine_capacity

        self._quarantined_routes: List[QuarantinedRoute] = []
        self._stats: Dict[str, int] = {
            "total_evaluated": 0,
            "total_accepted": 0,
            "total_rejected": 0,
            ASPathViolationCode.LOOP_DETECTED.value: 0,
            ASPathViolationCode.MAX_LENGTH_EXCEEDED.value: 0,
            ASPathViolationCode.EXCESSIVE_PREPENDING.value: 0,
            ASPathViolationCode.BOGON_ASN.value: 0,
            ASPathViolationCode.PRIVATE_ASN_LEAK.value: 0,
            ASPathViolationCode.MALFORMED_PATH.value: 0,
        }

    def evaluate_route(self, prefix: str, as_path: List[int], peer_asn: int) -> ASPathVerdict:
        """
        Validates an incoming BGP route advertisement's AS-Path against defensive criteria.
        """
        self._stats["total_evaluated"] += 1

        # 1. Malformed path validation
        if not isinstance(as_path, list) or len(as_path) == 0:
            return self._reject(
                prefix, as_path, peer_asn,
                ASPathViolationCode.MALFORMED_PATH, None,
                "AS-Path must be a non-empty list of integers",
            )

        for asn in as_path:
            if not isinstance(asn, int):
                return self._reject(
                    prefix, as_path, peer_asn,
                    ASPathViolationCode.MALFORMED_PATH, None,
                    f"Malformed non-integer ASN in path: {asn}",
                )

        # 2. RFC 4271 §9.2 AS-Path loop detection (Local ASN in path)
        if self.local_asn in as_path:
            return self._reject(
                prefix, as_path, peer_asn,
                ASPathViolationCode.LOOP_DETECTED, self.local_asn,
                f"Loop detected: local ASN {self.local_asn} present in AS-Path {as_path}",
            )

        # 3. Path length bounding (Defense against memory exhaustion / stuffing)
        if len(as_path) > self.max_path_length:
            return self._reject(
                prefix, as_path, peer_asn,
                ASPathViolationCode.MAX_LENGTH_EXCEEDED, as_path[0],
                f"AS-Path length {len(as_path)} exceeds defensive limit of {self.max_path_length}",
            )

        # 4. Bogon / Reserved ASN detection
        for asn in as_path:
            if is_bogon_or_reserved_asn(asn):
                return self._reject(
                    prefix, as_path, peer_asn,
                    ASPathViolationCode.BOGON_ASN, asn,
                    f"AS-Path contains bogon or reserved ASN {asn}",
                )

        # 5. Private ASN leakage defense (on public eBGP sessions)
        if not self.allow_private_asn:
            for asn in as_path:
                if is_private_asn(asn):
                    return self._reject(
                        prefix, as_path, peer_asn,
                        ASPathViolationCode.PRIVATE_ASN_LEAK, asn,
                        f"AS-Path leaks RFC 6996 private ASN {asn} into public routing domain",
                    )

        # 6. Excessive AS-Path prepending mitigation
        current_asn: Optional[int] = None
        consecutive_count = 0
        for asn in as_path:
            if asn == current_asn:
                consecutive_count += 1
                if consecutive_count > self.max_prepending:
                    return self._reject(
                        prefix, as_path, peer_asn,
                        ASPathViolationCode.EXCESSIVE_PREPENDING, asn,
                        f"Excessive AS prepending detected: ASN {asn} repeated {consecutive_count} times (> {self.max_prepending})",
                    )
            else:
                current_asn = asn
                consecutive_count = 1

        # Route is verified and safe
        self._stats["total_accepted"] += 1
        return ASPathVerdict(
            status=ASPathStatus.ACCEPTED,
            prefix=prefix,
            as_path=as_path,
            peer_asn=peer_asn,
        )

    def _reject(
        self,
        prefix: str,
        as_path: List[int],
        peer_asn: int,
        code: ASPathViolationCode,
        violating_asn: Optional[int],
        reason: str,
    ) -> ASPathVerdict:
        self._stats["total_rejected"] += 1
        self._stats[code.value] += 1

        verdict = ASPathVerdict(
            status=ASPathStatus.REJECTED,
            prefix=prefix,
            as_path=as_path if isinstance(as_path, list) else [],
            peer_asn=peer_asn,
            violation_code=code,
            violating_asn=violating_asn,
            reason=reason,
        )

        quarantined = QuarantinedRoute(
            prefix=prefix,
            as_path=as_path if isinstance(as_path, list) else [],
            peer_asn=peer_asn,
            verdict=verdict,
        )
        self._quarantined_routes.append(quarantined)
        if len(self._quarantined_routes) > self.quarantine_capacity:
            self._quarantined_routes.pop(0)

        return verdict

    def get_quarantined_routes(self) -> List[QuarantinedRoute]:
        return list(self._quarantined_routes)

    def clear_quarantine(self) -> None:
        self._quarantined_routes.clear()

    def get_telemetry_summary(self) -> Dict[str, Any]:
        return {
            "local_asn": self.local_asn,
            "quarantined_count": len(self._quarantined_routes),
            "stats": dict(self._stats),
        }
