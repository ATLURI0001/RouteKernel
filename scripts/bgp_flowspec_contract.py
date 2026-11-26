"""
BGP Flow Specification (Flowspec RFC 8955 / RFC 8956) Policy & Traffic Action Contract.

Enforces strict schema validation, match-condition boundaries, traffic action semantics,
and TCAM capacity guards for distributed denial-of-service (DDoS) mitigation and traffic
filtering rules propagated via BGP Flowspec.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


class FlowspecContractError(Exception):
    """Raised when a flowspec rule violates protocol schema or invariant boundaries."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message


SUPPORTED_SCHEMAS: Set[str] = {"flowspec/v1", "flowspec/v2"}
VALID_ACTIONS: Set[str] = {"DISCARD", "RATE_LIMIT", "REDIRECT_VRF", "MARK_DSCP"}

NAMED_PROTOCOLS: Dict[str, int] = {
    "icmp": 1,
    "tcp": 6,
    "udp": 17,
    "gre": 47,
    "esp": 50,
    "ah": 51,
    "sctp": 132,
}

VALID_PORT_OPERATORS: Set[str] = {"==", "!=", "<", "<=", ">", ">="}
ROUTE_TARGET_REGEX = re.compile(r"^(\d{1,10}):(\d{1,10})$")
MAX_ALLOWED_MATCH_LENGTH = 1500
MAX_RULES_PER_BATCH = 1000


@dataclass(frozen=True)
class PortCondition:
    operator: str
    port: int

    def matches(self, target_port: int) -> bool:
        if self.operator == "==":
            return target_port == self.port
        if self.operator == "!=":
            return target_port != self.port
        if self.operator == "<":
            return target_port < self.port
        if self.operator == "<=":
            return target_port <= self.port
        if self.operator == ">":
            return target_port > self.port
        if self.operator == ">=":
            return target_port >= self.port
        return False


@dataclass
class FlowspecRule:
    rule_id: str
    schema_version: str
    action_type: str
    destination_prefix: Optional[str] = None
    source_prefix: Optional[str] = None
    ip_protocols: List[int] = field(default_factory=list)
    destination_ports: List[PortCondition] = field(default_factory=list)
    source_ports: List[PortCondition] = field(default_factory=list)
    packet_lengths: List[int] = field(default_factory=list)
    rate_limit_bps: float = 0.0
    redirect_target: Optional[str] = None
    dscp_mark: Optional[int] = None


@dataclass
class FlowspecValidationResult:
    is_valid: bool
    rule_id: str
    schema_version: str
    violations: List[str] = field(default_factory=list)
    normalized_rule: Optional[FlowspecRule] = None


class FlowspecContractValidator:
    """
    Validates, normalizes, and verifies invariant adherence for BGP Flowspec rules.
    """

    def __init__(self, max_batch_size: int = MAX_RULES_PER_BATCH) -> None:
        self.max_batch_size = max_batch_size

    def validate_rule(self, raw: Dict[str, Any]) -> FlowspecValidationResult:
        if not isinstance(raw, dict):
            return FlowspecValidationResult(
                is_valid=False,
                rule_id="unknown",
                schema_version="invalid",
                violations=["Payload must be a dictionary object"],
            )

        violations: List[str] = []
        rule_id = str(raw.get("rule_id", "")).strip()
        if not rule_id:
            violations.append("Missing required 'rule_id'")

        schema = str(raw.get("schema_version", "")).strip()
        if schema not in SUPPORTED_SCHEMAS:
            violations.append(
                f"Unsupported schema_version '{schema}'; expected one of {sorted(SUPPORTED_SCHEMAS)}"
            )

        # Match prefixes
        dest_prefix = raw.get("destination_prefix")
        src_prefix = raw.get("source_prefix")

        if not dest_prefix and not src_prefix:
            violations.append(
                "Invariant violation: At least one of 'destination_prefix' or 'source_prefix' must be specified"
            )

        norm_dest: Optional[str] = None
        if dest_prefix is not None:
            try:
                net = ipaddress.ip_network(str(dest_prefix).strip(), strict=False)
                norm_dest = str(net)
            except ValueError as err:
                violations.append(f"Invalid destination_prefix '{dest_prefix}': {err}")

        norm_src: Optional[str] = None
        if src_prefix is not None:
            try:
                net = ipaddress.ip_network(str(src_prefix).strip(), strict=False)
                norm_src = str(net)
            except ValueError as err:
                violations.append(f"Invalid source_prefix '{src_prefix}': {err}")

        # Check IP version matching
        if norm_dest and norm_src:
            dest_ver = ipaddress.ip_network(norm_dest).version
            src_ver = ipaddress.ip_network(norm_src).version
            if dest_ver != src_ver:
                violations.append(
                    f"Address family mismatch: destination is IPv{dest_ver} but source is IPv{src_ver}"
                )

        # Protocols
        protocols: List[int] = []
        raw_protocols = raw.get("ip_protocols", [])
        if not isinstance(raw_protocols, list):
            violations.append("'ip_protocols' must be a list of integers or protocol names")
        else:
            for p in raw_protocols:
                if isinstance(p, int):
                    if 0 <= p <= 255:
                        protocols.append(p)
                    else:
                        violations.append(f"Protocol number {p} out of range [0, 255]")
                elif isinstance(p, str):
                    p_lower = p.strip().lower()
                    if p_lower in NAMED_PROTOCOLS:
                        protocols.append(NAMED_PROTOCOLS[p_lower])
                    else:
                        violations.append(f"Unrecognized protocol name '{p}'")
                else:
                    violations.append(f"Protocol item '{p}' must be int or string")

        # Port conditions
        dest_ports = self._parse_port_conditions(
            raw.get("destination_ports", []), "destination_ports", violations
        )
        src_ports = self._parse_port_conditions(
            raw.get("source_ports", []), "source_ports", violations
        )

        # Packet lengths
        packet_lengths: List[int] = []
        raw_lengths = raw.get("packet_lengths", [])
        if not isinstance(raw_lengths, list):
            violations.append("'packet_lengths' must be a list of integers")
        else:
            for l in raw_lengths:
                if isinstance(l, int) and 20 <= l <= 65535:
                    packet_lengths.append(l)
                else:
                    violations.append(f"Invalid packet_length {l}; expected integer in [20, 65535]")

        # Action verification
        action_type = str(raw.get("action_type", "")).strip().upper()
        if action_type not in VALID_ACTIONS:
            violations.append(
                f"Invalid action_type '{action_type}'; must be one of {sorted(VALID_ACTIONS)}"
            )

        rate_limit_bps = 0.0
        redirect_target = None
        dscp_mark = None

        if action_type == "RATE_LIMIT":
            try:
                rate_limit_bps = float(raw.get("rate_limit_bps", 0.0))
                if rate_limit_bps < 0.0:
                    violations.append(f"Negative rate_limit_bps {rate_limit_bps} not permitted")
            except (ValueError, TypeError):
                violations.append("rate_limit_bps must be a valid float")

        elif action_type == "REDIRECT_VRF":
            redirect_target = raw.get("redirect_target")
            if not redirect_target or not isinstance(redirect_target, str):
                violations.append("redirect_target string required for REDIRECT_VRF action")
            elif not ROUTE_TARGET_REGEX.match(redirect_target.strip()):
                violations.append(
                    f"redirect_target '{redirect_target}' must conform to ASN:index format"
                )
            else:
                redirect_target = redirect_target.strip()

        elif action_type == "MARK_DSCP":
            raw_dscp = raw.get("dscp_mark")
            if not isinstance(raw_dscp, int) or raw_dscp < 0 or raw_dscp > 63:
                violations.append(f"dscp_mark '{raw_dscp}' must be an integer in range [0, 63]")
            else:
                dscp_mark = raw_dscp

        if violations:
            return FlowspecValidationResult(
                is_valid=False,
                rule_id=rule_id or "unknown",
                schema_version=schema or "unknown",
                violations=violations,
                normalized_rule=None,
            )

        rule = FlowspecRule(
            rule_id=rule_id,
            schema_version=schema,
            action_type=action_type,
            destination_prefix=norm_dest,
            source_prefix=norm_src,
            ip_protocols=sorted(set(protocols)),
            destination_ports=dest_ports,
            source_ports=src_ports,
            packet_lengths=sorted(set(packet_lengths)),
            rate_limit_bps=rate_limit_bps,
            redirect_target=redirect_target,
            dscp_mark=dscp_mark,
        )

        return FlowspecValidationResult(
            is_valid=True,
            rule_id=rule_id,
            schema_version=schema,
            violations=[],
            normalized_rule=rule,
        )

    def _parse_port_conditions(
        self, raw_list: Any, field_name: str, violations: List[str]
    ) -> List[PortCondition]:
        if not isinstance(raw_list, list):
            violations.append(f"'{field_name}' must be a list of port conditions")
            return []

        conditions: List[PortCondition] = []
        for item in raw_list:
            if isinstance(item, int):
                if 1 <= item <= 65535:
                    conditions.append(PortCondition(operator="==", port=item))
                else:
                    violations.append(f"Port {item} in '{field_name}' out of valid range [1, 65535]")
            elif isinstance(item, tuple) or isinstance(item, list):
                if len(item) == 2 and item[0] in VALID_PORT_OPERATORS and isinstance(item[1], int):
                    if 1 <= item[1] <= 65535:
                        conditions.append(PortCondition(operator=item[0], port=item[1]))
                    else:
                        violations.append(
                            f"Port {item[1]} in '{field_name}' out of valid range [1, 65535]"
                        )
                else:
                    violations.append(
                        f"Port tuple {item} must match (operator, port) format"
                    )
            elif isinstance(item, dict):
                op = item.get("operator", "==")
                p = item.get("port")
                if op in VALID_PORT_OPERATORS and isinstance(p, int) and 1 <= p <= 65535:
                    conditions.append(PortCondition(operator=op, port=p))
                else:
                    violations.append(
                        f"Port dict {item} invalid operator or port out of range"
                    )
            else:
                violations.append(f"Unsupported port condition structure: {item}")
        return conditions

    def enforce_batch(self, rules: List[Dict[str, Any]]) -> List[FlowspecValidationResult]:
        if len(rules) > self.max_batch_size:
            raise FlowspecContractError(
                "BATCH_CAPACITY_EXCEEDED",
                f"Batch size {len(rules)} exceeds TCAM maximum capacity {self.max_batch_size}",
            )
        return [self.validate_rule(r) for r in rules]
