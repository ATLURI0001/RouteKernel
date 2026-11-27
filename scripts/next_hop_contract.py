"""BGP next-hop IPv4 address contract validator."""
import ipaddress


def validate_next_hop(ip: str) -> None:
    addr = ipaddress.ip_address(ip)
    if addr.is_multicast or addr.is_unspecified:
        raise ValueError(f"contract violation: invalid next-hop address {ip}")
