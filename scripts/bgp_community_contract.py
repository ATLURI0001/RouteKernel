"""BGP community string contract validator."""
import re

_COMM_RE = re.compile(r"^\d{1,5}:\d{1,5}$")


def validate_bgp_community(comm: str) -> None:
    if not isinstance(comm, str) or not _COMM_RE.match(comm):
        raise ValueError(f"contract violation: invalid BGP community '{comm}'")
    asn, val = (int(x) for x in comm.split(":"))
    if asn > 65535 or val > 65535:
        raise ValueError(f"contract violation: BGP community out of 16-bit range '{comm}'")
