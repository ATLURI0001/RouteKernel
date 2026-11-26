"""BGP prefix hijack origin-ASN sentinel."""


def assert_authorized_origin(prefix: str, origin_asn: int, roa_map: dict[str, set[int]]) -> None:
    allowed = roa_map.get(prefix, set())
    if origin_asn not in allowed:
        raise ValueError(f"sentinel violation: unauthorized origin AS{origin_asn} for {prefix}")
