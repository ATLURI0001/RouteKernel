"""BGP AS_PATH loop detection sentinel."""


def assert_acyclic_as_path(as_path: list[int], local_asn: int) -> None:
    if local_asn in as_path:
        raise ValueError(f"sentinel violation: AS_PATH loop detected for AS{local_asn}")
