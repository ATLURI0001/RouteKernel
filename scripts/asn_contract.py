"""BGP 32-bit ASN Range & Bogon AS Path Contract Validator."""

from __future__ import annotations

from typing import List


class AsnContract:
    PRIVATE_RANGES = [(64512, 65534), (4200000000, 4294967294)]
    RESERVED_ASNS = {0, 23456, 65535, 4294967295}

    @classmethod
    def validate_as_path(cls, as_path: List[int], allow_private: bool = False) -> tuple[bool, List[str]]:
        errors: List[str] = []
        if not as_path:
            return False, ["ERR_EMPTY_AS_PATH"]

        for asn in as_path:
            if asn < 0 or asn > 4294967295:
                errors.append(f"ERR_ASN_OUT_OF_RANGE:{asn}")
            elif asn in cls.RESERVED_ASNS:
                errors.append(f"ERR_RESERVED_ASN:{asn}")
            elif not allow_private:
                for low, high in cls.PRIVATE_RANGES:
                    if low <= asn <= high:
                        errors.append(f"ERR_BOGON_PRIVATE_ASN:{asn}")
                        break

        return len(errors) == 0, errors
