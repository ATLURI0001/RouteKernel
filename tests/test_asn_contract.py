from scripts.asn_contract import AsnContract


def test_asn_contract():
    ok, errs = AsnContract.validate_as_path([174, 3356, 13335])
    assert ok is True and errs == []

    bad, errs2 = AsnContract.validate_as_path([174, 64512, 0])
    assert bad is False
    assert "ERR_BOGON_PRIVATE_ASN:64512" in errs2
    assert "ERR_RESERVED_ASN:0" in errs2
