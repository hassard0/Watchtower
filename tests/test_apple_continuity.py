from watchtower.apple_continuity import decode_continuity


def test_airdrop_does_not_retain_contact_derived_hashes():
    decoded = decode_continuity("4c0005080102030405060708")
    assert decoded["subtype"] == "airdrop"
    assert decoded["payload_length"] == 8
    assert "contact_hashes" not in decoded


def test_malformed_continuity_hex_is_ignored():
    assert decode_continuity("4c00nothex") is None
