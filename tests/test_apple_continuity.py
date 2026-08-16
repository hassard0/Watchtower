from watchtower.apple_continuity import decode_continuity, short_state_summary


def test_airdrop_does_not_retain_contact_derived_hashes():
    decoded = decode_continuity("4c0005080102030405060708")
    assert decoded["subtype"] == "airdrop"
    assert decoded["payload_length"] == 8
    assert "contact_hashes" not in decoded


def test_malformed_continuity_hex_is_ignored():
    assert decode_continuity("4c00nothex") is None


def test_unresolved_proximity_model_code_is_exposed_for_research():
    decoded = decode_continuity("4c000703067900")
    assert decoded["subtype"] == "proximity-pairing"
    assert decoded["model_id"] == "0x7906"
    assert "unresolved model code: 0x7906" in short_state_summary(decoded)


def test_connected_airpods_keep_distinct_subtype_without_bogus_model():
    decoded = decode_continuity("4c00160400112233")
    assert decoded["subtype"] == "airpods-connected"
    assert "model_id" not in decoded
