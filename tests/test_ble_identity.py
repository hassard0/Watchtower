from watchtower.analytics import _ble_entity_id


def test_public_bluez_address_keeps_stable_mac_identity():
    features = {
        "mac": "d0:03:4b:3a:b9:69",
        "address_type": "public",
        "is_random_mac": False,
        "manufacturer_data_hex": "4c00160400112233",
    }
    assert _ble_entity_id(features, "ble_scanner", "ble_adv") == \
        "ble:mac:d0:03:4b:3a:b9:69"


def test_random_apple_address_groups_by_continuity_subtype():
    features = {
        "mac": "5d:54:1b:43:25:65",
        "address_type": "random",
        "is_random_mac": True,
        "manufacturer_data_hex": "4c00160400112233",
    }
    assert _ble_entity_id(features, "ble_scanner", "ble_adv") == \
        "ble:apple:airpods-connected"


def test_legacy_apple_packet_does_not_trust_false_random_flag():
    features = {
        "mac": "5d:54:1b:43:25:65",
        "is_random_mac": False,
        "manufacturer_data_hex": "4c000703067900",
    }
    assert _ble_entity_id(features, "ble_scanner", "ble_adv") == \
        "ble:apple:proximity-pairing"
