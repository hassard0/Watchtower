from watchtower.location_trackers import (
    detect_location_tracker,
    short_uuid,
    tracker_risk,
)


def test_uuid_normalization_handles_bluetooth_base_uuid():
    assert short_uuid("0000FD84-0000-1000-8000-00805F9B34FB") == "fd84"
    assert short_uuid("0xFCB2") == "fcb2"


def test_dult_payload_decodes_provider_and_separated_state():
    found = detect_location_tracker(None, [], {"0000fcb2-0000-1000-8000-00805f9b34fb": "0200aabb"}, None)
    assert found["family"] == "dult"
    assert found["provider"] == "google"
    assert found["separated"] is True
    assert found["alert_eligible"] is True


def test_dult_near_owner_bit_suppresses_separated_claim():
    found = detect_location_tracker(None, ["fcb2"], {"fcb2": "0101"}, None)
    assert found["provider"] == "apple"
    assert found["near_owner"] is True
    assert found["status"] == "near-owner"


def test_tile_requires_an_assigned_service_not_a_spoofable_name():
    assert detect_location_tracker("Tile", [], {}, None) is None
    found = detect_location_tracker(None, ["0000FEED-0000-1000-8000-00805F9B34FB"], {}, None)
    assert found["family"] == "tile"
    assert found["confidence"] == "high"


def test_tile_company_identifier_is_recognized():
    found = detect_location_tracker(None, [], {}, "7c06aabbcc")
    assert found["family"] == "tile"
    assert "0x067C" in found["protocol_evidence"]


def test_legacy_findmy_does_not_overclaim_airtag_model():
    found = detect_location_tracker(None, [], {}, "4c00121900" + "00" * 20)
    assert found["family"] == "apple_findmy"
    assert "AirTag" not in found["label"]


def test_risk_elevates_separated_persistent_close_tracker():
    severity, score = tracker_risk({"separated": True}, avg_rssi=-50, age_sec=1200, sightings=20)
    assert severity == "high"
    assert score >= 0.9
