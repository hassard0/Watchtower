from watchtower.api import _discovery_candidate_score


def test_high_confidence_named_ipad_outranks_unnamed_packet_volume():
    ipad = {
        "entity_id": "lan:mac:72:5a:68:df:7c:ed",
        "friendly_name": "iPad",
        "friendly_name_source": "apple_companion_name",
        "friendly_name_confidence": 0.975,
        "total_observations": 30,
    }
    noisy = {
        "entity_id": "ble:apple:nearby-info",
        "friendly_name": None,
        "friendly_name_confidence": None,
        "total_observations": 600_000,
    }
    assert _discovery_candidate_score(ipad, set()) > _discovery_candidate_score(noisy, set())
    assert ipad["candidacy_score"] > noisy["candidacy_score"]


def test_apple_audio_group_gets_visibility_boost():
    audio = {
        "entity_id": "ble:apple:proximity-pairing",
        "friendly_name": "Apple proximity accessory",
        "friendly_name_source": "service_fingerprint",
        "friendly_name_confidence": 0.68,
        "total_observations": 12,
    }
    assert _discovery_candidate_score(audio, set()) >= 45
