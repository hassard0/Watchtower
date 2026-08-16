from watchtower.analytics import _classify_entity_kind
from watchtower.flipper import detect_flipper_zero


def test_official_flipper_name_and_short_service_are_high_confidence():
    result = detect_flipper_zero("Flipper Bob", ["3081"])
    assert result == {
        "device_signature": "flipper_zero",
        "confidence": "high",
        "reasons": ["official-name-format", "official-serial-service"],
        "alert_eligible": True,
    }


def test_official_flipper_base_uuid_is_recognized():
    result = detect_flipper_zero(
        "Flipper Zero",
        ["00003083-0000-1000-8000-00805f9b34fb"],
    )
    assert result and result["confidence"] == "high"


def test_spoofable_name_alone_does_not_alert():
    result = detect_flipper_zero("Flipper Alice", ["180f"])
    assert result and result["confidence"] == "medium"
    assert result["alert_eligible"] is False


def test_unrelated_or_nearby_uuid_does_not_match():
    assert detect_flipper_zero("My Sensor", ["307f", "3084"]) is None


def test_analytics_classifies_detection():
    features = {
        "decoded": {"device_detection": {"device_signature": "flipper_zero"}},
        "service_uuids": ["3080"],
    }
    assert _classify_entity_kind("ble_scanner", "ble_adv", features) == "ble_flipper_zero"
