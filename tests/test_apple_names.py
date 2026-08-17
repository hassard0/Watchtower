"""Apple ecosystem naming must preserve provenance and reject opaque IDs."""
from watchtower.apple_names import (
    analyze_apple_service,
    apple_model_label,
    normalize_apple_instance,
)


def test_airplay_and_raop_extract_user_facing_name_and_model():
    result = analyze_apple_service(
        "_raop._tcp.local.",
        "CA3FF992A25E@Living Room",
        "Living-Room.local",
        {"am": "AppleTV6,2", "pk": "secret-public-key-material"},
    )
    assert result["name"] == "Living Room"
    assert result["source"] == "airplay_display_name"
    assert result["model"] == "Apple TV 4K (1st generation)"
    assert result["apple_hardware"] is True
    assert "pk" not in result["evidence"]


def test_companion_link_extracts_exact_bluetooth_link_and_model():
    result = analyze_apple_service(
        "_companion-link._tcp.local.", "Kepler", "Kepler.local",
        {"rpMd": "Mac16,9", "rpBA": "7C:3F:93:E7:01:AB", "rpHI": "opaque"},
    )
    assert result["name"] == "Kepler"
    assert result["model"] == "Mac Studio (2025, M4 Max)"
    assert result["bluetooth_mac"] == "7c:3f:93:e7:01:ab"
    assert result["evidence"]["apple_hardware"] is True
    assert "rpHI" not in result["evidence"]


def test_airplay_does_not_misclassify_third_party_receiver_as_apple_hardware():
    result = analyze_apple_service(
        "_airplay._tcp.local.", "Kitchen", "sonos.local",
        {"manufacturer": "Sonos", "model": "One", "deviceid": "48:A6:B8:D9:20:3A"},
    )
    assert result["name"] == "Kitchen"
    assert result["model"] == "One"
    assert result["apple_hardware"] is False
    assert result["device_mac"] == "48:a6:b8:d9:20:3a"


def test_opaque_instances_are_not_promoted_to_names():
    assert normalize_apple_instance("CA3FF992A25E@Bedroom", "_raop._tcp.local.") == "Bedroom"
    assert normalize_apple_instance("70-35-60-63.1 Guest Room", "_sleep-proxy._udp.local.") == "Guest Room"
    assert normalize_apple_instance("00112233445566778899", "_apple-mobdev2._tcp.local.") is None


def test_opaque_mobile_instance_can_fall_back_to_human_bonjour_host():
    result = analyze_apple_service(
        "_apple-mobdev2._tcp.local.", "00112233445566778899",
        "Ians-iPhone.local", {},
    )
    assert result["name"] == "Ians iPhone"
    assert result["source"] == "apple_bonjour_host_name"
    assert result["evidence"]["name_origin"] == "host_name"


def test_unknown_apple_model_keeps_family_and_identifier():
    assert apple_model_label("AppleTV99,1") == "Apple TV (AppleTV99,1)"
    assert apple_model_label("0,1,2") is None
