"""Passive identification of standardized BLE location-tracker broadcasts.

This module deliberately decodes only public radio metadata. Owner identity
and stable identifiers are protected by the tracker networks and are not
available from an arbitrary passive capture.
"""
from __future__ import annotations

from typing import Any

DULT_SERVICE_UUID = "fcb2"
TILE_SERVICE_UUIDS = {"fd84", "feec", "feed"}
DULT_NETWORKS = {
    0x01: "apple",
    0x02: "google",
    0x03: "samsung",
    0x04: "amazon",
}


def short_uuid(value: str) -> str:
    """Normalize a Bluetooth 16-bit UUID or its base-UUID expansion."""
    raw = str(value or "").strip().lower().replace("0x", "")
    if len(raw) == 4 and all(char in "0123456789abcdef" for char in raw):
        return raw
    suffix = "-0000-1000-8000-00805f9b34fb"
    if raw.startswith("0000") and raw.endswith(suffix) and len(raw) == 36:
        return raw[4:8]
    return raw


def _normalized_service_data(service_data_hex: dict[str, str] | None) -> dict[str, str]:
    return {short_uuid(key): str(value or "").lower() for key, value in (service_data_hex or {}).items()}


def detect_location_tracker(
    local_name: str | None,
    service_uuids: list[str] | None,
    service_data_hex: dict[str, str] | None,
    manufacturer_data_hex: str | None,
) -> dict[str, Any] | None:
    """Return protocol-backed tracker metadata, or ``None``.

    Name-only guesses are intentionally excluded because they are trivial to
    spoof and would create unsafe anti-stalking false positives.
    """
    del local_name  # Names may aid display, but are never proof of a tracker.
    services = {short_uuid(value) for value in (service_uuids or [])}
    service_data = _normalized_service_data(service_data_hex)
    mfr = (manufacturer_data_hex or "").lower()

    # Current cross-platform Detecting Unwanted Location Trackers broadcast.
    if DULT_SERVICE_UUID in services or DULT_SERVICE_UUID in service_data:
        payload_hex = service_data.get(DULT_SERVICE_UUID, "")
        try:
            payload = bytes.fromhex(payload_hex)
        except ValueError:
            payload = b""
        network_id = payload[0] if payload else None
        near_owner = bool(payload[1] & 0x01) if len(payload) >= 2 else None
        provider = DULT_NETWORKS.get(network_id, "unknown")
        return {
            "family": "dult",
            "label": f"{provider.title()} compatible location tracker",
            "provider": provider,
            "network_id": network_id,
            "near_owner": near_owner,
            "separated": (not near_owner) if near_owner is not None else None,
            "status": "near-owner" if near_owner else "separated" if near_owner is not None else "unknown",
            "confidence": "high",
            "alert_eligible": True,
            "protocol_evidence": "DULT service-data UUID 0xFCB2",
        }

    # Apple legacy Find My advertisement, used by AirTag, AirPods, and
    # third-party Find My accessories. It is not enough to claim AirTag model.
    if mfr.startswith("4c0012"):
        from watchtower.apple_continuity import decode_continuity

        decoded = decode_continuity(mfr) or {}
        status = decoded.get("status") or "unknown"
        return {
            "family": "apple_findmy",
            "label": "Apple Find My-compatible tracker",
            "provider": "apple",
            "near_owner": status == "owned",
            "separated": status in {"separated", "lost-mode", "unowned"},
            "status": status,
            "confidence": "high",
            "alert_eligible": True,
            "protocol_evidence": "Apple company ID 0x004C and Find My subtype 0x12",
        }

    tile_markers = sorted((services | set(service_data)) & TILE_SERVICE_UUIDS)
    tile_company_data = mfr.startswith("7c06")  # 0x067C, little-endian on air
    if tile_markers or tile_company_data:
        evidence = (
            "Tile assigned service UUID(s): " + ", ".join(f"0x{x.upper()}" for x in tile_markers)
            if tile_markers else "Tile Bluetooth company ID 0x067C"
        )
        return {
            "family": "tile",
            "label": "Tile-compatible tracker",
            "provider": "tile",
            "near_owner": None,
            "separated": None,
            "status": "state-unavailable",
            "confidence": "high",
            "alert_eligible": True,
            "protocol_evidence": evidence,
        }
    return None


def tracker_risk(detection: dict[str, Any], *, avg_rssi: float | None, age_sec: int, sightings: int) -> tuple[str, float]:
    """Score observable anti-stalking evidence without inferring ownership."""
    score = 0.45
    if detection.get("separated") is True:
        score += 0.25
    if avg_rssi is not None and avg_rssi > -65:
        score += 0.15
    if age_sec >= 600 and sightings >= 6:
        score += 0.10
    score = min(score, 0.95)
    severity = "high" if score >= 0.75 else "medium"
    return severity, round(score, 2)
