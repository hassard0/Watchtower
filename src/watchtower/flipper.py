"""Conservative BLE fingerprints for official Flipper Zero firmware."""
from __future__ import annotations

import re
from typing import Any, Iterable


_OFFICIAL_NAME = re.compile(r"^Flipper(?: [A-Za-z0-9_-]{1,24})?$")


def _short_uuid(value: str) -> int | None:
    """Return a Bluetooth 16-bit UUID from short or base-UUID notation."""
    raw = str(value or "").strip().lower().removeprefix("0x")
    match = re.fullmatch(r"([0-9a-f]{4})", raw)
    if match:
        return int(match.group(1), 16)
    match = re.fullmatch(r"0000([0-9a-f]{4})-0000-1000-8000-00805f9b34fb", raw)
    return int(match.group(1), 16) if match else None


def detect_flipper_zero(local_name: str | None, service_uuids: Iterable[str]) -> dict[str, Any] | None:
    """Identify the BLE advertisement emitted by official Flipper firmware.

    Official firmware advertises a ``Flipper <device-name>`` local name and a
    0x3080..0x3083 service UUID (the low bits encode the hardware colour).
    A name alone is easy to spoof, so only the two-signal match is high
    confidence and eligible for an alert.
    """
    name = str(local_name or "").strip()
    name_match = bool(_OFFICIAL_NAME.fullmatch(name))
    short_uuids = {short for value in service_uuids if (short := _short_uuid(value)) is not None}
    service_match = any(0x3080 <= value <= 0x3083 for value in short_uuids)
    if not name_match and not service_match:
        return None
    confidence = "high" if name_match and service_match else "medium"
    reasons = []
    if name_match:
        reasons.append("official-name-format")
    if service_match:
        reasons.append("official-serial-service")
    return {
        "device_signature": "flipper_zero",
        "confidence": confidence,
        "reasons": reasons,
        "alert_eligible": confidence == "high",
    }
