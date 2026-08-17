"""Stable device identity hints from decoded RF protocol envelopes.

Encrypted and rolling-code payloads are intentionally treated as volatile.
Protocol decoders often expose an unencrypted device or sensor identifier next
to those fields; only those stable fields are suitable for entity grouping.
"""
from __future__ import annotations

import re
from typing import Any


_STABLE_KEYS = (
    "id", "device_id", "sensor_id", "serial", "device", "house_code",
    "system_id", "network_id", "transmitter_id",
)
_VOLATILE_OR_PROTECTED_KEYS = {
    "rolling_code", "rollingcode", "counter", "sequence", "mic", "crc",
    "code", "data", "payload", "raw_msg", "msg",
}


def _safe_component(value: Any) -> str | None:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    text = str(value).strip()
    if not text or len(text) > 80:
        return None
    return re.sub(r"[^A-Za-z0-9_.:-]+", "_", text)


def stable_subghz_identity(decoded: dict[str, Any]) -> tuple[str, str] | None:
    """Return the first trustworthy identity field, never a rolling code."""
    for key in _STABLE_KEYS:
        value = _safe_component(decoded.get(key))
        if value is not None:
            return key, value
    return None


def subghz_identification_metadata(decoded: dict[str, Any]) -> dict[str, Any]:
    identity = stable_subghz_identity(decoded)
    observed = sorted(
        key for key, value in decoded.items()
        if key.lower() in _VOLATILE_OR_PROTECTED_KEYS and value is not None and value != ""
    )
    return {
        "stable_identity_field": identity[0] if identity else None,
        "stable_identity_value": identity[1] if identity else None,
        "protected_or_volatile_fields": observed,
        "encrypted_or_rolling": any(
            key.lower() in {"rolling_code", "rollingcode", "mic", "payload", "data"}
            for key in observed
        ),
        "decoder": "rtl_433",
    }


def subghz_summary(protocol: str, decoded: dict[str, Any]) -> str:
    meta = subghz_identification_metadata(decoded)
    parts = [f"rtl_433 decoded protocol: {protocol}"]
    if meta["stable_identity_field"]:
        parts.append(
            f"stable {meta['stable_identity_field']}: {meta['stable_identity_value']}"
        )
    if meta["encrypted_or_rolling"]:
        parts.append("rolling/encrypted payload observed; grouped without using the changing code")
    return " · ".join(parts)
