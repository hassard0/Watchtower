"""Apple Continuity protocol decoder.

Apple's "Continuity" family of BLE broadcasts uses manufacturer data prefix
``0x004C`` followed by ``<subtype><len><payload>``. Multiple subtypes can be
concatenated in one advertisement.

Subtypes most useful for device fingerprinting / state-aware grouping:

  0x07  AirPods/Beats *Proximity Pairing*
        15-byte payload includes a 2-byte device-model-number that
        unambiguously identifies AirPods Pro / Max / Studio Buds / etc.,
        plus battery levels and case lid state.

  0x10  *Nearby-Info*
        6-byte payload. Byte 0 nibble carries ACTIVITY (lock-screen / video /
        call / unlocked / charging). Byte 1 carries STATUS flags (AirPods
        nearby, Wi-Fi state, primary device). Bytes 2-5 = rotating auth tag,
        not identifying.

  0x12  *Find-My*
        Anonymous tracker beacon. We can't identify the owner (by design),
        but we can detect the broadcast as a signal that an AirTag /
        lost-AirPods / Find-My-enabled accessory is present.

  0x05/0x09 AirDrop / Handoff — partial activity hints. Contact hashes and
        rotating authentication material are deliberately not retained.
"""
from __future__ import annotations

from typing import Any


# AirPods / Beats / proximity pairing model IDs (subtype 0x07).
# 2-byte little-endian model number → friendly name.
_AIRPODS_MODEL_IDS: dict[int, str] = {
    0x0220: "AirPods",
    0x0F20: "AirPods (Gen 2)",
    0x1320: "AirPods (Gen 3)",
    0x1420: "AirPods Pro",
    0x0E20: "AirPods Pro",
    0x2420: "AirPods Pro 2",
    0x2D20: "AirPods Pro 2 (USB-C)",
    0x0A20: "AirPods Max",
    0x0B20: "PowerBeats Pro",
    0x0C20: "Beats Solo Pro",
    0x1020: "Beats Flex",
    0x0520: "BeatsX",
    0x0620: "Beats Solo3",
    0x0320: "Beats Studio3",
    0x0920: "Beats Studio Pro",
    0x1120: "Beats Studio Buds",
    0x1720: "Beats Studio Buds+",
    0x1B20: "Beats Fit Pro",
    0x1E20: "AirPods (Gen 3)",
    0x2020: "AirPods Pro 2",
    0x2720: "Beats Solo 4",
}


# Nearby-Info ACTIVITY (low nibble of byte 0 of the 6-byte 0x10 payload).
_NEARBY_ACTIVITY: dict[int, str] = {
    0x0: "activity-unknown",
    0x1: "screen-off",          # paired apple watch on wrist
    0x3: "screen-on",           # phone idle, screen on
    0x4: "audio-playing",
    0x5: "lock-changed",
    0x7: "transition-state",
    0x9: "phone-call-or-facetime",
    0xA: "active",              # actively used / front app
    0xB: "screen-on-w-airdrop", # airdrop sharing pane
    0xD: "screen-on-w-music-or-video",
    0xE: "transcript-mode",
}


# Nearby-Info ACTION flags (bit 1 byte 1) — Apple iOS device family/state hints.
def _nearby_status_flags(byte1: int) -> list[str]:
    flags: list[str] = []
    if byte1 & 0x40: flags.append("airpods-nearby")
    if byte1 & 0x20: flags.append("primary-icloud-device")
    if byte1 & 0x10: flags.append("airdrop-receiving")
    if byte1 & 0x04: flags.append("auth-tag-present")
    if byte1 & 0x02: flags.append("wifi-on")
    if byte1 & 0x01: flags.append("charging")
    return flags


# Find-My status nibble (subtype 0x12 byte 0 high nibble).
_FINDMY_STATUS: dict[int, str] = {
    0x0: "unowned",          # AirTag not paired with any iCloud account
    0x4: "owned",            # nearby-owner mode (recently with owner)
    0x8: "separated",        # offline / lost-mode
    0x2: "lost-mode",
    0xC: "unowned-paired",
}


def _decode_proximity_pairing(payload: bytes) -> dict:
    """0x07 — AirPods / Beats proximity pairing."""
    out: dict[str, Any] = {"subtype": "proximity-pairing"}
    if len(payload) < 3:
        return out
    # bytes 0-1: model-id (LE)
    model_id = int.from_bytes(payload[0:2], "little")
    out["model_id"] = f"0x{model_id:04x}"
    out["model"] = _AIRPODS_MODEL_IDS.get(model_id) or _AIRPODS_MODEL_IDS.get(int.from_bytes(payload[0:2], "big"))
    if len(payload) >= 6:
        # byte 2 = status; nibble 4-bit each = right pod / left pod state
        # bytes 4-5 = battery levels (high nibble = right pod %, low = left pod %)
        # exact format varies by firmware — extract conservatively
        battery_byte = payload[4]
        out["battery_left_pct"] = (battery_byte & 0x0F) * 10 if (battery_byte & 0x0F) <= 10 else None
        out["battery_right_pct"] = ((battery_byte >> 4) & 0x0F) * 10 if ((battery_byte >> 4) & 0x0F) <= 10 else None
        out["case_lid_open"] = bool(payload[3] & 0x40)
        out["in_ear"] = bool(payload[3] & 0x20)
    return out


def _decode_nearby_info(payload: bytes) -> dict:
    """0x10 — Nearby-Info (Continuity 'state' broadcast from iOS/macOS)."""
    out: dict[str, Any] = {"subtype": "nearby-info"}
    if len(payload) < 2:
        return out
    activity_nibble = payload[0] & 0x0F
    status_byte = payload[1]
    out["activity"] = _NEARBY_ACTIVITY.get(activity_nibble, f"unknown-0x{activity_nibble:x}")
    out["activity_code"] = activity_nibble
    out["flags"] = _nearby_status_flags(status_byte)
    return out


def _decode_find_my(payload: bytes) -> dict:
    """0x12 — Find-My beacon. Owner anonymous by design; we can read status."""
    out: dict[str, Any] = {"subtype": "find-my"}
    if len(payload) < 1:
        return out
    status_nibble = (payload[0] >> 4) & 0x0F
    out["status"] = _FINDMY_STATUS.get(status_nibble, f"unknown-0x{status_nibble:x}")
    out["maintained"] = bool(payload[0] & 0x04)  # "maintained" = owner nearby recently
    # The remaining payload bytes are 22 bytes of public key suffix — rotating
    # cryptographic identifier; we don't extract it because it changes every ~15min.
    return out


def _decode_handoff(payload: bytes) -> dict:
    """0x0c — Handoff (continuity activity broadcast)."""
    out: dict[str, Any] = {"subtype": "handoff"}
    if len(payload) >= 2:
        out["clipboard_status"] = bool(payload[0] & 0x10)
        out["sequence"] = int.from_bytes(payload[1:3], "little") if len(payload) >= 3 else None
    return out


def _decode_airdrop(payload: bytes) -> dict:
    """0x05 — AirDrop presence without retaining contact-derived hashes."""
    out: dict[str, Any] = {"subtype": "airdrop"}
    if payload:
        out["payload_length"] = len(payload)
    return out


# Map subtype byte → friendly name + decoder.
_SUBTYPE_DECODERS: dict[int, tuple[str, Any]] = {
    0x02: ("ibeacon",          None),
    0x05: ("airdrop",          _decode_airdrop),
    0x07: ("proximity-pairing", _decode_proximity_pairing),
    0x09: ("airplay-target",    None),
    0x0a: ("magic-switch",      None),
    0x0b: ("watch-connection",  None),
    0x0c: ("handoff",           _decode_handoff),
    0x0d: ("tethering-target",  None),
    0x0e: ("tethering-source",  None),
    0x0f: ("nearby-action",     None),
    0x10: ("nearby-info",       _decode_nearby_info),
    0x12: ("find-my",           _decode_find_my),
    0x16: ("airpods-connected", _decode_proximity_pairing),
}


def decode_continuity(mfr_data_hex: str) -> dict | None:
    """Parse Apple manufacturer data; return decoded dict or None.

    Multiple Continuity messages can concatenate; we decode the first one
    we recognize for entity_id grouping, but record all subtypes seen.
    """
    if not mfr_data_hex or not mfr_data_hex.lower().startswith("4c00"):
        return None
    try:
        raw = bytes.fromhex(mfr_data_hex)
    except (TypeError, ValueError):
        return None
    if len(raw) < 4:
        return None
    # Strip the 0x4C00 vendor id prefix.
    body = raw[2:]
    decoded: dict[str, Any] = {"subtypes_seen": []}
    primary: dict | None = None
    i = 0
    while i + 1 < len(body):
        subtype = body[i]
        seg_len = body[i + 1]
        if i + 2 + seg_len > len(body):
            break
        payload = body[i + 2:i + 2 + seg_len]
        name, decoder = _SUBTYPE_DECODERS.get(subtype, (f"subtype-0x{subtype:02x}", None))
        decoded["subtypes_seen"].append(name)
        if primary is None:
            primary = {"subtype": name, "subtype_byte": subtype}
            if decoder is not None:
                try:
                    primary.update(decoder(payload) or {})
                except Exception:  # noqa: BLE001
                    pass
        i += 2 + seg_len
    if primary:
        decoded.update(primary)
    return decoded


def label_for_decoded(decoded: dict | None) -> str:
    """Produce a friendly entity_id suffix from a decoded Continuity payload."""
    if not decoded:
        return "unknown"
    # Highest-fidelity: AirPods/Beats with a recognized model.
    if decoded.get("model"):
        return decoded["model"].replace(" ", "-")
    sub = decoded.get("subtype") or "unknown"
    return sub


def short_state_summary(decoded: dict | None) -> str:
    """One-line human-readable state line for entity detail UI."""
    if not decoded:
        return ""
    parts: list[str] = []
    sub = decoded.get("subtype")
    if sub:
        parts.append(sub)
    if decoded.get("model"):
        parts.append(f"model: {decoded['model']}")
    if decoded.get("activity"):
        parts.append(decoded["activity"])
    flags = decoded.get("flags") or []
    if flags:
        parts.append(", ".join(flags[:3]))
    if decoded.get("status"):
        parts.append(f"status: {decoded['status']}")
    bl = decoded.get("battery_left_pct")
    br = decoded.get("battery_right_pct")
    if bl is not None or br is not None:
        parts.append(f"battery L:{bl} R:{br}")
    return " · ".join(p for p in parts if p)
