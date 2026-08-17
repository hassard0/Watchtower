"""Event envelope shared across all scanners and sinks."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from ulid import ULID


class Scanner(str, Enum):
    BLE = "ble_scanner"
    WIFI = "wifi_scanner"
    SUBGHZ = "subghz_scanner"
    MIDBAND = "midband_scanner"


class EventKind(str, Enum):
    BLE_ADV = "ble_adv"
    BLE_SCAN_RESPONSE = "ble_scan_response"
    WIFI_PROBE_REQUEST = "wifi_probe_request"
    WIFI_ASSOC_REQUEST = "wifi_assoc_request"
    WIFI_BEACON_SEEN = "wifi_beacon_seen"
    KEYFOB_EMISSION = "keyfob_emission"
    GARAGE_EMISSION = "garage_emission"
    UNKNOWN_SUBGHZ_BURST = "unknown_subghz_burst"
    WALKIETALKIE_EMISSION = "walkietalkie_emission"
    SUBGHZ_PROTOCOL_DECODED = "subghz_protocol_decoded"
    CELLULAR_BAND_ENERGY = "cellular_band_energy"
    LORA_EMISSION = "lora_emission"
    AVIATION_BAND_ENERGY = "aviation_band_energy"


@dataclass
class Features:
    rssi: int | None = None
    mac: str | None = None
    vendor_oui: str | None = None
    service_uuids: list[str] = field(default_factory=list)
    service_data_hex: dict[str, str] = field(default_factory=dict)
    manufacturer_data_hex: str | None = None
    encrypted_ad_data_hex: list[str] = field(default_factory=list)
    # BlueZ's authoritative BLE address classification ("public" or
    # "random").  BLE privacy addresses cannot be identified reliably from
    # the IEEE locally-administered bit alone.
    address_type: str | None = None
    is_random_mac: bool | None = None
    tx_power: int | None = None
    local_name: str | None = None
    # sub-GHz
    frequency_hz: int | None = None
    protocol: str | None = None
    decoded: dict[str, Any] = field(default_factory=dict)
    # midband / spectrum
    band_name: str | None = None
    energy_dbm: float | None = None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Event:
    scanner: Scanner
    kind: EventKind
    features: Features
    raw: dict[str, Any] = field(default_factory=dict)
    ts: str = field(default_factory=_now_iso)
    event_id: str = field(default_factory=lambda: str(ULID()))
    channel_hint: int | None = None
    mesh_node_id: str | None = None  # v2

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["scanner"] = self.scanner.value
        d["kind"] = self.kind.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Event":
        return cls(
            event_id=d["event_id"],
            ts=d["ts"],
            scanner=Scanner(d["scanner"]),
            kind=EventKind(d["kind"]),
            features=Features(**d.get("features", {})),
            raw=d.get("raw", {}),
            channel_hint=d.get("channel_hint"),
            mesh_node_id=d.get("mesh_node_id"),
        )
