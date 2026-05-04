"""BLE scanner using bleak.

Subscribes to all BLE advertisements within range and emits one Event per
advertisement seen. Does not actively connect to devices (passive only).
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from bleak import BleakScanner

from watchtower.events import Event, EventKind, Features, Scanner as ScannerName
from watchtower.scanners.base import Scanner

log = logging.getLogger(__name__)


def _is_random_mac(mac: str) -> bool:
    """The locally-administered bit (bit 1 of MSB) flags random/non-OUI MACs."""
    try:
        first = int(mac.split(":")[0], 16)
    except (IndexError, ValueError):
        return False
    return bool(first & 0x02)


# Minimal vendor OUI table for v1 (top consumer brands).
# Full IEEE OUI registry will be downloaded at install time in a future task.
_OUI: dict[str, str] = {
    "00:00:00": "Xerox",
    "ac:de:48": "Apple",
    "f4:5c:89": "Apple",
    "fc:fc:48": "Apple",
    "00:18:b4": "Samsung",
    "08:08:c2": "Samsung",
    "94:eb:cd": "Google",
    "7c:9d:f0": "Google",
}


def _vendor_for_oui(mac: str) -> str | None:
    if not mac or len(mac) < 8:
        return None
    return _OUI.get(mac[:8].lower())


def _mfr_data_to_hex(data: dict[int, bytes]) -> str | None:
    if not data:
        return None
    # Concatenate vendor_id (LE 16-bit) + payload for each entry.
    parts = []
    for vid, payload in data.items():
        parts.append(vid.to_bytes(2, "little").hex() + payload.hex())
    return "".join(parts)


class BleScanner(Scanner):
    name = ScannerName.BLE

    def __init__(self, adapter: str | None = "hci0") -> None:
        super().__init__()
        self._adapter = adapter

    async def run(self) -> None:
        loop = asyncio.get_running_loop()

        def cb(device: Any, adv: Any) -> None:
            try:
                feats = Features(
                    mac=device.address,
                    rssi=int(adv.rssi) if adv.rssi is not None else None,
                    tx_power=int(adv.tx_power) if adv.tx_power is not None else None,
                    vendor_oui=_vendor_for_oui(device.address),
                    is_random_mac=_is_random_mac(device.address),
                    service_uuids=list(adv.service_uuids or []),
                    manufacturer_data_hex=_mfr_data_to_hex(adv.manufacturer_data or {}),
                    local_name=adv.local_name or device.name,
                )
                ev = Event(
                    scanner=ScannerName.BLE,
                    kind=EventKind.BLE_ADV,
                    features=feats,
                    raw={
                        "address": device.address,
                        "name": device.name,
                        "rssi": adv.rssi,
                        "tx_power": adv.tx_power,
                        "service_uuids": list(adv.service_uuids or []),
                        "manufacturer_data": {
                            str(k): v.hex() for k, v in (adv.manufacturer_data or {}).items()
                        },
                    },
                )
                # Schedule async emit from sync callback context.
                asyncio.run_coroutine_threadsafe(self._emit(ev), loop)
            except Exception:  # noqa: BLE001
                log.exception("ble cb failed")

        scanner = BleakScanner(detection_callback=cb, adapter=self._adapter)
        await scanner.start()
        try:
            # Stay alive until stopped.
            await self._stop_event.wait()
        finally:
            try:
                await scanner.stop()
            except Exception:  # noqa: BLE001
                log.exception("BleakScanner.stop failed")
