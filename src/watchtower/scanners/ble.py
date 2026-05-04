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

    # Deduplicate identical advertisements per (mac, content_hash) inside a window.
    # BLE devices spam advertisements every 100-500ms; storing every one is
    # wasteful. We keep the FIRST event per (mac, hash) per DEDUP_WINDOW_SEC,
    # which still yields one event per ~5s per stationary device — plenty
    # for presence tracking and visit segmentation.
    DEDUP_WINDOW_SEC: float = 5.0

    def __init__(self, adapter: str | None = "hci0", dedup_window_sec: float | None = None) -> None:
        super().__init__()
        self._adapter = adapter
        if dedup_window_sec is not None:
            self.DEDUP_WINDOW_SEC = dedup_window_sec
        # last-emitted-at per (mac, content_hash); periodically GC'd.
        self._last_emit: dict[tuple[str, int], float] = {}
        self._last_gc: float = 0.0

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        import time as _time

        def cb(device: Any, adv: Any) -> None:
            try:
                mac = device.address
                rssi = int(adv.rssi) if adv.rssi is not None else None
                services = list(adv.service_uuids or [])
                mfr_hex = _mfr_data_to_hex(adv.manufacturer_data or {})
                local_name = adv.local_name or device.name
                # Dedupe key: same MAC + same advertisement content.
                # RSSI is excluded so RSSI fluctuations don't bypass dedup;
                # we'll capture RSSI changes when the window expires.
                # Dedup hash uses STABLE parts only — rotating bytes (cryptographic
                # keys in Apple Continuity, counters in some Samsung msgs) bypass
                # dedup if included. Use vendor-id + sub-type only (first 6 hex chars).
                mfr_stable = mfr_hex[:6] if mfr_hex else ""
                content = (mac, hash((tuple(services), mfr_stable, local_name)))
                now_ts = _time.monotonic()
                last = self._last_emit.get(content)
                if last is not None and (now_ts - last) < self.DEDUP_WINDOW_SEC:
                    return  # suppress duplicate
                self._last_emit[content] = now_ts
                # Garbage-collect old entries every 60s.
                if now_ts - self._last_gc > 60:
                    cutoff = now_ts - max(60, self.DEDUP_WINDOW_SEC * 12)
                    for k in [k for k, v in self._last_emit.items() if v < cutoff]:
                        self._last_emit.pop(k, None)
                    self._last_gc = now_ts

                feats = Features(
                    mac=mac,
                    rssi=rssi,
                    tx_power=int(adv.tx_power) if adv.tx_power is not None else None,
                    vendor_oui=_vendor_for_oui(mac),
                    is_random_mac=_is_random_mac(mac),
                    service_uuids=services,
                    manufacturer_data_hex=mfr_hex,
                    local_name=local_name,
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
