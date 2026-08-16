"""BLE scanner using bleak.

Subscribes to all BLE advertisements within range and emits one Event per
advertisement seen. Does not actively connect to devices (passive only).
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from bleak import BleakScanner

from watchtower.events import Event, EventKind, Features
from watchtower.events import Scanner as ScannerName
from watchtower.flipper import detect_flipper_zero
from watchtower.location_trackers import detect_location_tracker
from watchtower.scanners.base import Scanner

log = logging.getLogger(__name__)


def _is_random_mac(mac: str) -> bool:
    """The locally-administered bit (bit 1 of MSB) flags random/non-OUI MACs."""
    try:
        first = int(mac.split(":")[0], 16)
    except (IndexError, ValueError):
        return False
    return bool(first & 0x02)


# Minimal seed table covering well-known historical OUIs. The full IEEE OUI
# database (~50k entries) is loaded via watchtower.oui.vendor_for_mac() — we
# fall back to this seed table if that lookup misses (e.g., older bundled DB).
_OUI_SEED: dict[str, str] = {
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
    if not mac:
        return None
    # Try the full IEEE OUI database first.
    try:
        from watchtower.oui import vendor_for_mac
        v = vendor_for_mac(mac)
        if v:
            return v
    except Exception:  # noqa: BLE001
        pass
    # Fall back to the small seed table.
    if len(mac) < 8:
        return None
    return _OUI_SEED.get(mac[:8].lower())


def _mfr_data_to_hex(data: dict[int, bytes]) -> str | None:
    if not data:
        return None
    # Concatenate vendor_id (LE 16-bit) + payload for each entry.
    parts = []
    for vid, payload in data.items():
        parts.append(vid.to_bytes(2, "little").hex() + payload.hex())
    return "".join(parts)


def _encrypted_ad_data(platform_data: Any) -> list[str]:
    """Extract raw AD type 0x31 exposed by Bleak's BlueZ backend.

    Bleak intentionally normalizes only common AD types. BlueZ retains the
    remaining types in Device1.AdvertisingData, available through
    AdvertisementData.platform_data as ``(object_path, properties)``.
    """
    try:
        props = platform_data[1]
        advertising = props.get("AdvertisingData", {})
    except (IndexError, KeyError, TypeError, AttributeError):
        return []
    out: list[str] = []
    for key, value in getattr(advertising, "items", lambda: [])():
        try:
            ad_type = int(getattr(key, "value", key))
            raw = getattr(value, "value", value)
            if ad_type == 0x31:
                out.append(bytes(raw).hex())
        except (TypeError, ValueError):
            continue
    return out


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
        # Coordination with active GATT prober — when "paused", the scanner
        # stops its BleakScanner so something else (the prober) can use the
        # adapter exclusively.
        self._pause_lock = asyncio.Lock()
        self._scanner_instance = None

    async def pause_for_probe(self):
        """Async context manager: pause scanning while the body runs.

        BlueZ on a single adapter doesn't reliably allow concurrent passive
        scanning + outgoing GATT connect, so the prober uses this to take
        exclusive access for a few seconds.
        """
        from contextlib import asynccontextmanager
        scanner = self
        @asynccontextmanager
        async def _ctx():
            async with scanner._pause_lock:
                paused = False
                if scanner._scanner_instance is not None:
                    try:
                        await scanner._scanner_instance.stop()
                        paused = True
                    except Exception:  # noqa: BLE001
                        log.exception("ble: failed to pause scanner for probe")
                try:
                    yield
                finally:
                    if paused and scanner._scanner_instance is not None:
                        try:
                            await scanner._scanner_instance.start()
                        except Exception:  # noqa: BLE001
                            log.exception("ble: failed to resume scanner after probe")
        return _ctx()

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        import time as _time

        def cb(device: Any, adv: Any) -> None:
            try:
                mac = device.address
                rssi = int(adv.rssi) if adv.rssi is not None else None
                services = list(adv.service_uuids or [])
                service_data = {str(k): v.hex() for k, v in (adv.service_data or {}).items()}
                mfr_hex = _mfr_data_to_hex(adv.manufacturer_data or {})
                ead_hex = _encrypted_ad_data(getattr(adv, "platform_data", ()))
                local_name = adv.local_name or device.name
                # Dedupe key: same MAC + same advertisement content.
                # RSSI is excluded so RSSI fluctuations don't bypass dedup;
                # we'll capture RSSI changes when the window expires.
                # Dedup hash uses STABLE parts only — rotating bytes (cryptographic
                # keys in Apple Continuity, counters in some Samsung msgs) bypass
                # dedup if included. Use vendor-id + sub-type only (first 6 hex chars).
                mfr_stable = mfr_hex[:6] if mfr_hex else ""
                service_stable = tuple(sorted((k, v[:4]) for k, v in service_data.items()))
                content = (mac, hash((tuple(services), service_stable, mfr_stable, local_name)))
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

                signature = detect_flipper_zero(local_name, services)
                tracker = detect_location_tracker(local_name, services, service_data, mfr_hex)
                decoded = {}
                if mfr_hex.lower().startswith("4c00"):
                    from watchtower.apple_continuity import decode_continuity
                    continuity = decode_continuity(mfr_hex)
                    if continuity:
                        decoded["apple_continuity"] = continuity
                if signature:
                    decoded["device_detection"] = signature
                if tracker:
                    decoded["location_tracker"] = tracker
                feats = Features(
                    mac=mac,
                    rssi=rssi,
                    tx_power=int(adv.tx_power) if adv.tx_power is not None else None,
                    vendor_oui=_vendor_for_oui(mac),
                    is_random_mac=_is_random_mac(mac),
                    service_uuids=services,
                    service_data_hex=service_data,
                    manufacturer_data_hex=mfr_hex,
                    encrypted_ad_data_hex=ead_hex,
                    local_name=local_name,
                    decoded=decoded,
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
                        "service_data": service_data,
                        "manufacturer_data": {
                            str(k): v.hex() for k, v in (adv.manufacturer_data or {}).items()
                        },
                        "encrypted_ad_data": ead_hex,
                    },
                )
                # Schedule async emit from sync callback context.
                asyncio.run_coroutine_threadsafe(self._emit(ev), loop)
            except Exception:  # noqa: BLE001
                log.exception("ble cb failed")

        scanner = BleakScanner(detection_callback=cb, adapter=self._adapter)
        self._scanner_instance = scanner
        await scanner.start()
        try:
            # Stay alive until stopped.
            await self._stop_event.wait()
        finally:
            self._scanner_instance = None
            try:
                await scanner.stop()
            except Exception:  # noqa: BLE001
                log.exception("BleakScanner.stop failed")
