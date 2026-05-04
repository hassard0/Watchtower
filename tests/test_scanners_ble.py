"""Tests for BLE scanner — uses bleak mocks."""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from watchtower.events import EventKind, Scanner as ScannerName
from watchtower.scanners.ble import BleScanner


def _fake_device(address: str = "aa:bb:cc:dd:ee:ff", name: str | None = "iPhone"):
    d = MagicMock()
    d.address = address
    d.name = name
    return d


def _fake_advertisement(rssi: int = -55, tx_power: int | None = -8,
                        service_uuids: list[str] | None = None,
                        manufacturer_data: dict[int, bytes] | None = None,
                        local_name: str | None = "iPhone"):
    a = MagicMock()
    a.rssi = rssi
    a.tx_power = tx_power
    a.service_uuids = service_uuids or ["fd6f"]
    a.manufacturer_data = manufacturer_data or {0x004C: bytes.fromhex("1005")}
    a.local_name = local_name
    return a


async def test_ble_scanner_emits_on_advertisement():
    received = []

    with patch("watchtower.scanners.ble.BleakScanner") as MockScanner:
        instance = MockScanner.return_value
        instance.start = AsyncMock()
        instance.stop = AsyncMock()
        # capture the detection callback
        captured: dict[str, callable] = {}
        def _ctor(*args, **kwargs):
            captured["cb"] = kwargs.get("detection_callback") or (args[0] if args else None)
            return instance
        MockScanner.side_effect = _ctor

        s = BleScanner()
        s.on_event(lambda ev: received.append(ev))
        runner = asyncio.create_task(s.start())
        await asyncio.sleep(0.05)
        # invoke the captured detection callback as bleak would
        cb = captured["cb"]
        cb(_fake_device(), _fake_advertisement())
        await asyncio.sleep(0.05)
        await s.stop()
        runner.cancel()
        try:
            await runner
        except asyncio.CancelledError:
            pass

    assert len(received) == 1
    e = received[0]
    assert e.scanner == ScannerName.BLE
    assert e.kind == EventKind.BLE_ADV
    assert e.features.mac == "aa:bb:cc:dd:ee:ff"
    assert e.features.rssi == -55
    assert e.features.tx_power == -8
    assert e.features.service_uuids == ["fd6f"]
    assert e.features.manufacturer_data_hex.lower().startswith("4c00") or \
           e.features.manufacturer_data_hex.lower().startswith("004c")
    assert e.features.local_name == "iPhone"


def test_ble_is_random_mac_detection():
    from watchtower.scanners.ble import _is_random_mac
    # locally-administered bit (bit 1 of first byte) set => random
    assert _is_random_mac("ca:bb:cc:dd:ee:ff") is True   # first byte 0xCA, bit1=1
    assert _is_random_mac("aa:bb:cc:dd:ee:ff") is True   # 0xAA bit1=1
    assert _is_random_mac("a8:bb:cc:dd:ee:ff") is False  # 0xA8 bit1=0
    assert _is_random_mac("00:1A:11:22:33:44") is False  # 0x00 bit1=0


def test_ble_vendor_oui_lookup():
    from watchtower.scanners.ble import _vendor_for_oui
    # OUI list is small and we don't depend on it being exhaustive in M1;
    # just confirm the function returns None for unknown without raising.
    assert _vendor_for_oui("00:00:00") in (None, "Xerox")  # 00:00:00 historically Xerox
    assert _vendor_for_oui("zz:zz:zz") is None
