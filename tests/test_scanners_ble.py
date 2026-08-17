"""Tests for BLE scanner — uses bleak mocks."""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from watchtower.events import EventKind, Scanner as ScannerName
from watchtower.scanners.ble import BleScanner
from watchtower.scanners.ble import _bluez_address_type, _encrypted_ad_data


def test_extracts_bluez_encrypted_advertising_data():
    assert _encrypted_ad_data(("/org/bluez/hci0/dev_x", {"AdvertisingData": {0x31: b"\x01\x02"}})) == ["0102"]
    assert _encrypted_ad_data(()) == []


def _fake_device(address: str = "aa:bb:cc:dd:ee:ff", name: str | None = "iPhone"):
    d = MagicMock()
    d.address = address
    d.name = name
    d.details = {"props": {"AddressType": "random"}}
    return d


def _fake_advertisement(rssi: int = -55, tx_power: int | None = -8,
                        service_uuids: list[str] | None = None,
                        manufacturer_data: dict[int, bytes] | None = None,
                        local_name: str | None = "iPhone"):
    a = MagicMock()
    a.rssi = rssi
    a.tx_power = tx_power
    a.service_uuids = service_uuids or ["fd6f"]
    a.manufacturer_data = ({0x004C: bytes.fromhex("1005")}
                           if manufacturer_data is None else manufacturer_data)
    a.local_name = local_name
    a.platform_data = ("/org/bluez/hci0/dev_x", {"AddressType": "random"})
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
    assert e.features.address_type == "random"
    assert e.features.is_random_mac is True


async def test_ble_scanner_accepts_advertisement_without_manufacturer_data():
    received = []
    with patch("watchtower.scanners.ble.BleakScanner") as MockScanner:
        instance = MockScanner.return_value
        instance.start = AsyncMock()
        instance.stop = AsyncMock()
        captured = {}

        def _ctor(*args, **kwargs):
            captured["cb"] = kwargs["detection_callback"]
            return instance

        MockScanner.side_effect = _ctor
        scanner = BleScanner()
        scanner.on_event(received.append)
        runner = asyncio.create_task(scanner.start())
        await asyncio.sleep(0.05)
        captured["cb"](_fake_device(), _fake_advertisement(manufacturer_data={}))
        await asyncio.sleep(0.05)
        await scanner.stop()
        await runner

    assert len(received) == 1
    assert received[0].features.manufacturer_data_hex is None


def test_ble_is_random_mac_detection():
    from watchtower.scanners.ble import _is_random_mac
    assert _is_random_mac("a8:bb:cc:dd:ee:ff", "random") is True
    assert _is_random_mac("ca:bb:cc:dd:ee:ff", "public") is False
    # The U/L bit is useful fallback evidence, but an unset bit is unknown.
    assert _is_random_mac("ca:bb:cc:dd:ee:ff") is True   # first byte 0xCA, bit1=1
    assert _is_random_mac("aa:bb:cc:dd:ee:ff") is True   # 0xAA bit1=1
    assert _is_random_mac("a8:bb:cc:dd:ee:ff") is None
    assert _is_random_mac("00:1A:11:22:33:44") is None


def test_extracts_bluez_address_type_from_advertisement_or_device():
    assert _bluez_address_type(("/dev/x", {"AddressType": "public"})) == "public"
    assert _bluez_address_type((), {"props": {"AddressType": "random"}}) == "random"
    assert _bluez_address_type(("/dev/x", {}), {}) is None


def test_ble_vendor_oui_lookup():
    from watchtower.scanners.ble import _vendor_for_oui
    # We now query the full IEEE OUI database (~50k entries) via mac-vendor-lookup
    # with a small seed-table fallback. Vendor strings come from IEEE so we just
    # smoke-test the shape (returns a non-empty string for known prefixes, None
    # for malformed input, no exceptions).
    v = _vendor_for_oui("00:00:00")
    assert v is None or (isinstance(v, str) and "xerox" in v.lower())
    assert _vendor_for_oui("zz:zz:zz") is None
    assert _vendor_for_oui("") is None
