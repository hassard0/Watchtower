"""Tests for WiFi scanner — stub mode when no adapter is present."""
import asyncio
from pathlib import Path

import pytest

from watchtower.scanners.wifi import WifiScanner, _adapter_present, _parse_iw_scan


def test_adapter_present_returns_false_for_missing_iface(tmp_path: Path):
    # /sys/class/net/<iface> doesn't exist -> False
    assert _adapter_present("zzznonexistent_iface_12345") is False


async def test_wifi_scanner_runs_in_stub_mode_when_iface_missing():
    """If the configured interface doesn't exist, the scanner should
    log a warning and idle without emitting events or crashing."""
    received = []
    s = WifiScanner(interface="zzznonexistent_iface_12345")
    s.on_event(lambda ev: received.append(ev))
    runner = asyncio.create_task(s.start())
    await asyncio.sleep(0.2)
    await s.stop()
    runner.cancel()
    try:
        await runner
    except asyncio.CancelledError:
        pass
    assert received == []  # stub mode emits nothing


def test_iw_scan_extracts_wpa3_and_public_wps_identity_metadata():
    output = """
BSS 02:11:22:33:44:55(on wlan0)
        freq: 5180
        signal: -42.00 dBm
        SSID: Workshop
        RSN:
                * Authentication suites: PSK SAE
        WPS:
                * Manufacturer: Example Networks
                * Model: Router 9000
                * Device name: Workshop AP
"""
    result = _parse_iw_scan(output)
    assert result == [{
        "bssid": "02:11:22:33:44:55",
        "ssid": "Workshop",
        "channel": None,
        "signal": -42.0,
        "freq": 5180,
        "encryption": "WPA3-SAE",
        "manufacturer": "Example Networks",
        "model": "Router 9000",
        "device_name": "Workshop AP",
    }]
