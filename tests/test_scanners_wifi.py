"""Tests for WiFi scanner — stub mode when no adapter is present."""
import asyncio
from pathlib import Path

import pytest

from watchtower.scanners.wifi import WifiScanner, _adapter_present


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
