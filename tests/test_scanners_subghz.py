"""Tests for SubGhzScanner — parses rtl_433 JSON output via mock subprocess."""
import asyncio
import json

import pytest

from watchtower.events import EventKind, Scanner as ScannerName
from watchtower.scanners.subghz import SubGhzScanner, _line_to_event


def test_keyfob_line_to_event():
    line = json.dumps({
        "time": "2026-05-03 22:41:13",
        "model": "Honda-CarRemote",
        "id": "0x123ABC",
        "rolling_code": "0xDEADBEEF",
        "freq": 433.92,
    })
    ev = _line_to_event(line)
    assert ev is not None
    assert ev.scanner == ScannerName.SUBGHZ
    assert ev.kind == EventKind.KEYFOB_EMISSION
    assert ev.features.frequency_hz == 433_920_000
    assert ev.features.protocol == "Honda-CarRemote"
    assert ev.features.decoded["id"] == "0x123ABC"


def test_garage_line_to_event():
    line = json.dumps({
        "time": "2026-05-03 22:41:13",
        "model": "Genie-OverheadDoor",
        "id": "12345",
        "freq": 390.0,
    })
    ev = _line_to_event(line)
    assert ev is not None
    assert ev.kind == EventKind.GARAGE_EMISSION
    assert ev.features.frequency_hz == 390_000_000


def test_unknown_protocol_line_to_event():
    line = json.dumps({
        "time": "2026-05-03 22:41:13",
        "model": "WeatherStationXYZ",
        "freq": 433.92,
    })
    ev = _line_to_event(line)
    assert ev is not None
    assert ev.kind == EventKind.SUBGHZ_PROTOCOL_DECODED


def test_invalid_json_line_returns_none():
    assert _line_to_event("not json at all") is None


def test_non_decoded_status_line_returns_none():
    # rtl_433 sometimes emits status messages — ignore them.
    line = json.dumps({"app": "rtl_433", "version": "23.11"})
    assert _line_to_event(line) is None


async def test_subghz_scanner_consumes_subprocess_lines(monkeypatch):
    """Patch the subprocess to feed canned lines."""
    received = []
    line1 = json.dumps({"model": "Honda-CarRemote", "id": "0xABC", "freq": 433.92})
    line2 = json.dumps({"model": "Genie-OverheadDoor", "id": "55", "freq": 390.0})
    canned = [line1.encode() + b"\n", line2.encode() + b"\n"]

    class FakeStream:
        def __init__(self, lines):
            self._lines = list(lines)

        async def readline(self):
            if self._lines:
                return self._lines.pop(0)
            return b""

    class FakeProc:
        def __init__(self):
            self.stdout = FakeStream(canned)
            self.stderr = FakeStream([])
            self.returncode = None
            self._terminated = False

        def terminate(self):
            self._terminated = True
            self.returncode = 0

        async def wait(self):
            return 0

    async def fake_create_subprocess_exec(*args, **kwargs):
        return FakeProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    s = SubGhzScanner(rtl_433_args=["-F", "json"])
    s.on_event(lambda ev: received.append(ev))
    runner = asyncio.create_task(s.start())
    await asyncio.sleep(0.1)
    await s.stop()
    try:
        await asyncio.wait_for(runner, timeout=1.0)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        runner.cancel()

    assert len(received) == 2
    assert received[0].kind == EventKind.KEYFOB_EMISSION
    assert received[1].kind == EventKind.GARAGE_EMISSION
