"""Tests for Scanner ABC contract."""
import asyncio

import pytest

from watchtower.events import Event, EventKind, Features, Scanner as ScannerName
from watchtower.scanners.base import Scanner, ScannerError


class FakeScanner(Scanner):
    """In-test scanner that emits one event then stops."""

    name = ScannerName.BLE

    async def run(self) -> None:
        ev = Event(scanner=ScannerName.BLE, kind=EventKind.BLE_ADV, features=Features(rssi=-1))
        await self._emit(ev)
        # stay alive until cancelled
        await asyncio.Event().wait()


async def test_scanner_emits_event():
    received = []
    s = FakeScanner()
    s.on_event(lambda ev: received.append(ev))
    task = asyncio.create_task(s.start())
    await asyncio.sleep(0.05)
    await s.stop()
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    assert len(received) == 1
    assert received[0].kind == EventKind.BLE_ADV


async def test_scanner_supports_async_callbacks():
    received = []

    async def consume(ev):
        received.append(ev)

    s = FakeScanner()
    s.on_event(consume)
    task = asyncio.create_task(s.start())
    await asyncio.sleep(0.05)
    await s.stop()
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    assert len(received) == 1


def test_scanner_error_is_exception():
    assert issubclass(ScannerError, Exception)
