"""Tests for the local message bus."""
import asyncio

import pytest

from watchtower.bus import Bus
from watchtower.events import Event, EventKind, Features, Scanner


def _ev() -> Event:
    return Event(scanner=Scanner.BLE, kind=EventKind.BLE_ADV, features=Features(rssi=-50))


async def test_bus_delivers_to_one_subscriber():
    bus = Bus()
    received: list[Event] = []

    async def consumer(ev):
        received.append(ev)

    bus.subscribe(consumer)
    await bus.publish(_ev())
    await bus.drain(timeout=1.0)
    assert len(received) == 1
    assert received[0].kind == EventKind.BLE_ADV


async def test_bus_delivers_to_multiple_subscribers():
    bus = Bus()
    a, b = [], []
    bus.subscribe(lambda ev: a.append(ev))
    bus.subscribe(lambda ev: b.append(ev))
    await bus.publish(_ev())
    await bus.drain(timeout=1.0)
    assert len(a) == 1
    assert len(b) == 1


async def test_bus_isolates_failing_subscriber():
    bus = Bus()
    received_b: list[Event] = []

    def bad(ev):
        raise RuntimeError("boom")

    async def good(ev):
        received_b.append(ev)

    bus.subscribe(bad)
    bus.subscribe(good)
    await bus.publish(_ev())
    await bus.drain(timeout=1.0)
    # good subscriber still received despite bad raising
    assert len(received_b) == 1


async def test_bus_supports_sync_and_async_subscribers():
    bus = Bus()
    sync_recv, async_recv = [], []
    bus.subscribe(lambda ev: sync_recv.append(ev))

    async def a(ev):
        async_recv.append(ev)

    bus.subscribe(a)
    await bus.publish(_ev())
    await bus.drain(timeout=1.0)
    assert sync_recv and async_recv
