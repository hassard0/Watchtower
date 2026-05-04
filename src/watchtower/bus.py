"""In-process pub/sub bus for Event objects.

Implementation note: M1 uses asyncio for simplicity since all scanners are
already coroutine-friendly (bleak is async, pyrtlsdr can be wrapped, rtl_433
output is read line-by-line). multiprocessing.Queue is reserved for cross-process
fan-out which is not needed in M1. Swap is local to this module.
"""
from __future__ import annotations

import asyncio
import inspect
import logging
from typing import Awaitable, Callable, Union

from watchtower.events import Event

log = logging.getLogger(__name__)

Subscriber = Union[Callable[[Event], None], Callable[[Event], Awaitable[None]]]


class Bus:
    def __init__(self, queue_size: int = 10000) -> None:
        self._subs: list[Subscriber] = []
        self._queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=queue_size)
        self._dispatcher_task: asyncio.Task | None = None

    def subscribe(self, fn: Subscriber) -> None:
        self._subs.append(fn)

    async def publish(self, ev: Event) -> None:
        if self._dispatcher_task is None:
            self._dispatcher_task = asyncio.create_task(self._dispatch())
        await self._queue.put(ev)

    async def _dispatch(self) -> None:
        while True:
            ev = await self._queue.get()
            for sub in self._subs:
                try:
                    res = sub(ev)
                    if inspect.isawaitable(res):
                        await res
                except Exception:  # noqa: BLE001
                    log.exception("subscriber raised; isolated")

    async def drain(self, timeout: float = 5.0) -> None:
        """Wait for the queue to empty and dispatcher to settle. For tests."""
        deadline = asyncio.get_event_loop().time() + timeout
        while not self._queue.empty():
            if asyncio.get_event_loop().time() > deadline:
                raise TimeoutError("bus drain timeout")
            await asyncio.sleep(0.01)
        # one more tick so the last in-flight handler can finish
        await asyncio.sleep(0.05)

    async def shutdown(self) -> None:
        if self._dispatcher_task and not self._dispatcher_task.done():
            self._dispatcher_task.cancel()
            try:
                await self._dispatcher_task
            except asyncio.CancelledError:
                pass
