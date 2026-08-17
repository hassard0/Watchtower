"""Scanner abstract base.

A Scanner runs as an awaitable `start()` task and emits `Event`s to all
registered callbacks via `_emit(ev)`. Callbacks may be sync or async.
"""
from __future__ import annotations

import asyncio
import inspect
import logging
from abc import ABC, abstractmethod
from typing import Awaitable, Callable, Union

from watchtower.events import Event, Scanner as ScannerName

log = logging.getLogger(__name__)


class ScannerError(Exception):
    pass


Listener = Union[Callable[[Event], None], Callable[[Event], Awaitable[None]]]


class Scanner(ABC):
    """Long-lived event-producing scanner."""

    name: ScannerName  # subclass sets this

    def __init__(self) -> None:
        self._listeners: list[Listener] = []
        self._stop_event = asyncio.Event()

    def on_event(self, fn: Listener) -> None:
        self._listeners.append(fn)

    async def start(self) -> None:
        self._stop_event.clear()
        runner = asyncio.create_task(self.run())
        stopper = asyncio.create_task(self._stop_event.wait())
        tasks = (runner, stopper)
        try:
            done, _pending = await asyncio.wait(
                tasks,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if runner in done:
                # Awaiting propagates a real scanner exception to the retry
                # loop while preserving normal completion.
                await runner
        finally:
            # start() itself is commonly cancelled during service shutdown.
            # Never orphan the hardware runner or its subprocess in that path.
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def stop(self) -> None:
        self._stop_event.set()

    @abstractmethod
    async def run(self) -> None:
        """Subclass implements the long-lived capture loop."""

    async def _emit(self, ev: Event) -> None:
        for fn in self._listeners:
            try:
                res = fn(ev)
                if inspect.isawaitable(res):
                    await res
            except Exception:  # noqa: BLE001
                log.exception("scanner listener raised; isolated")
