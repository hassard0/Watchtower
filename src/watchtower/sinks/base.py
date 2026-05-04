"""Sink abstract interface."""
from __future__ import annotations

from abc import ABC, abstractmethod

from watchtower.events import Event


class Sink(ABC):
    @abstractmethod
    async def start(self) -> None: ...
    @abstractmethod
    async def stop(self) -> None: ...
    @abstractmethod
    async def write(self, ev: Event) -> None: ...
    @abstractmethod
    async def flush(self) -> None: ...
