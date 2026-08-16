"""SQLite-backed sink. Batches writes for throughput."""
from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path

from watchtower.events import Event
from watchtower.sinks.base import Sink
from watchtower.storage.db import get_connection

log = logging.getLogger(__name__)

_INSERT_SQL = """
INSERT INTO raw_events (event_id, ts, ts_unix, scanner, kind, features_json, raw_json)
VALUES (?, ?, ?, ?, ?, ?, ?)
"""


class LocalSink(Sink):
    def __init__(
        self,
        db_path: Path | str,
        batch_size: int = 100,
        flush_interval: float = 1.0,
    ) -> None:
        self._db = Path(db_path)
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._buf: list[tuple] = []
        self._lock = asyncio.Lock()
        self._flusher: asyncio.Task | None = None
        self._stopping = False

    async def start(self) -> None:
        self._stopping = False
        self._flusher = asyncio.create_task(self._periodic_flush())

    async def stop(self) -> None:
        self._stopping = True
        if self._flusher:
            self._flusher.cancel()
            try:
                await self._flusher
            except asyncio.CancelledError:
                pass
        await self.flush()

    async def write(self, ev: Event) -> None:
        async with self._lock:
            self._buf.append(self._to_row(ev))
            if len(self._buf) >= self._batch_size:
                await self._flush_locked()

    async def flush(self) -> None:
        async with self._lock:
            await self._flush_locked()

    async def _flush_locked(self) -> None:
        if not self._buf:
            return
        rows, self._buf = self._buf, []
        try:
            await asyncio.to_thread(self._write_rows, rows)
        except sqlite3.OperationalError as exc:
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                # A busy analytics pass should delay capture persistence, not
                # lose observations. Preserve ordering and retry next flush.
                self._buf = rows + self._buf
                log.exception("local sink flush deferred; %d events queued for retry", len(rows))
            else:
                log.exception("local sink flush failed; %d events lost", len(rows))
        except Exception:  # noqa: BLE001
            log.exception("local sink flush failed; %d events lost", len(rows))

    def _write_rows(self, rows: list[tuple]) -> None:
        with get_connection(self._db) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.executemany(_INSERT_SQL, rows)
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

    async def _periodic_flush(self) -> None:
        try:
            while not self._stopping:
                await asyncio.sleep(self._flush_interval)
                await self.flush()
        except asyncio.CancelledError:
            pass

    @staticmethod
    def _to_row(ev: Event) -> tuple:
        ts_unix = int(datetime.fromisoformat(ev.ts).timestamp())
        # Features is a dataclass; asdict via to_dict pulls already-serialized form
        d = ev.to_dict()
        return (
            ev.event_id,
            ev.ts,
            ts_unix,
            d["scanner"],
            d["kind"],
            json.dumps(d["features"], default=str),
            json.dumps(d["raw"], default=str),
        )
