"""Tests for the SQLite local sink."""
import asyncio
import json
import sqlite3
from pathlib import Path

import pytest

from watchtower.events import Event, EventKind, Features, Scanner
from watchtower.sinks.local import LocalSink
from watchtower.storage.db import init_db


def _ev(rssi: int = -50) -> Event:
    return Event(
        scanner=Scanner.BLE,
        kind=EventKind.BLE_ADV,
        features=Features(rssi=rssi, mac="aa:bb:cc:dd:ee:ff"),
        raw={"k": "v"},
    )


async def test_sink_writes_single_event(tmp_path: Path):
    db = tmp_path / "t.db"
    init_db(db)
    sink = LocalSink(db, batch_size=1, flush_interval=0.1)
    await sink.start()
    await sink.write(_ev())
    await sink.flush()
    await sink.stop()
    with sqlite3.connect(db) as conn:
        n = conn.execute("SELECT COUNT(*) FROM raw_events").fetchone()[0]
    assert n == 1


async def test_sink_batches_then_flushes(tmp_path: Path):
    db = tmp_path / "t.db"
    init_db(db)
    sink = LocalSink(db, batch_size=10, flush_interval=10.0)
    await sink.start()
    for i in range(5):
        await sink.write(_ev(rssi=-50 - i))
    # batch_size not yet reached, but explicit flush forces write
    await sink.flush()
    await sink.stop()
    with sqlite3.connect(db) as conn:
        n = conn.execute("SELECT COUNT(*) FROM raw_events").fetchone()[0]
    assert n == 5


async def test_sink_retries_batch_after_database_lock(tmp_path: Path, monkeypatch):
    db = tmp_path / "t.db"
    init_db(db)
    sink = LocalSink(db, batch_size=1, flush_interval=10.0)
    real_write = sink._write_rows
    attempts = 0

    def locked_once(rows):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise sqlite3.OperationalError("database is locked")
        real_write(rows)

    monkeypatch.setattr(sink, "_write_rows", locked_once)
    await sink.start()
    await sink.write(_ev())
    assert len(sink._buf) == 1
    await sink.flush()
    await sink.stop()

    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM raw_events").fetchone()[0] == 1
    assert attempts == 2


async def test_sink_persists_features_and_raw(tmp_path: Path):
    db = tmp_path / "t.db"
    init_db(db)
    sink = LocalSink(db, batch_size=1, flush_interval=0.1)
    await sink.start()
    e = _ev()
    await sink.write(e)
    await sink.flush()
    await sink.stop()
    with sqlite3.connect(db) as conn:
        row = conn.execute(
            "SELECT event_id, scanner, kind, features_json, raw_json FROM raw_events"
        ).fetchone()
    assert row[0] == e.event_id
    assert row[1] == "ble_scanner"
    assert row[2] == "ble_adv"
    feats = json.loads(row[3])
    assert feats["rssi"] == -50
    assert feats["mac"] == "aa:bb:cc:dd:ee:ff"
    assert json.loads(row[4]) == {"k": "v"}


async def test_sink_retires_legacy_entity_for_bluez_random_address(tmp_path: Path):
    db = tmp_path / "t.db"
    init_db(db)
    with sqlite3.connect(db) as conn:
        conn.execute(
            """INSERT INTO entities
                   (entity_id,scanner,kind,first_seen_unix,last_seen_unix,is_random_mac)
               VALUES ('ble:mac:aa:bb:cc:dd:ee:ff','ble_scanner','ble_device',1,1,0)"""
        )
    sink = LocalSink(db, batch_size=1, flush_interval=10.0)
    await sink.start()
    event = _ev()
    event.features.address_type = "random"
    event.features.is_random_mac = True
    await sink.write(event)
    await sink.stop()
    with sqlite3.connect(db) as conn:
        row = conn.execute(
            """SELECT is_random_mac, notes_inferred FROM entities
               WHERE entity_id = 'ble:mac:aa:bb:cc:dd:ee:ff'"""
        ).fetchone()
    assert row == (1, "Legacy rotating BLE privacy address")
