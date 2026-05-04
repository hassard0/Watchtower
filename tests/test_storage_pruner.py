"""Tests for retention pruner."""
import time
from pathlib import Path

import pytest

from watchtower.events import Event, EventKind, Features, Scanner
from watchtower.sinks.local import LocalSink
from watchtower.storage.db import get_connection, init_db
from watchtower.storage.pruner import prune_older_than


def _seed_events(db: Path, count: int, ts_unix: int) -> None:
    """Seed `count` raw_events at the given epoch ts."""
    rows = []
    for i in range(count):
        rows.append((
            f"01HF{ts_unix:010d}{i:010d}",                  # fake ULID-shaped id, unique per ts_unix
            "2026-05-03T22:41:13+00:00",
            ts_unix,
            "ble_scanner", "ble_adv", "{}", "{}",
        ))
    with get_connection(db) as conn:
        conn.executemany(
            "INSERT INTO raw_events VALUES (?, ?, ?, ?, ?, ?, ?)", rows
        )


def test_prune_deletes_old_events(tmp_path: Path):
    db = tmp_path / "t.db"
    init_db(db)
    now = int(time.time())
    _seed_events(db, 5, now - 8 * 86400)   # 8 days old, should be pruned
    _seed_events(db, 3, now - 1 * 86400)   # 1 day old, kept
    n_pruned = prune_older_than(db, retention_seconds=7 * 86400)
    assert n_pruned == 5
    with get_connection(db) as conn:
        remaining = conn.execute("SELECT COUNT(*) FROM raw_events").fetchone()[0]
    assert remaining == 3


def test_prune_noop_when_nothing_old(tmp_path: Path):
    db = tmp_path / "t.db"
    init_db(db)
    now = int(time.time())
    _seed_events(db, 3, now - 86400)
    assert prune_older_than(db, retention_seconds=7 * 86400) == 0


def test_prune_returns_zero_on_empty_db(tmp_path: Path):
    db = tmp_path / "t.db"
    init_db(db)
    assert prune_older_than(db, retention_seconds=7 * 86400) == 0
