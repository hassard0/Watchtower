"""Tests for storage/db.py — schema setup and connection helper."""
import sqlite3
from pathlib import Path

import pytest

from watchtower.storage.db import init_db, get_connection, schema_version


def test_init_db_creates_raw_events_table(tmp_path: Path):
    db = tmp_path / "test.db"
    init_db(db)
    with get_connection(db) as conn:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
    names = [r[0] for r in rows]
    assert "raw_events" in names
    assert "schema_meta" in names


def test_init_db_is_idempotent(tmp_path: Path):
    db = tmp_path / "test.db"
    init_db(db)
    init_db(db)  # second call must not fail
    with get_connection(db) as conn:
        v = conn.execute("SELECT version FROM schema_meta").fetchone()
    assert v[0] == 1


def test_raw_events_columns(tmp_path: Path):
    db = tmp_path / "test.db"
    init_db(db)
    with get_connection(db) as conn:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(raw_events)")}
    expected = {"event_id", "ts", "ts_unix", "scanner", "kind", "features_json", "raw_json"}
    assert expected.issubset(cols)


def test_get_connection_enables_foreign_keys(tmp_path: Path):
    db = tmp_path / "test.db"
    init_db(db)
    with get_connection(db) as conn:
        v = conn.execute("PRAGMA foreign_keys").fetchone()[0]
    assert v == 1


def test_schema_version_returns_int(tmp_path: Path):
    db = tmp_path / "test.db"
    init_db(db)
    assert schema_version(db) == 1
