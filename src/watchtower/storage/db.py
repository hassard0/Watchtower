"""SQLite connection helper and schema bootstrap."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from importlib import resources
from pathlib import Path
from typing import Iterator


def _load_schema_sql() -> str:
    return resources.files("watchtower.storage").joinpath("schema.sql").read_text(encoding="utf-8")


@contextmanager
def get_connection(db_path: Path | str) -> Iterator[sqlite3.Connection]:
    """Yield a SQLite connection with PRAGMAs set sensibly for the daemon.

    The DB grows to several hundred MB inside a day from BLE adv volume, so
    each fresh connection without a healthy page cache + memory map made
    /api/entities and /api/findmy/* take ~2.7 s — blocking the asyncio loop.
    The mmap_size + cache_size pragmas push that down by an order of magnitude
    by letting the kernel/page-cache do most of the read work.
    """
    conn = sqlite3.connect(str(db_path), isolation_level=None, timeout=15.0)  # autocommit
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        # Setting journal_mode on every short-lived connection competes with
        # active writers. Only change it when bootstrapping a non-WAL DB.
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        if str(mode).lower() != "wal":
            conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA busy_timeout = 15000")
        conn.execute("PRAGMA cache_size = -65536")   # 64 MB page cache
        conn.execute("PRAGMA mmap_size = 268435456")  # 256 MB memory map
        conn.execute("PRAGMA temp_store = MEMORY")
        yield conn
    finally:
        conn.close()


def init_db(db_path: Path | str) -> None:
    """Create the database file and apply the schema if not already present."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with get_connection(db_path) as conn:
        conn.executescript(_load_schema_sql())
        columns = {row[1] for row in conn.execute("PRAGMA table_info(findmy_clusters)")}
        migrations = {
            "tracker_family": "TEXT NOT NULL DEFAULT 'apple_findmy'",
            "network_provider": "TEXT",
            "near_owner": "INTEGER",
        }
        for name, declaration in migrations.items():
            if name not in columns:
                conn.execute(f"ALTER TABLE findmy_clusters ADD COLUMN {name} {declaration}")


def schema_version(db_path: Path | str) -> int:
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT version FROM schema_meta").fetchone()
    return int(row[0]) if row else 0
