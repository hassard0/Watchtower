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
    """Yield a SQLite connection with PRAGMAs set sensibly for the daemon."""
    conn = sqlite3.connect(str(db_path), isolation_level=None)  # autocommit
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA busy_timeout = 5000")
        yield conn
    finally:
        conn.close()


def init_db(db_path: Path | str) -> None:
    """Create the database file and apply the schema if not already present."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with get_connection(db_path) as conn:
        conn.executescript(_load_schema_sql())


def schema_version(db_path: Path | str) -> int:
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT version FROM schema_meta").fetchone()
    return int(row[0]) if row else 0
