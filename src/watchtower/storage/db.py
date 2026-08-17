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
        entity_columns = {row[1] for row in conn.execute("PRAGMA table_info(entities)")}
        entity_migrations = {
            "friendly_name_source": "TEXT",
            "friendly_name_confidence": "REAL",
            "friendly_name_updated_unix": "INTEGER",
        }
        for name, declaration in entity_migrations.items():
            if name not in entity_columns:
                conn.execute(f"ALTER TABLE entities ADD COLUMN {name} {declaration}")
        # Preserve pre-v7 labels as candidates.  Their provenance is unknown,
        # so they remain replaceable by a stronger standardized observation.
        conn.execute(
            """UPDATE entities
               SET friendly_name_source = 'legacy',
                   friendly_name_confidence = 0.60,
                   friendly_name_updated_unix = COALESCE(friendly_name_updated_unix, last_seen_unix)
               WHERE friendly_name IS NOT NULL AND friendly_name_source IS NULL"""
        )
        conn.execute(
            """INSERT OR IGNORE INTO entity_name_candidates
                   (entity_id, name, source, confidence, first_seen_unix, last_seen_unix, evidence_json)
               SELECT entity_id, friendly_name, 'legacy', 0.60,
                      first_seen_unix, COALESCE(friendly_name_updated_unix, last_seen_unix), '{}'
               FROM entities WHERE friendly_name IS NOT NULL"""
        )
        from watchtower.name_resolution import (
            backfill_apple_audio_groups,
            revalidate_name_candidates,
        )
        revalidate_name_candidates(conn)
        backfill_apple_audio_groups(conn)
        # Older builds promoted every rtl_433 decode immediately.  Move only
        # untouched singletons back to the repeat-confirmation queue; raw
        # observations and user-classified/named entities are preserved.
        conn.execute(
            """INSERT OR IGNORE INTO entity_candidates
                   (entity_id, scanner, kind, first_seen_unix, last_seen_unix,
                    observation_count)
               SELECT entity_id, scanner, kind, first_seen_unix, last_seen_unix,
                      total_observations
               FROM entities
               WHERE scanner = 'subghz_scanner'
                 AND total_observations <= 1
                 AND classification IS NULL
                 AND friendly_name IS NULL"""
        )
        conn.execute(
            """DELETE FROM entities
               WHERE scanner = 'subghz_scanner'
                 AND total_observations <= 1
                 AND classification IS NULL
                 AND friendly_name IS NULL"""
        )


def schema_version(db_path: Path | str) -> int:
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT version FROM schema_meta").fetchone()
    return int(row[0]) if row else 0
