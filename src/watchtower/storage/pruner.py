"""Retention pruner. Deletes raw_events older than retention window."""
from __future__ import annotations

import logging
import time
from pathlib import Path

from watchtower.storage.db import get_connection

log = logging.getLogger(__name__)


def prune_older_than(db_path: Path | str, retention_seconds: int) -> int:
    """Delete raw_events with ts_unix older than `now - retention_seconds`.

    Returns the count of deleted rows.
    """
    cutoff = int(time.time()) - retention_seconds
    with get_connection(db_path) as conn:
        cur = conn.execute("DELETE FROM raw_events WHERE ts_unix < ?", (cutoff,))
        deleted = cur.rowcount or 0
        # M1 does not VACUUM — pages are reused over the steady-state 7-day window
        # so file size stabilizes naturally. Periodic vacuum is M5 ops cleanup.
    if deleted:
        log.info("pruner: deleted %d rows older than %d (cutoff=%d)", deleted, retention_seconds, cutoff)
    return deleted
