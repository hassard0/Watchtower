-- Watchtower schema v1.
-- raw_events stores every scan event for the retention window (default 7d).

CREATE TABLE IF NOT EXISTS schema_meta (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS raw_events (
    event_id      TEXT PRIMARY KEY,            -- ULID, time-sortable
    ts            TEXT NOT NULL,               -- ISO-8601 UTC
    ts_unix       INTEGER NOT NULL,            -- epoch seconds, indexed for prune
    scanner       TEXT NOT NULL,               -- e.g. "ble_scanner"
    kind          TEXT NOT NULL,               -- e.g. "ble_adv"
    features_json TEXT NOT NULL,               -- JSON-encoded Features dict
    raw_json      TEXT NOT NULL                -- JSON-encoded raw scanner output
);

CREATE INDEX IF NOT EXISTS idx_raw_events_ts_unix ON raw_events(ts_unix);
CREATE INDEX IF NOT EXISTS idx_raw_events_scanner_kind ON raw_events(scanner, kind);
CREATE INDEX IF NOT EXISTS idx_raw_events_mac ON raw_events(json_extract(features_json, '$.mac'));

-- Initial version row inserted only if absent.
INSERT OR IGNORE INTO schema_meta(version) VALUES (1);
