-- Watchtower schema.
-- v1: raw_events
-- v2: entities, entity_visits, baseline_stats, alerts (M2-lite + M3-lite)

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

-- v2: entity tracking + analytics

-- One row per stable identity. M2-lite: keyed by MAC for now (random-MAC defeat is M2-full work).
CREATE TABLE IF NOT EXISTS entities (
    entity_id        TEXT PRIMARY KEY,         -- "ble:aa:bb:cc:dd:ee:ff" or "subghz:Honda-CarRemote:0x123"
    scanner          TEXT NOT NULL,
    kind             TEXT NOT NULL,            -- ble_phone, ble_tag, ble_unknown, subghz_keyfob, ...
    first_seen_unix  INTEGER NOT NULL,
    last_seen_unix   INTEGER NOT NULL,
    visit_count      INTEGER NOT NULL DEFAULT 0,
    total_observations INTEGER NOT NULL DEFAULT 0,
    classification   TEXT,                     -- null | anchor | satellite | known_guest | untrusted
    friendly_name    TEXT,                     -- user-set label
    vendor           TEXT,                     -- inferred from OUI / mfr data
    is_random_mac    INTEGER,                  -- 0/1; null if N/A
    avg_rssi         REAL,
    min_rssi         INTEGER,
    max_rssi         INTEGER,
    regularity       REAL,                     -- 0..1; 1 = perfectly regular visitor
    anomaly_score    REAL,                     -- 0..1; 1 = highly anomalous
    last_anomaly_at  INTEGER,                  -- epoch when anomaly score last bumped
    notes_inferred   TEXT
);
CREATE INDEX IF NOT EXISTS idx_entities_last_seen ON entities(last_seen_unix);
CREATE INDEX IF NOT EXISTS idx_entities_classification ON entities(classification);
CREATE INDEX IF NOT EXISTS idx_entities_anomaly ON entities(anomaly_score);

-- A "visit" is a contiguous window where an entity is present (gap < 5 min splits visits).
CREATE TABLE IF NOT EXISTS entity_visits (
    visit_id      TEXT PRIMARY KEY,            -- ULID
    entity_id     TEXT NOT NULL,
    start_unix    INTEGER NOT NULL,
    end_unix      INTEGER NOT NULL,
    duration_sec  INTEGER NOT NULL,
    observation_count INTEGER NOT NULL,
    avg_rssi      REAL,
    max_rssi      INTEGER,
    FOREIGN KEY (entity_id) REFERENCES entities(entity_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_visits_entity ON entity_visits(entity_id);
CREATE INDEX IF NOT EXISTS idx_visits_start ON entity_visits(start_unix);

-- Per (feature, hour-of-week) running statistics. ~12 features × 168 hours = ~2000 rows.
-- Welford's online mean+variance.
CREATE TABLE IF NOT EXISTS baseline_stats (
    feature       TEXT NOT NULL,               -- "ble_unique_count", "midband_900MHz_dbm", etc.
    hour_of_week  INTEGER NOT NULL,            -- 0..167 (Mon 00 = 0, Sun 23 = 167)
    n             INTEGER NOT NULL DEFAULT 0,
    mean          REAL NOT NULL DEFAULT 0,
    m2            REAL NOT NULL DEFAULT 0,     -- sum of squared deviations
    last_updated_unix INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (feature, hour_of_week)
);

-- Fired alerts (rules + baseline). Indefinite retention.
CREATE TABLE IF NOT EXISTS alerts (
    alert_id      TEXT PRIMARY KEY,            -- ULID
    ts_unix       INTEGER NOT NULL,
    rule_id       TEXT NOT NULL,               -- "anchor_absent_unknown_linger", "baseline_deviation", etc.
    severity      TEXT NOT NULL,               -- critical | high | medium | low
    entity_id     TEXT,                        -- null for baseline-only alerts
    score         REAL,                        -- final detection_score
    surprisal     REAL,                        -- per-minute observation surprisal
    home_state    TEXT,                        -- "home" | "away" | "unknown"
    evidence_json TEXT NOT NULL,               -- full evidence blob
    acknowledged  INTEGER NOT NULL DEFAULT 0,
    user_feedback INTEGER                      -- null | 1 (useful) | -1 (false positive)
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts_unix);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_unack ON alerts(acknowledged) WHERE acknowledged = 0;

-- Bookkeeping for analytics rollups (so we don't reprocess events).
CREATE TABLE IF NOT EXISTS analytics_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_unix INTEGER NOT NULL DEFAULT 0
);

-- Set schema version to 2 (idempotent migration from v1).
DELETE FROM schema_meta WHERE version < 2;
INSERT OR IGNORE INTO schema_meta(version) VALUES (2);
