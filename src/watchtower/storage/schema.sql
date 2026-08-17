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
    friendly_name    TEXT,                     -- selected local/user-friendly label
    friendly_name_source TEXT,                 -- user | ble_gatt_device_name | ...
    friendly_name_confidence REAL,             -- 0..1 confidence in selected label
    friendly_name_updated_unix INTEGER,
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

-- Candidate identities must repeat before becoming dashboard devices.  This
-- prevents one-off rtl_433 false decodes from flooding the "new" list while
-- retaining every raw observation for later analysis.
CREATE TABLE IF NOT EXISTS entity_candidates (
    entity_id          TEXT PRIMARY KEY,
    scanner            TEXT NOT NULL,
    kind               TEXT NOT NULL,
    first_seen_unix    INTEGER NOT NULL,
    last_seen_unix     INTEGER NOT NULL,
    observation_count  INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_entity_candidates_last_seen
    ON entity_candidates(last_seen_unix);

-- v10: transient anonymous BLE flows and explainable multi-signal episodes.
-- Tracklets expire quickly and are explicitly not durable device identities.
CREATE TABLE IF NOT EXISTS presence_tracklets (
    tracklet_id        TEXT PRIMARY KEY,
    signature          TEXT NOT NULL,
    label              TEXT NOT NULL,
    first_seen_unix    INTEGER NOT NULL,
    last_seen_unix     INTEGER NOT NULL,
    observation_count  INTEGER NOT NULL DEFAULT 0,
    address_count      INTEGER NOT NULL DEFAULT 1,
    first_rssi         INTEGER,
    last_rssi          INTEGER,
    avg_rssi           REAL,
    max_rssi           INTEGER,
    state              TEXT NOT NULL DEFAULT 'active',
    confidence         REAL NOT NULL DEFAULT 0,
    evidence_json      TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_presence_tracklets_last_seen
    ON presence_tracklets(last_seen_unix);
CREATE INDEX IF NOT EXISTS idx_presence_tracklets_signature
    ON presence_tracklets(signature,last_seen_unix);

CREATE TABLE IF NOT EXISTS presence_tracklet_macs (
    tracklet_id        TEXT NOT NULL,
    mac                TEXT NOT NULL,
    first_seen_unix    INTEGER NOT NULL,
    last_seen_unix     INTEGER NOT NULL,
    observation_count  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tracklet_id,mac),
    FOREIGN KEY (tracklet_id) REFERENCES presence_tracklets(tracklet_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_presence_tracklet_macs_mac
    ON presence_tracklet_macs(mac,last_seen_unix);

CREATE TABLE IF NOT EXISTS intrusion_signals (
    signal_id      TEXT PRIMARY KEY,
    ts_unix        INTEGER NOT NULL,
    bucket         INTEGER NOT NULL,
    signal_type    TEXT NOT NULL,
    family         TEXT NOT NULL,
    source_id      TEXT NOT NULL,
    weight         REAL NOT NULL,
    evidence_json  TEXT NOT NULL DEFAULT '{}',
    UNIQUE(bucket,signal_type,source_id)
);
CREATE INDEX IF NOT EXISTS idx_intrusion_signals_ts ON intrusion_signals(ts_unix);

CREATE TABLE IF NOT EXISTS intrusion_episodes (
    episode_id         TEXT PRIMARY KEY,
    start_unix         INTEGER NOT NULL,
    last_seen_unix     INTEGER NOT NULL,
    status             TEXT NOT NULL,
    score              INTEGER NOT NULL,
    severity           TEXT NOT NULL,
    home_state         TEXT NOT NULL,
    signal_types_json  TEXT NOT NULL DEFAULT '[]',
    evidence_json      TEXT NOT NULL DEFAULT '{}',
    alert_id           TEXT
);
CREATE INDEX IF NOT EXISTS idx_intrusion_episodes_last_seen
    ON intrusion_episodes(last_seen_unix);

-- v7: auditable local friendly-name resolution.  Keep every observation so
-- the selected label can change as better evidence becomes available without
-- losing provenance.  No protected payloads or stable owner identifiers are
-- derived here; these are names devices already disclose locally.
CREATE TABLE IF NOT EXISTS entity_name_candidates (
    entity_id       TEXT NOT NULL,
    name            TEXT NOT NULL,
    source          TEXT NOT NULL,
    confidence      REAL NOT NULL,
    first_seen_unix INTEGER NOT NULL,
    last_seen_unix  INTEGER NOT NULL,
    evidence_json   TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (entity_id, source, name),
    FOREIGN KEY (entity_id) REFERENCES entities(entity_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_name_candidates_entity
    ON entity_name_candidates(entity_id, confidence DESC, last_seen_unix DESC);

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

-- v3: zones + site-survey probe captures (phone-as-probe calibration).

-- A logical location label like "front porch", "driveway", "kitchen".
CREATE TABLE IF NOT EXISTS zones (
    zone_id           TEXT PRIMARY KEY,
    name              TEXT UNIQUE NOT NULL COLLATE NOCASE,
    perimeter         INTEGER NOT NULL DEFAULT 0,  -- 1 = outdoor/perimeter, gates rules
    excluded_alerts   INTEGER NOT NULL DEFAULT 0,  -- 1 = noise zone (e.g., "street")
    created_unix      INTEGER NOT NULL,
    sample_count      INTEGER NOT NULL DEFAULT 0,
    notes             TEXT
);

-- One capture window's worth of fingerprint data — averaged into the zone.
CREATE TABLE IF NOT EXISTS zone_samples (
    sample_id        TEXT PRIMARY KEY,
    zone_id          TEXT NOT NULL,
    captured_unix    INTEGER NOT NULL,
    duration_sec     INTEGER NOT NULL,
    fingerprint_json TEXT NOT NULL,
    FOREIGN KEY (zone_id) REFERENCES zones(zone_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_zone_samples_zone ON zone_samples(zone_id);

-- In-progress probe captures. Cleared when consumed.
CREATE TABLE IF NOT EXISTS probe_captures (
    capture_id       TEXT PRIMARY KEY,            -- ULID
    zone_name        TEXT NOT NULL,               -- target label (zone may be created on save)
    started_unix     INTEGER NOT NULL,
    ends_unix        INTEGER NOT NULL,
    status           TEXT NOT NULL,               -- pending | done | discarded
    fingerprint_json TEXT,
    notes            TEXT
);
CREATE INDEX IF NOT EXISTS idx_probe_captures_status ON probe_captures(status);

-- v4: Find-My cluster tracking. Apple rotates Find-My keys ~every 15 min so
-- we can't ID a specific tracker by MAC over time. We can cluster across
-- rotations using RSSI continuity (same RSSI, ~simultaneous MAC handoff)
-- and assign a stable internal ID. Co-presence with anchors then gives us
-- inferred ownership.

CREATE TABLE IF NOT EXISTS findmy_clusters (
    cluster_id              TEXT PRIMARY KEY,
    first_seen_unix         INTEGER NOT NULL,
    last_seen_unix          INTEGER NOT NULL,
    sighting_count          INTEGER NOT NULL DEFAULT 0,
    rotation_count          INTEGER NOT NULL DEFAULT 0,  -- distinct rotating MACs we've seen
    last_rssi               INTEGER,
    avg_rssi                REAL,
    last_status             TEXT,
    last_mac                TEXT,
    classification          TEXT,                         -- null | known | suspicious | enrolled
    user_label              TEXT,                          -- user-provided name
    inferred_owner_anchor   TEXT,                          -- entity_id of associated anchor
    inferred_owner_score    REAL,                          -- co-presence correlation 0..1
    notes                   TEXT,
    tracker_family          TEXT NOT NULL DEFAULT 'apple_findmy',
    network_provider        TEXT,
    near_owner              INTEGER
);
CREATE INDEX IF NOT EXISTS idx_findmy_clusters_last_seen ON findmy_clusters(last_seen_unix);
CREATE INDEX IF NOT EXISTS idx_findmy_clusters_owner ON findmy_clusters(inferred_owner_anchor);

-- Map of rotating MAC → cluster (so a returning MAC quickly hits its cluster).
CREATE TABLE IF NOT EXISTS findmy_cluster_macs (
    rotating_mac    TEXT PRIMARY KEY,
    cluster_id      TEXT NOT NULL,
    first_seen_unix INTEGER NOT NULL,
    last_seen_unix  INTEGER NOT NULL,
    sighting_count  INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (cluster_id) REFERENCES findmy_clusters(cluster_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_findmy_cluster_macs_cluster ON findmy_cluster_macs(cluster_id);

-- v5: owned Find-My trackers (master-secret import + catalog matching).
-- These are the user's own AirTags / Find-My-enabled accessories. Paired
-- on a real Apple device, master secret extracted via OpenHaystack on Mac.
-- We precompute future BLE pubkeys in findmy_key_catalog so we can match
-- incoming Find-My broadcasts deterministically and label them with the
-- user's name (e.g. "Ian's Keys", "Living Room").

CREATE TABLE IF NOT EXISTS findmy_owned_trackers (
    tracker_id      TEXT PRIMARY KEY,            -- ULID
    name            TEXT NOT NULL,
    enrolled_unix   INTEGER NOT NULL,
    last_match_unix INTEGER,
    catalog_to_unix INTEGER NOT NULL DEFAULT 0,  -- catalog computed up to this slot start
    notes           TEXT
);
CREATE INDEX IF NOT EXISTS idx_findmy_owned_name ON findmy_owned_trackers(name);

-- Pre-computed expected public keys per 15-min slot. One entry per
-- tracker × slot. Lookup by pubkey_22b_hex on every incoming Find-My event.
CREATE TABLE IF NOT EXISTS findmy_key_catalog (
    tracker_id        TEXT NOT NULL,
    slot_index        INTEGER NOT NULL,
    slot_start_unix   INTEGER NOT NULL,
    pubkey_22b_hex    TEXT NOT NULL,             -- bytes 6..27 of EC public X coord
    pubkey_top_bits   INTEGER NOT NULL,          -- top 2 bits of byte 0 (used in adv byte 23)
    expected_mac      TEXT NOT NULL,
    PRIMARY KEY (tracker_id, slot_index),
    FOREIGN KEY (tracker_id) REFERENCES findmy_owned_trackers(tracker_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_findmy_catalog_pubkey ON findmy_key_catalog(pubkey_22b_hex);
CREATE INDEX IF NOT EXISTS idx_findmy_catalog_mac ON findmy_key_catalog(expected_mac);
CREATE INDEX IF NOT EXISTS idx_findmy_catalog_slot ON findmy_key_catalog(slot_start_unix);

-- v8: encrypted, local-only key vault.  secret_ciphertext is always a
-- Fernet token; the master key is stored separately with mode 0600.
CREATE TABLE IF NOT EXISTS name_decryption_keys (
    key_id             TEXT PRIMARY KEY,
    label              TEXT NOT NULL,
    key_type           TEXT NOT NULL CHECK (key_type IN ('ble_ead', 'fast_pair_account', 'ble_irk')),
    scope              TEXT NOT NULL DEFAULT '*',
    secret_ciphertext  TEXT NOT NULL,
    metadata_json      TEXT NOT NULL DEFAULT '{}',
    created_unix       INTEGER NOT NULL,
    last_used_unix     INTEGER,
    enabled            INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_name_decryption_keys_type
    ON name_decryption_keys(key_type, enabled);

-- Set schema version to 10 (anonymous presence + intrusion episodes).
DELETE FROM schema_meta WHERE version < 10;
INSERT OR IGNORE INTO schema_meta(version) VALUES (10);
