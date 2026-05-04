# Watchtower — Perimeter RF Awareness Layer

**Status:** Design / pre-implementation
**Author:** Ian (with Claude)
**Date:** 2026-05-03
**Working name:** Watchtower (placeholder)

---

## 1. Summary

Watchtower is a single-Pi RF monitoring system for residential perimeter awareness. It passively observes BLE, WiFi, sub-GHz, cellular, and adjacent radio bands around the property; clusters scan fragments into stable tracked entities despite MAC randomization; classifies entities into household/known/unknown; learns signal-entropy baselines per (feature × hour-of-week); and fires graded alerts for casing-pattern anomalies (especially when nobody is home) while maintaining a 7-day forensic timeline accessible only over Tailscale.

The system is designed as a **perimeter awareness layer** that complements (not replaces) cameras and motion sensors. The primary ship value is the forensic timeline; realtime casing alerts are tunable and expected to need a runway.

## 2. Goals & non-goals

### Goals

- Detect **pre-intrusion casing**: persistent unknown RF presence near the property, especially when residents are absent.
- Maintain a **forensic timeline** of every RF entity observed in the last 7 days, queryable post-hoc.
- Learn the household's normal RF environment without manual whitelisting.
- Detect **RF-based attack patterns** that bypass cameras: key-fob relay attacks, garage-code captures, walkie-talkie coordination by intruders.
- Run **fully standalone** on a single Pi 5 — no internet, no cloud, no server dependencies. (Cloud extension is explicitly v2.)
- Be **dwelling-portable**: a configuration profile system handles different deployment environments (detached / dense / townhouse / apartment).
- Be **future-multi-tenant**: data model and event schema designed so a SaaS extension is additive, not a rewrite.

### Non-goals (v1)

- Live cellular IMSI capture, decryption, or device identification (illegal in most jurisdictions; technically futile on 5G).
- Attempting to identify *who* a device belongs to in the legal-evidence sense — only to recognize "same device as before, probably."
- Replacing cameras or alarm systems. Watchtower is a complementary layer.
- Power-cut survival beyond what an optional UPS provides. Full power-cut robustness requires battery + cellular uplink, scoped to a future revision.
- Active intrusion alarm. The threat model is pre-intrusion casing + forensic logging; mid-intrusion alerts are best handled by motion sensors and cameras.

## 3. Threat model

Watchtower targets two threat scenarios:

1. **Pre-intrusion casing.** Methodical attackers scout properties before breaking in. They walk by, sit in cars, return multiple times, observe routines. RF presence over time is detectable here even when cameras see nothing actionable.
2. **Forensic evidence.** After-the-fact, "what RF entities were near the property at time T" is useful for incident review and corroboration with other sources.

Watchtower **does not** target:
- Sophisticated attackers who leave their phones at home.
- Smash-and-grab opportunists who arrive and leave in <5 minutes.
- Insider threats from already-enrolled devices.

**Honest expected coverage:** the system catches the methodical middle band of attacker — sophisticated enough to case, not professional enough to leave the phone behind. Most residential burglary fits this band.

## 4. Architecture overview

Single Pi 5 (16GB) + Hailo-8L AI HAT, all state in SQLite, dashboard over Tailscale. Four logical layers connected by an in-process message bus:

```
HARDWARE          Pi 5 16GB · Hailo-8L AI HAT
                  Built-in BLE 5.0 · USB WiFi (monitor) · 2× RTL-SDR (RTL2832U)

CAPTURE           ble_scanner · wifi_scanner · subghz_scanner · midband_scanner
                  → uniform Event envelope on local bus

ENRICHMENT        device_resolver: probabilistic entity tracking
                  enrichment_engine: friendly name / category / model
                  presence_engine: open/close visit sessions
                  home_state: anchor-presence model

DETECTION         rules_engine: declarative, instant fire
                  baseline_engine: per (feature × hour-of-week) statistics
                  surprisal_engine: per-minute joint observation entropy
                  ml_engine [v2]: Hailo autoencoder

OUTPUT            alert_dispatcher: dedupe + severity routing → ntfy push
                  event_sink_local: SQLite, 7-day raw retention
                  event_sink_external [v2 hook]: vulcan/MQTT/webhook stubs
                  dashboard_api: web UI over Tailscale
```

The bus is in-process Python (multiprocessing.Queue or ZeroMQ inproc — TBD at implementation time, no broker). The `event_sink_external` interface is wired but no-op in v1; v2 cloud forwarding plugs in here without touching detection.

## 5. Capture layer

| Scanner | Hardware | Output events |
|---------|----------|---------------|
| `ble_scanner` | Pi 5 built-in BLE 5.0 | `ble_adv`, `ble_scan_response` |
| `wifi_scanner` | USB WiFi adapter, monitor mode | `wifi_probe_request`, `wifi_assoc_request`, `wifi_beacon_seen` |
| `subghz_scanner` | RTL-SDR #1 (RTL2832U), fixed 24–960 MHz | `keyfob_emission`, `garage_emission`, `unknown_subghz_burst`, `walkietalkie_emission`, `subghz_protocol_decoded` |
| `midband_scanner` | RTL-SDR #2 (RTL2832U), fixed 960 MHz – 1.7 GHz | `cellular_band_energy_low_mid`, `lora_emission_915`, `aviation_band_energy` |

**Why fixed-assignment RTL-SDRs** rather than one sweeping radio: time-slicing across 24 MHz–1.7 GHz misses sub-second events on whichever band is currently off-air (key-fob bursts especially). Two radios on dedicated bands = continuous coverage, no missed events.

**Why a dedicated USB WiFi adapter** rather than relying solely on built-in WiFi: built-in WiFi monitor mode on Pi 5 is unreliable; purpose-built USB adapters (e.g., Alfa AWUS036ACS) handle monitor mode well. Built-in BLE is kept for Bluetooth.

**Hardware coverage limitations of RTL-SDR vs HackRF (acknowledged):** RTL-SDR cannot directly survey 2.4 GHz (BLE/WiFi already covered by dedicated radios) or 5 GHz, and only catches the lower cellular bands (700/800/900 MHz LTE) — high-band cellular (1800/2100/2600 MHz) is out of range. For this threat model these losses are negligible: BLE/WiFi capture is the right tool for 2.4 GHz device tracking, and cellular Tier-1 detection works on whichever bands are accessible (carrier-dependent). A future HackRF upgrade is a drop-in replacement at the scanner abstraction.

### Event envelope (uniform across all scanners)

```jsonc
{
  "event_id":   "ulid",
  "ts":         "2026-05-03T22:41:13.412Z",
  "scanner":    "ble_scanner",
  "kind":       "ble_adv",
  "raw":        { /* scanner-specific raw fields */ },
  "features":   {
    "mac": "aa:bb:cc:dd:ee:ff",
    "rssi": -67,
    "vendor_oui": "Apple, Inc.",
    "service_uuids": ["fd6f", "feaa"],
    "manufacturer_data_hex": "4c001005...",
    "is_random_mac": true,
    "tx_power": -8
  },
  "channel_hint": null,
  "mesh_node_id": null   // v2: distinguishes nodes in a mesh deployment
}
```

`features` is pre-extracted at scanner boundary; downstream consumers don't re-parse `raw`. `raw` is preserved for the 7-day window so feature-extraction logic improvements can re-derive features in place.

## 6. Enrichment layer

### 6.1 device_resolver — defeating MAC randomization

**Goal:** reduce a stream of randomized-MAC scan events into stable tracked entities.

**Clustering signals:**

1. **Vendor OUI / non-random MAC presence.** ~30–50% of BLE traffic comes from devices that don't randomize at all (headphones, smartwatches, AirTags, cars, IoT) — these are stable forever.
2. **Service UUID + manufacturer data fingerprint.** The shape of advertised services + manufacturer data layout is stable per device model + app combination, even when MAC rotates.
3. **RSSI continuity.** A MAC disappearing and a new MAC appearing within ±2s at similar RSSI from similar direction is almost certainly the same device rotating.
4. **Co-presence with stable anchors.** A randomized MAC consistently co-present with a stable accessory (e.g., the same AirPods MAC) is "the phone connected to those AirPods" — this is a powerful identity hook that survives phone replacement when the accessory persists.

**Resolution algorithm (sketch):**

```
on each ble_adv:
    fingerprint = (vendor_oui, sorted(service_uuids), mfr_data_layout_hash)
    candidates  = recent_entities_within_rssi_continuity(fingerprint, rssi, ts)
    if exactly_one_strong_match(candidates):
        attach event to entity, update entity rolling features
    elif multiple_candidates:
        score each by (fingerprint_match × rssi_continuity × co_presence_score)
        attach to top-scoring if score > threshold, else create new entity
    else:
        create new entity, mark as "fragile" (low confidence)
    decay_old_entities()  // age out anything not seen in 30 min
```

**Entity lifecycle states:**

- `fragile` — seen <3 times, may be a rotation artifact.
- `tracked` — seen consistently; eligible for detection rules.
- `enrolled` — explicitly classified by user.
- `dormant` — not seen in 30 min, kept for re-identification.

**Honest expected accuracy:** 85–95% re-identification on devices with stable companion accessories or non-random MAC components, dropping to 60–75% on bare iPhones with all peripherals off. Sufficient for "this entity has been here 22 minutes" detection; not sufficient for legal-grade identification.

### 6.2 enrichment_engine — friendly names, categories, models

When the resolver creates or significantly mutates an entity, the enrichment engine derives the most identifying information available. Layered:

| Layer | Source | Examples |
|-------|--------|----------|
| **Passive identification** (always on) | OUI · BLE Service UUIDs · Apple manufacturer data sub-types · TX power patterns · BLE Local Name field · WiFi probe SSIDs | "Apple — AirTag", "Bose QC45", "Likely Pixel 8 + Galaxy Buds" |
| **Behavioral inference** (>24h obs) | Visit pattern, companion fingerprint, RSSI trajectory shape | "Weekday 16:00 visitor", "always co-present with `bose_qc45_a47f`", "walks past not stops" |
| **Active probing** (opt-in, default OFF) | GATT connection attempt to read public Generic Access "Device Name" | Friendlier names where listed |
| **User-supplied labeling** (enrollment) | User input | "Mom's iPhone 15", "Honda Civic key fob" |

**Categories:** `phone | tag | headphones | watch | car | smart_home | beacon | wearable | unknown`.

**Stored on entity row:**

```jsonc
{
  "entity_id": "ent_a47f3...",
  "first_seen": "2026-04-11T14:22:13Z",
  "last_seen":  "2026-05-03T22:41:13Z",
  "lifecycle":  "tracked",
  "classification": null,                 // null | anchor | satellite | known_guest | untrusted
  "confidence": 0.87,
  "friendly_name": "Likely Pixel 8",
  "name_source": "passive_manufacturer_data",  // user_set | active_probed | passive_*
  "category": "phone",
  "vendor": "Google",
  "model_guess": "Pixel 8 / Pixel 8 Pro",
  "model_confidence": 0.71,
  "fingerprint": { /* hash blob */ },
  "notes_user": "",
  "notes_inferred": "Weekday 16:00 visitor, ~3x/week",
  "linked_entities": ["bose_qc45_a47f"]
}
```

`name_source` is surfaced in the dashboard so users can tell where a name came from.

### 6.3 home_state — who's home

Always-current state derived from anchor-classified enrolled devices:

```jsonc
{
  "ts": "2026-05-03T22:41:13Z",
  "is_home": true,
  "anchors_present": ["mom_phone", "dad_phone"],
  "anchors_absent":  ["liam_phone"],
  "satellites_present": ["mom_watch", "kitchen_speaker"],
  "absent_for_seconds": 0,
  "last_state_change": "2026-05-03T16:12:04Z",
  "evidence": "anchor_ble_seen"   // ble_seen | wifi_associated | both
}
```

**Rules:**
- `is_home == true` if any anchor present by configured evidence type.
- A device is "present" if seen in the last `presence_window_sec` (default 300).
- Departure detected after `departure_grace_sec` (default 180) to avoid flapping.
- **Time-of-day overrides** per enrolled device prevent false "empty house" determinations during expected absences (e.g., kids' phones during school hours).
- `evidence` field exposes confidence to detection rules; BLE-only is weaker than WiFi-associated.

## 7. Detection layer

### 7.1 rules_engine

Declarative, instant-fire rules. High-precision triggers with severity + cooldown.

| Rule | Trigger | Severity |
|------|---------|----------|
| `key_fob_attack` | sub-GHz repeated bursts matching relay/replay pattern (high duty-cycle on a single freq for >5s, or rolling-code structure with unfamiliar pattern) | critical |
| `garage_signal_anomaly` | unfamiliar 315/390 MHz emission near garage door frequencies | high |
| `unknown_walkietalkie_emission` | unfamiliar push-to-talk in 462/467 MHz or 154–155 MHz bands inside property zones, esp. when `home_state.is_home == false` | high |
| `anchor_absent_unknown_linger` | `home_state.is_home == false` AND a `tracked` non-enrolled entity has been present in property zones (excluding `street`) for > `casing_threshold_sec` (default 600) | high |
| `unknown_at_perimeter_offhours` | unknown entity in close-perimeter zone for >2 min between 23:00–05:00 | medium |
| `unknown_back_yard_anytime` | any unknown entity in `back_yard` zone for >5 min — back yards rarely receive legitimate visitors regardless of home_state | medium |
| `enrolled_device_anomaly` | enrolled anchor's MAC pattern, advertised services, or RSSI signature shifted dramatically — possible spoofing | medium |
| `cellular_burst_with_silent_ble` | cellular band energy spike with no corresponding BLE/WiFi from a tracked entity — phone in airplane-mode-but-cellular-on | low (forensic flag) |

Rules are Python predicates (small declarative DSL via simple decorator pattern). Adding a rule is a 10-line PR.

### 7.2 baseline_engine

Per `(feature × hour-of-week)` rolling statistics. **168 buckets per feature** for the weekly cycle.

**Tracked features:**
- count of distinct tracked entities seen in this hour
- count of new entities (first-seen this hour)
- count of unknown (non-enrolled) tracked entities
- mean RSSI of unknown lingerers
- cellular band energy mean/peak
- sub-GHz event count
- duration of longest unknown lingerer in the hour

**Algorithm:** Welford's online mean+variance per bucket, exponentially decayed (half-life ~6 weeks) to track seasonal change. ~12 features × 168 hours = ~2000 rows. Trivial size.

**Warmup:** 14 days. No alerts during warmup; UI shows "baseline learning: day N of 14."

**Storage:** `baseline_stats` table — persists indefinitely (separate from raw 7-day retention).

### 7.3 surprisal_engine — entropy-based weighting

Two complementary entropy measures replace simple z-score thresholds.

#### Per-entity behavioral entropy

Each tracked entity gets an incrementally-updated `regularity ∈ [0, 1]`:

- **Visit-time entropy** — Shannon entropy over historical arrival hour-of-week buckets.
- **Visit-duration entropy** — entropy over linger-duration distribution.
- **Co-presence entropy** — entropy over which entities are seen alongside.

`regularity = 1 - normalized_combined_entropy`. Predictable visitors (mailman, weekly cleaner) approach 1.0; chaotic walkers approach 0.0.

#### Per-minute observation surprisal

Joint observation `(entity_count, unknown_count, RSSI histogram, cellular_energy, ...)` scored against learned distribution for the same hour-of-week:

`surprisal = -log P(observation | learned_history)`

Implemented v1 via per-feature kernel density estimate (CPU-cheap on Pi); v2 via Hailo autoencoder reconstruction error.

#### Combined detection score

```
detection_score(rule, entity, observation) =
    rule.base_severity
    × surprisal_weight(observation)               // bounded, modulates severity
    × (1 - entity.regularity)                     // erratic entities scored higher
    × home_state_multiplier(home_state)           // empty house = bigger weight
    × dwelling_profile.sensitivity_factor
```

Surprisal modulates severity, **not firing** — the rule still requires its primary condition. Effect: known-pattern visitors (mailman, weekly cleaner) auto-dampen to forensic flags without explicit whitelisting; unfamiliar patterns bump severity.

### 7.4 alert_dispatcher

Aggregates from rules + baseline (+ ML in v2). Dedupes by `(rule_id, entity_id, 5-minute window)`. Severity-to-channel routing:

| Severity | Channel | Behavior |
|----------|---------|----------|
| critical | ntfy + dashboard banner | immediate, persistent until ack |
| high     | ntfy + dashboard | immediate, dismissable |
| medium   | dashboard only | alert tab, no push |
| low      | logged | forensic flag |

Per-rule overrides allowed.

## 8. Site survey & RSSI calibration

A walk-around calibration mode: user dwells in each labeled zone with their enrolled phone for 30s; Pi captures the RSSI fingerprint. Resulting per-zone fingerprints turn raw RSSI thresholds into zone-classified detection.

### Walk flow

1. **Define zones** — pre-filled defaults per dwelling profile (detached: `front_door, front_porch, driveway, front_yard, side_yard_left, side_yard_right, back_yard, back_door, garage, mailbox, street, living_room, kitchen, bedrooms`).
2. **Walk and dwell** — 30s per zone with the calibration phone. Big visual countdown.
3. **Validate** — confidence indicator per zone; redo noisy ones.
4. **Multi-pass option** — repeat on different days/weather; flag inherently noisy zones.

### Zone fingerprint shape

```jsonc
{
  "zone": "front_porch",
  "captured": "2026-05-03T15:22:00Z",
  "passes": 2,
  "rssi_mean": -52.1,
  "rssi_std": 4.3,
  "rssi_distribution": [/* histogram bins */],
  "calibration_device": "moms_iphone_15",
  "stability": 0.87
}
```

### Projection to other devices

1. **TX-power-aware normalization** when `tx_power` field is broadcast.
2. **Distribution-shape matching** (KL divergence between observed and zone fingerprints) when not — the *shape* of an entity's RSSI distribution captures path loss independently of absolute power.

Imperfect on adjacent zones (`front_porch` ≈ `front_door`) but correct on the structural distinctions detection rules care about: outside/inside, perimeter/interior, front/back.

### Continuous re-calibration

Anchor devices roaming the house during normal life provide free calibration data points. Zone fingerprints auto-refine over weeks. When drift exceeds threshold the dashboard prompts targeted re-survey.

The `street` zone is explicitly excluded from alert-firing rules — captures passersby and removes the dominant noise source.

## 9. Enrollment UX

Observation-first. The system runs 24+ hours before asking the user to label anything. Three flows:

### Auto-suggest queue (primary)

Dashboard `Discover` tab ranks stable entities by stability + presence-frequency. Each row shows category icon, friendly name, visit stats, co-presence hints, and one-tap classification: `Anchor / Satellite / Known guest / Ignore / Skip`.

**Auto-link suggestions** — when an unenrolled entity is consistently co-present with an already-enrolled entity (e.g., a phone that always appears with a specific AirPods MAC), the UI suggests "link as same person's accessory" so future MAC rotations re-attach via the persistent companion.

### Proximity enroll

GPIO button on the Pi triggers a 10-second window: "I'm holding the device near the Pi now." Highest-RSSI new entity in that window becomes the enrollment candidate; user names + classifies via dashboard.

### Manual entry

Form-based. Edge cases only.

### Per-device data

```jsonc
{
  "owner_label": "Mom",
  "friendly_name": "Mom's iPhone 15",
  "classification": "anchor",
  "category_override": null,
  "expected_presence": {
    "weekdays": [{ "hours": "08:00-17:00", "expected": "absent" },
                 { "hours": "17:00-08:00", "expected": "present" }],
    "weekends": [{ "hours": "*", "expected": "any" }]
  },
  "linked_entities": ["bose_qc45_a47f"],
  "notes": ""
}
```

## 10. Forensic dashboard

Single-page web app served by the Pi over Tailscale. WebAuthn/passkey auth (no passwords). Mobile-first responsive layout — most likely access pattern is "ntfy fired while I'm out, check the dashboard from my phone."

### Five views

1. **Live** — RF radar (RSSI-distance plot, color by category), anchor ribbon (presence per household member), cellular spectrum strip, active alerts.
2. **Timeline** (killer feature) — 7-day scrubbable timeline; one row per entity, visits as colored bars; filter by severity / classification / category / "show only when nobody home"; drag-select a time range; one-click static HTML/PDF report export for any range.
3. **Entities** — encyclopedia of all observed entities with sortable list, individual entity profiles (visit heatmap, RSSI distribution, co-presence graph, behavioral notes), bulk classification.
4. **Alerts** — fired alerts with evidence, expandable detail, **per-alert thumbs up/down feedback** UI (v1 captures votes; v1.5 wires votes to auto-tune baseline as Bayesian prior on rule sensitivity); per-rule settings.
5. **Settings** — dwelling profile, RSSI thresholds, ntfy endpoints, active probing toggle (off by default), time-of-day rules editor (visual weekday × hour grid per device), backup/export, v2 sink hooks (greyed out).

### Multi-user roles

- **admin** — full settings, enrollment, rule edits.
- **viewer** — live + timeline + alerts + ack, no settings.

Each user enrolls own passkey.

### Future expansion stubs (designed in, dormant)

These exist as interface contracts in v1 to avoid rewrite later:

- `event_sink` plugin interface (vulcan_forwarder, mqtt_publisher, webhook).
- `camera_event` schema for future Frigate/Reolink integration.
- `acoustic_event` schema for future glass-break / footstep mic add-on.
- `mesh_node_id` field on every event for future multi-Pi mesh.

## 11. Dwelling profiles

YAML bundles of detection thresholds, default zones, behavioral assumptions. Hot-reloadable via dashboard. Ships with: `detached_home.yaml`, `dense_neighborhood.yaml`, `townhouse.yaml`, `apartment.yaml` (alerts disabled by default — forensic-only).

Sample profile (detached home):

```yaml
name: "Detached home, neighbors >30ft"
zones:
  defaults: [front_door, front_porch, driveway, front_yard, side_yard_left,
             side_yard_right, back_yard, back_door, garage, mailbox, street]
  excluded_from_alerts: [street]
  perimeter:  [front_porch, driveway, front_yard, side_yard_*, back_yard, mailbox]
  interior:   [living_room, kitchen, bedrooms]
thresholds:
  rssi_close_perimeter_dbm: -55
  rssi_property_dbm:        -75
  linger_short_sec:         120
  linger_casing_sec:        600
  presence_window_sec:      300
  departure_grace_sec:      180
  baseline_warmup_days:     14
  baseline_sigma_medium:    3
  baseline_sigma_high:      4
  surprisal_weight_cap:     2.5
  zone_overrides:
    back_yard:
      linger_short_sec: 60
      sigma_medium:     2
home_state:
  anchor_evidence_required: ble_or_wifi
  prefer_wifi_associated:   true
cellular_band_sensitivity: 0.6
sensitivity_factor:        1.0
```

## 12. Data model & retention

### Tables

| Table | Purpose | Retention |
|-------|---------|-----------|
| `raw_events` | Every scan event with `raw` + `features` | **7 days** (hard-prune older) |
| `entities` | One row per tracked/enrolled entity, including enrichment | indefinite |
| `entity_visits` | One row per opened/closed visit session | 7 days |
| `home_state_history` | Transitions of `is_home` and anchor presence | 7 days |
| `zones` | Calibrated zone fingerprints | indefinite |
| `baseline_stats` | Per (feature, hour-of-week) running mean/variance | indefinite |
| `entity_regularity` | Per-entity behavioral entropy state | indefinite |
| `alerts` | Fired alerts with evidence blobs | indefinite (small) |
| `alert_feedback` | Per-alert user thumbs feedback | indefinite |
| `enrollment` | User-supplied device labeling | indefinite |
| `dwelling_profile` | Active profile + thresholds | indefinite |

7-day raw is partitioned hourly for fast prune. No rollup tiers in v1 (deferred to v2 cloud forwarding).

### Anonymized export

Exports to USB or cloud sinks optionally hash MAC addresses with a per-install salt, preserving entity_id continuity while making MACs non-recoverable.

## 13. Operations

### Updates

`watchtower-agent` polls a release source for updates. Atomic swap (download, verify checksum, single systemd restart). Last version retained for one rollback. `stable` channel default; `beta` available. Major-version updates require explicit user confirmation.

### Backups

- **Configuration**: dwelling profile, enrollment, zone fingerprints, baseline_stats. ~50KB. Daily encrypted snapshot to USB if attached, or downloadable from dashboard.
- **Raw data**: optional daily zstd Parquet export of last 7 days to USB or Tailscale-mounted SMB. Off by default.

### Fail-safes

| Failure | Behavior |
|---------|----------|
| One scanner crashes | Others keep running, dashboard yellow banner, ntfy alert. Single-source rules pause; cross-source rules degrade. |
| All scanners crash | Watchdog restarts processes (30s); persistent failure → ntfy critical "Watchtower not scanning." |
| SQLite disk full | Aggressive prune from oldest hour, ntfy warning. Last resort: in-memory detection (no forensic logging) + ntfy critical. |
| Network down | Continue scanning + detecting. Queue ntfy alerts locally, flush on restore. Dashboard works on local LAN. |
| ntfy unreachable | Local visual indicator (Pi LED). Queue alerts for retry. |
| Pi reboot | Detection back online <30s. Baseline stats and 7-day raw persist. Active sessions resumed where possible. |

### Power, heartbeat, tamper

- **UPS:** deferred (originally specced; user opted to ship without v1).
- **Heartbeat-to-ntfy + external watchdog:** deferred.
- **Tamper detection (accelerometer):** deferred.

These are documented as v1.5/v2 work — not blocking ship.

### Logs

Structured JSON to `/var/log/watchtower/`, daily rotation. Dashboard exposes last 1000 lines on demand. Sensitive fields scrubbed from any "share for support" export with user review before export.

## 14. Privacy

All defaults at maximum privacy:

- **Active probing of unknown devices:** OFF.
- **Raw retention:** 7 days (slider 1–14, capped to disk).
- **Network metadata** (probe SSIDs etc.): logged but never exported off-device unless user enables a sink.
- **Anonymize export:** MACs hashed with per-install salt for any export.
- **Wipe:** one-click "wipe all data" in settings.

## 15. Hardware bill of materials (v1 ship)

| Item | ~Cost |
|------|-------|
| Pi 5 16GB | $120 |
| Hailo-8L AI HAT | $70 |
| 256GB A2 microSD | $30 |
| USB WiFi adapter (Alfa AWUS036ACS or equivalent) | $15 |
| RTL-SDR Blog v3 #1 (sub-GHz fixed) | $35 |
| RTL-SDR Blog v3 #2 (mid-band fixed) | $35 |
| Powered USB 3 hub (recommended for radio + WiFi adapter power budget) | $30 |
| Antennas (telescoping for RTL-SDRs, high-gain for BLE/WiFi) | $40 |
| Enclosure with airflow | $30 |
| **Total v1** | **~$405** |

**Future hardware upgrade path:** swapping to 2× HackRF One (~$600 incremental) extends band coverage to 6 GHz, enabling 2.4/5 GHz spectrum survey and full LTE band coverage. Drop-in at the scanner abstraction; no design changes required.

### Deferred (v1.5 / v2)

- Argon ONE UPS HAT (~$50)
- Pi Camera Module 3 + IR cut filter (~$50) for camera-side ML on Hailo
- USB mic + acoustic anomaly model (~$10) for glass-break/footstep
- ADXL345 accelerometer (~$3) for tamper detection
- Additional Pi Zero 2 W listener nodes (~$15 each) for v2 mesh

## 16. Implementation phasing

### v1 — standalone Pi ship

Goal: forensic-first, casing alerts tunable, no cloud.

1. Capture layer (4 scanners) → uniform event envelope → bus.
2. SQLite schema + 7-day raw retention.
3. `device_resolver` (passive identification + RSSI continuity + co-presence linking).
4. `enrichment_engine` Layers 1, 2, 4 (passive + behavioral + user-supplied).
5. `home_state` model.
6. `rules_engine` with the rules in §7.1.
7. `baseline_engine` (Welford per bucket).
8. `surprisal_engine` (per-entity regularity + per-minute KDE surprisal).
9. `alert_dispatcher` + ntfy push.
10. Site survey & calibration UI.
11. Dwelling profile system + 4 default profiles.
12. Forensic dashboard — five views, mobile-first, passkey auth, multi-user.
13. Backup, restore, wipe, log export.

### v1.5 — operational hardening

- UPS HAT integration + power_lost/restored events.
- Heartbeat-to-ntfy + external watchdog script.
- Active probing layer (off by default but available).
- Per-alert thumbs-feedback auto-tuning of baseline.

### v2 — cloud extension

- `event_sink_external` implementation: vulcan forwarder over Tailscale.
- Cold-tier storage on vulcan (rollup tiers, indefinite history).
- ML training on vulcan from accumulated data; model push back to Pi for Hailo inference.
- `ml_engine` on Pi via Hailo (autoencoder for surprisal).
- Multi-tenant data model (one Pi = one tenant; vulcan handles many).

### v3 — multi-node mesh

- 2–3 Pi Zero 2 W listener nodes with directional antennas.
- TDOA-based localization across nodes.
- Phase-coherent HackRF mode for single-Pi direction finding.
- Camera-side fusion (Frigate / Pi Camera + Hailo person/face/plate detection).
- Acoustic side-channel (mic + glass-break / footstep ML on Hailo).

## 17. Open questions

1. **Bus implementation** — multiprocessing.Queue vs ZeroMQ inproc. Defer to implementation; either works at v1 scale.
2. **GATT active probing protocol scope** — should it attempt to read more than `Device Name` (e.g., `Manufacturer Name`, `Model Number`)? Probably yes for enrolled-only entities but worth confirming during implementation.
3. **WebAuthn library on Pi** — pick at impl time (`fido2` Python, `simplewebauthn` JS); not architectural.
4. **Sub-GHz key-fob attack signature library** — needs a small but well-curated database of known relay/replay patterns. Source: build incrementally, leveraging existing `rtl_433` decoders + custom rules for novel patterns.
5. **iOS Continuity message decoding** — partial decoders exist (hexway/apple-bleee, adam-toscher's notes); confirm what's still working in 2026 versions of iOS during implementation.

## 18. Future expansion hooks

Designed-in-but-dormant in v1:

- `event_sink_external.{vulcan_forwarder, mqtt_publisher, webhook_publisher}` — empty class stubs.
- `camera_event` and `acoustic_event` schemas in the data model.
- `mesh_node_id` field on every event.
- Multi-tenant ID on enrollment, profile, alerts (single-tenant constant in v1).

## 19. References & prior art

- Bluetooth SIG Assigned Numbers — vendor and service UUID lists.
- `rtl_433` — sub-GHz protocol decoder reference for keyfobs/garages/weather.
- `bleak` / `bluepy` / BlueZ HCI — BLE capture libraries.
- Welford (1962) — online running variance.
- Apple Continuity protocol partial documentation (community-maintained, not Apple-published).
