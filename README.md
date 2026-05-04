# Watchtower

Perimeter RF awareness layer for residential pre-intrusion casing detection,
running on a single Raspberry Pi. Passive monitoring of BLE, Wi-Fi, sub-GHz,
and cellular bands plus a beautiful real-time dashboard.

> Status: **M3-lite shipped.** Capture, analytics, detection, dashboard,
> and phone-probe site survey are all live. See `docs/superpowers/specs/`
> for the full design and `docs/superpowers/plans/` for milestone plans.

---

## What it does, in 30 seconds

- **Listens** continuously to every nearby BLE advertisement, Wi-Fi AP, sub-GHz
  protocol decode (key fobs, garage doors, weather sensors), and cellular-band
  energy.
- **Groups** the noise into stable identities: phones with stable MACs, BLE
  devices that broadcast a name (Samsung TVs, AirPods, smart bulbs), and the
  Apple Continuity protocol family (AirDrop, AirPlay, Find-My, Nearby-Info,
  ...).
- **Scores** each identity on regularity (entropy of when it shows up) and
  anomaly (lingering, unfamiliar pattern, strong signal close to the property).
- **Fires** alerts for casing-pattern rules:
  *anchor-absent + unknown lingering*, *unknown key-fob emission*,
  *unknown garage-door emission*, *Apple Find-My/AirTag near property*,
  *first-time visitor after-hours*, *strong-signal mobile unknown nearby*,
  *rogue Wi-Fi hotspot (random-BSSID with strong signal)*.
- **Surfaces** all of this through a dark-themed responsive dashboard at
  `http://watchtower.local:8080`, with a separate mobile-first calibration
  webapp at `/probe`.

---

## Architecture

```
HARDWARE   Pi 5 16GB · built-in BLE 5.0 · built-in Wi-Fi (active scan)
           · 2× RTL-SDR (R820T + E4000 tuners, 24 MHz - 1.7 GHz)

CAPTURE    ble_scanner   wifi_scanner   subghz_scanner   midband_scanner
           (bleak)       (iw scan)      (rtl_433 child)  (pyrtlsdr sweep)
                              ↓ uniform Event envelope
LOCAL BUS  asyncio pub/sub with sync+async subscribers

ENRICHMENT analytics.py: random-MAC defeat (Apple Continuity decoder, named
           grouping, stable-MAC tracking), visit segmentation, regularity
           via Shannon entropy, Welford running baseline per (feature ×
           hour-of-week), anomaly score, rule evaluation.

OUTPUT     LocalSink → SQLite (7-day raw retention, hourly pruner)
           api.py → /api/* JSON + static dashboard at port 8080
```

All in one asyncio process supervised by systemd. Standalone, no internet
required.

---

## The dashboard at `:8080`

| Tab | What you see |
| --- | --- |
| **Overview** | Hero state (CALM / WATCHING / EYES UP / SETUP / AWAY · QUIET), live RF radar, top anomalies, scanner activity bars, baseline learning progress, "entropy of the room" envelope plot |
| **Discover** | Auto-suggested enrollment candidates ranked by stability, one-tap classify into Anchor / Satellite / Known guest / Untrusted |
| **Entities** | Sortable, filterable table of every tracked entity with anomaly bars and regularity meters |
| **Timeline** | 1h / 6h / 24h / 3d / 7d scrubbable visit timeline, color-coded by classification and anomaly score |
| **Spectrum** | Live energy sparklines per cellular/ISM band, sub-GHz protocol decode log |
| **Zones** | Calibrated locations from phone probe captures |
| **Alerts** | Rule fires with severity, evidence, ack + thumbs up/down feedback |
| **Settings** | Per-rule toggles, anomaly thresholds, after-hours window, danger-zone DB tools |

Plus `/probe` — a separate mobile-first webapp for site-survey calibration:
walk to a location, dwell 30 s, save the RF fingerprint as a zone.

---

## Quickstart

### Pi prep (one-time, on the Pi)

Run the bundled setup script as root:

```bash
ssh admin@watchtower.local "bash" < deploy/pi-setup.sh
sudo reboot   # to apply the DVB-driver blacklist
```

Installs `bluez`, `rtl-sdr`, `rtl-433`, `iw`, `sqlite3`; blacklists kernel
DVB drivers so RTL-SDR can claim the dongles; installs udev rules for
non-root SDR access; adds `admin` to `bluetooth` and `plugdev` groups; and
creates the watchtower data directories.

### Develop on your host

```bash
cd /path/to/watchtower
uv sync
uv run pytest -v
```

42 unit tests + 6 integration tests (skip unless `WATCHTOWER_PI_HOST` is
set). Mock-driven; doesn't require hardware.

### Deploy to the Pi

```bash
./deploy/deploy.sh watchtower.local
```

Rsyncs source, installs uv on the Pi, syncs the venv, drops the example
config to `/etc/watchtower/watchtower.toml` (if not already present),
installs the systemd unit, and (re)starts the service.

### Verify

```bash
ssh admin@watchtower.local
systemctl is-active watchtower
sudo journalctl -u watchtower -f
```

Open `http://watchtower.local:8080` in a browser.

### First-run flow

1. Open the dashboard. State will be **SETUP**.
2. Click **Discover**. Mark your phone (look for "phone (random MAC)" with
   high observation count, or your phone's local name) as **Anchor**. Mark
   your watch / earbuds / kids' phones as **Satellite**.
3. Open `/probe` on your phone, pick a location (Front Porch, Driveway,
   ...), tap **Start capture · 30s**, and stand still. Save the
   fingerprint. Repeat for every meaningful zone in your house.
4. State should switch to **CALM** (anchor home) or **AWAY · QUIET**
   (anchor away). Detection rules are now armed.

---

## Hardware bill of materials

| Item | ~Cost |
| --- | --- |
| Pi 5 16GB | $120 |
| 256 GB microSD (A2-rated) | $30 |
| 2× RTL-SDR Blog v3 (or compatible Nooelec NESDR / SMArTee XTR) | $70 total |
| Antennas (telescoping for RTL-SDRs) | $40 |
| Powered USB hub (recommended for power budget) | $30 |
| Enclosure with airflow | $30 |
| **Total** | **~$320** |

A USB Wi-Fi monitor adapter (e.g. Alfa AWUS036ACS) and a Hailo-8L AI HAT
are documented in the spec but not required for v1. Likewise a Pi UPS HAT
for the "power-cut robustness" threat model is deferred work.

---

## Configuration

Settings live in `/etc/watchtower/watchtower.toml`. The example is at
`config/watchtower.example.toml`. Detection thresholds and per-rule
toggles are tunable from the **Settings** tab in the dashboard at
runtime — no restart needed.

---

## Schema

SQLite at `/var/lib/watchtower/watchtower.db`. Schema v3.

| Table | Rows | Retention |
| --- | --- | --- |
| `raw_events` | every BLE/WiFi/sub-GHz/midband event | **7 days** |
| `entities` | one row per stable identity | indefinite |
| `entity_visits` | one row per contiguous visit (gap > 5 min closes) | indefinite |
| `baseline_stats` | Welford running stats per (feature × hour-of-week) | indefinite |
| `alerts` | fired alerts with evidence | indefinite |
| `zones` | calibrated locations from phone probe | indefinite |
| `zone_samples` | per-capture RF fingerprints | indefinite |
| `probe_captures` | in-flight probe requests | cleared on save/discard |
| `analytics_state` | rollup watermark + settings overrides | indefinite |

---

## Detection rules

Each rule is a Python predicate in `analytics.py:_evaluate_rules`. All have
runtime on/off toggles in the **Settings** tab.

- `anchor_absent_unknown_linger` — unknown entity present > linger threshold
  while no anchor home.
- `unknown_keyfob_emission` — sub-GHz key-fob protocol with unknown source.
- `unknown_garage_emission` — sub-GHz garage protocol with unknown source.
- `airtag_findmy_present` — Apple Find-My broadcast detected; severity
  scaled by RSSI proximity.
- `first_time_visitor_after_hours` — new entity first-seen during after-hours
  window. Requires at least one anchor enrolled.
- `close_unknown_signal` — unknown BLE entity with RSSI > -50 dBm and
  recurring presence (skips stationary IoT).
- `rogue_hotspot` — random-BSSID Wi-Fi AP with strong signal — phone hotspot
  near the property.

Severities (`critical / high / medium / low`) drive dashboard banner colors
and (in v1.5) ntfy push routing.

---

## Roadmap

- **v1.5 (next)** — UPS HAT support, ntfy push notifications, heartbeat /
  watchdog, tamper detection, active BLE GATT probing for richer device
  identification.
- **v2** — vulcan (or other) cloud sink for cold-tier storage, ML training
  pipeline, Hailo NPU for on-device autoencoder anomaly scoring.
- **v3** — multi-Pi mesh with TDOA localization, Frigate / camera fusion,
  acoustic glass-break detection.

---

## Licensing & non-goals

This is a personal-use security tool. **Do not** deploy in shared housing
without informed consent of all residents — passive RF monitoring
captures a lot of incidental signal. Cellular IMSI capture is explicitly
**not** implemented and is illegal in most jurisdictions.
