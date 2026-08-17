# Watchtower

**A single-Pi residential RF perimeter sensor for pre-intrusion casing detection.**

Watchtower listens passively to every radio signal between **24 MHz and
1.7 GHz** within range of a Raspberry Pi placed inside a home, learns
what *normally* happens in that RF environment, and surfaces anomalies
that look like someone surveilling the property — unfamiliar BLE
devices lingering near the front door, rogue Wi-Fi hotspots, AirTags
following the household, sub-GHz key-fob and garage-door bursts that
don't belong to anyone in the family.

It is **standalone** (no cloud, no internet required), runs as a
single systemd-supervised Python process, and exposes a real-time
dashboard at `http://watchtower.local` plus a separate mobile
calibration page at `/probe`.

---

## Why this exists

Most residential break-ins are preceded by reconnaissance: someone
walking the perimeter, scanning to see who's home, watching for
patterns of arrival and departure. From an RF perspective that
behavior is *very* loud — modern phones broadcast BLE every 100 ms,
every smartwatch emits Apple Continuity status nibbles, key fobs and
garage remotes leak rolling-code signatures, and every car has TPMS
pumping out 315 / 433 MHz packets every minute.

If you can:

1. **Capture** all of that traffic continuously,
2. **Learn** the per-hour baseline of what's normal in your
   neighborhood (entropy of *who* shows up, *when*, and *for how long*),
3. **Match** rotating-MAC privacy schemes (Apple Continuity, BLE RPA,
   randomized Wi-Fi probes) back into stable identities,
4. **Score** new entities for novelty + persistence + signal strength,
5. **Fire** rule-based alerts when the pattern matches casing,

…then a single Pi 5 can detect the *interesting* RF activity around a
house — without a camera, without a microphone, without phoning home,
and without snitching on the people who legitimately live there.

This is the project.

---

## Threat model

The thing Watchtower is designed to catch:

| Threat | Signal we listen for |
| --- | --- |
| Pre-burglary reconnaissance | Strong-signal **unknown BLE device lingering** near the perimeter while the family is away |
| Rolling-code attack tooling | **Sub-GHz key-fob / garage emission** with no known matching household device |
| AirTag stalking / luggage tracker dropped on a vehicle | **Apple Find-My broadcast** with persistent presence over multiple days, or near a household member's anchor |
| Rogue mobile hotspot used as a staging point | Random-BSSID Wi-Fi AP with strong signal that *isn't* on the home network |
| Visitor under-the-radar at unusual hours | First-time entity arriving inside the configured **after-hours window** |
| Active probing of decoy devices | Outbound BLE GATT connection attempts to the Pi's **honeypot lures** |
| Nearby Flipper Zero | High-confidence match on the official firmware's BLE name plus serial-service UUID |

Out of scope (and explicitly *not* implemented):

- Cellular IMSI catching or anything else illegal in most jurisdictions
- Decryption / cracking of rolling codes — we detect *that* a code was
  emitted, retain lawful decoder metadata, and group it by any exposed stable
  device ID; changing codes, MICs, and opaque payloads are never treated as identity
- Capturing audio / video / network content
- Tracking residents or guests they've consented to (anchors and
  satellites are intentionally exempted from most rules once enrolled)

---

## Architecture at a glance

```
HARDWARE      Pi 5 16 GB
              └─ built-in BLE 5.0 (hci0)               → BLE scanner
              └─ built-in Wi-Fi (wlan0, active scan)   → Wi-Fi scanner
              └─ USB SDR #0 (R820T2)                   → sub-GHz live decoder (rtl_433)
              └─ USB SDR #1 (E4000)                    → 24 MHz - 1.7 GHz mid-band sweep

CAPTURE       ble_scanner    wifi_scanner    subghz_scanner    midband_scanner
              (bleak)        (iw scan)       (rtl_433 child)   (pyrtlsdr sweep)
                                  ↓ uniform Event envelope on an asyncio Bus
SUB-GHZ       midband detects energy spikes at <1 GHz priority bands
DECODER       └→ writes IQ snapshot to disk (CU8, ~625 ms windows)
              └→ sub_decoder runs `rtl_433 -r FILE` offline against each capture
              └→ decoded protocols emit subghz_scanner events back into the bus

ENRICHMENT    analytics.py: privacy-defeat (Apple Continuity decoder + named
              grouping), visit segmentation, regularity (Shannon entropy),
              Welford running baseline per (feature × hour-of-week), anomaly
              score, OUI vendor lookup (≈50 k IEEE prefixes), Find-My cluster
              tracking across rotating MACs, owned-tracker catalog matching.

DETECTION     7 declarative rules, all toggleable + tunable from the dashboard.
              Each fires an Alert with structured evidence.

OUTPUT        SQLite (WAL mode, 64 MB cache, 256 MB mmap) with hourly pruner
              aiohttp /api/* + static SPA at port 80
              optional ntfy push, generic webhook, and MQTT publish per alert
```

All in one asyncio process supervised by systemd. The Pi serves the
dashboard on its own port and the data never leaves the LAN unless
the user explicitly enables ntfy / webhook / MQTT.

---

## Hardware bill of materials

The reference build that everything is tested against:

| Item | Specific part used | ~Cost (USD, May 2026) | Why |
| --- | --- | --- | --- |
| **Single-board computer** | Raspberry Pi 5, 16 GB RAM | $120 | Two USB 3 ports, native BLE 5.0, enough RAM for the asyncio process + 700 MB rolling DB |
| **microSD card** | SanDisk Extreme Pro 256 GB A2 (or Samsung Pro Endurance) | $35 | A2-rated random IO matters for the SQLite write rate; endurance matters because the DB churns continuously |
| **PSU** | Official Pi 5 27 W USB-C PSU | $15 | Pi 5 + 2× SDRs + Bluetooth radio is right at the edge of a generic 3 A supply; the official 5 A unit prevents under-voltage throttling |
| **Sub-GHz SDR** (device 0) | Nooelec NESDR SMArt v5 (R820T2 tuner, TCXO) | $35 | R820T2 has the best sensitivity in the 300-900 MHz range where keyfobs / garage / weather sensors live. TCXO holds frequency lock for protocol decoding. |
| **Wide-band SDR** (device 1) | Nooelec SMArTee XTR v5 (E4000 tuner) | $40 | E4000 reaches up to 2.2 GHz so the same sweep loop that reads ISM bands also covers ADS-B (1090 MHz), GPS L1 (1575 MHz), GLONASS (1602 MHz), and weather satellite downlinks |
| **Antennas** | 2× telescoping dipole (e.g. NESDR Bargain 2) | $30 | Adjustable for the 4× wavelength range we cover. Best results come from extending the antenna to ~λ/4 of the band you care about most (~17 cm for 433 MHz). |
| **Powered USB hub** *(optional but recommended)* | Anker 4-port USB 3.0 powered hub | $30 | Decouples the SDRs' inrush current from the Pi's own rail and lets the Pi sit further from antenna interference |
| **USB Bluetooth 6.0 adapter** *(optional)* | Realtek `0bda:a760` BT 6.0 dongle with external antenna | $25-40 | The Pi's onboard Cypress radio is BT 5.0 and uses an internal PCB antenna; a BT 6.0 USB stick with an external antenna noticeably extends the BLE detection range. Bring it up as `hci1`; the BLE scanner can be pointed at it via `[scanners.ble] adapter = "hci1"`. The onboard hci0 stays available for the Find-My broadcaster + honeypot. See `deploy/bt-hci1-up.service`. |
| **Enclosure** | Pi 5 case with active cooling fan + cutouts for two USB extensions | $25 | The CPU runs ≈55 °C continuously; passive cases throttle |
| **Total** | | **~$330** (+$25-40 with the BT 6.0 dongle) | |

Notes:

- A second USB Wi-Fi monitor adapter (e.g. Alfa AWUS036ACS) would unlock
  802.11 probe-request capture in addition to beacons. The current code
  uses `iw dev wlan0 scan` for active beacon scanning only — adding a
  monitor adapter is a forward-compatible addition.
- A Pi UPS HAT is on the v1.5 roadmap for "survives a power cut" threat
  modelling; not required for v1.
- A Hailo-8L AI HAT is on the v2 roadmap for on-device ML anomaly
  scoring; the current code uses analytical scoring (Welford + entropy
  + rule predicates) and runs comfortably on the CPU.

---

## What each radio does

### BLE scanner (`hci0` by default, configurable)

Passive scan via [bleak](https://github.com/hbldh/bleak) with a
detection callback that fires on every advertisement. Per-event we
extract MAC, RSSI, advertised name, manufacturer-data hex, and
service UUIDs.

The adapter is selected by `[scanners.ble] adapter` in
`watchtower.toml`. `"hci0"` is the Pi's onboard Cypress radio; if you
plug in a USB BT 6.0 adapter for better range, set this to `"hci1"`
and enable `bt-hci1-up.service` (in `deploy/`) so the adapter comes
up at boot. The onboard `hci0` stays available for the Find-My
broadcaster + honeypot, both of which use bluetoothctl's default
controller.

Crucial extras:

- **Deduplication** — same `(mac, content_hash)` is suppressed for
  5 s. BLE devices broadcast every 100 ms and storing every one
  would be wasteful; one event per ~5 s per stationary device is
  plenty for presence tracking.
- **OUI lookup** — first 3 bytes of any non-randomized MAC map to
  the IEEE-registered manufacturer. Watchtower bundles the full
  ≈50 k-entry IEEE OUI registry (refreshed monthly from
  `standards-oui.ieee.org`) at `/var/lib/watchtower/oui-cache.txt`.
  Stable-MAC entities self-identify as "eero inc.", "Espressif",
  "Samsung", "Sagemcom", "TP-Link" etc. without any active probing.
- **Local friendly-name resolver** — advertised BLE names, Bluetooth Classic
  Remote Name results, trusted BlueZ aliases, standardized GATT Device
  Name/model fields, Wi-Fi WPS metadata, SSIDs, mDNS/DNS-SD, UPnP, DHCP, and
  reverse DNS are retained as confidence-scored candidates. The UI shows the
  winning name's provenance; an explicit user label always wins.
- **Authorized name decryption** — the Settings gear accepts keys from
  devices you own: Bluetooth Encrypted Advertising Data session key + IV,
  Bluetooth IRKs, and Google Fast Pair account keys. EAD names are decrypted
  passively with AES-CCM; IRKs resolve rotating private addresses; Fast Pair
  personalized names are accepted only after the protocol HMAC verifies.
  Keys are Fernet-encrypted with a separate mode-0600 master key at
  `/var/lib/watchtower/name-vault.key`; APIs never return secret material.
  No key guessing or brute force is implemented.
- **GATT prober** — when enabled, the prober briefly pauses the passive
  scan and tries a polite GATT connection to read public *Device Name*,
  manufacturer, and model characteristics. Devices that require pairing
  simply reject the read. Automatic probes do not collect serial numbers.
- **Apple Continuity decoder** — Apple devices broadcast a 0x4C00
  manufacturer-data prefix with an inner subtype byte. We decode
  AirDrop / AirPlay / Find-My / Nearby-Info / Proximity-Pairing
  model and state fields and surface them under the entity row. Rotating
  authentication and contact-derived hash material is not retained.
- **Apple ecosystem name fusion** — Bonjour discovery explicitly queries
  AirPlay, RAOP, Companion Link, device-info, mobile-device, sleep-proxy,
  and HomeKit services. Watchtower separates human service-instance names
  from models and opaque identifiers, normalizes RAOP prefixes, and records
  every result with protocol provenance. When Apple publishes an exact
  Bluetooth address in local-link TXT metadata, the name is copied to an
  already-observed matching BLE entity; no fuzzy or rotation-breaking join
  is attempted.

### Wi-Fi scanner (`wlan0`)

Calls `iw dev wlan0 scan` every 30 s and parses BSSIDs, SSIDs,
channels, RSSI, and security flags. Random-BSSID detection (locally
administered bit) feeds the rogue-hotspot rule. Vendor OUI is shared
with the BLE pipeline.

### Sub-GHz live decoder (`rtl_433`, SDR #0)

Spawns `rtl_433` as a subprocess that hops every 5 s across the
intrusion-relevant frequencies:

`315 MHz → 318 MHz → 345 MHz → 390 MHz → 433.92 MHz → 868.35 MHz`

with `-Y autolevel -Y squelch -g 40 -M stats:1:60 -M level`. Any
matching protocol record (key fob, weather sensor, TPMS, garage
remote, generic OOK / FSK device) emits a `subghz_protocol_decoded`
event with the model name. rtl_433 ships with ~275 protocol decoders;
Watchtower honors all of them.

A heartbeat is logged every 60 s with frame counts so a quiet RF
environment is distinguishable from a stuck tuner.

### Mid-band sweep (SDR #1)

`pyrtlsdr` driven sweep of 36 frequencies covering:

- 25 MHz (HF reference)
- 88-216 MHz (FM broadcast, aviation VHF, marine, business radio,
  amateur 2 m, NOAA weather, VHF TV)
- 303 / 315 / 318 / 345 / 390 / 418 / 433.92 / 462.5 / 488 MHz
  (keyfob / TPMS / garage / ISM / FRS-GMRS / UHF TV)
- 617-944 MHz (5G band 71, LTE 700/850, **EU LoRa 868**, GSM 900,
  US LoRa / Z-Wave 915)
- 1090 MHz (ADS-B aircraft transponders)
- 1350-1675 MHz (cellular L-band, GPS L1, GLONASS, weather sat
  downlinks)

The sub-GHz priority frequencies are listed *twice* in the sweep so
they are revisited every ~3 s, while wider context bands are visited
once per outer cycle. Default dwell is 0.5 s. Energy at every dwell
is logged as a midband event; if a `<1 GHz` priority band exceeds
its rolling baseline by more than 1 dB, **midband captures the IQ
samples** that detected the spike + 500 ms tail, writes them to
`/var/lib/watchtower/sub_captures/{freq}-{ts}.cu8`, and enqueues a
job to the offline decoder.

### Sub-GHz offline decoder (`sub_decoder.py`)

The dedicated `rtl_433` process can only listen at one frequency at
a time. The sweep covers many. So when midband sees an energy spike,
the offline decoder runs `rtl_433 -r FILE -f {freq}` against the
saved IQ. Any matching protocol becomes a `subghz_scanner` event
tagged with `_decoded_offline=true`. This trades latency (decode
happens up to a few seconds after the burst) for **multi-frequency
coverage from a single SDR**.

### Unwanted location-tracker listener and clustering

The passive BLE scanner recognizes four protocol-backed families:

- legacy Apple Find My manufacturer data (`0x4C 0x00 0x12`);
- Tile-assigned service UUIDs (`0xFD84`, `0xFEEC`, `0xFEED`) and
  Tile's Bluetooth company ID (`0x067C`);
- Google Find Hub `0xFEAA` frames, including the explicit `0x41`
  unwanted-tracking-protection state;
- the cross-platform Detecting Unwanted Location Trackers service-data
  UUID (`0xFCB2`), including network provider and near-owner/separated state.

The cluster tracker:

- Joins **rotating MAC addresses** back into stable cluster IDs by
  matching consecutive observations on RSSI continuity (the
  rotating MAC changes every ~15 minutes but the RSSI doesn't jump).
- Computes **Jaccard sensor co-presence** between each cluster and each
  enrolled anchor over a 1-day window. This is contextual correlation,
  not proof of ownership or proof that the tracker travelled with a person.
- Alerts on protocol confidence, separated state, proximity, and the history
  of each individual cluster. Unrelated neighbors' devices cannot combine
  into one persistent-tracker alert.

Apple/Tile owner labels are not present in their radio advertisements.
Watchtower therefore does not claim to decrypt a stranger's identity; use
iOS/Android unwanted-tracker alerts for the authorized physical-identification
and disablement flow. User-owned tracker catalog labels remain supported.

### Local identity controls

Open **Settings → Friendly names & authorized decryption**, enter the setup
token, then load devices. From there you can:

- run a bounded Bluetooth Classic inquiry and import Remote Name results;
- explicitly pair an owned device, enabling BlueZ identity resolution and
  trusted aliases and importing EAD key material when the authenticated
  characteristic permits it;
- import a 16-byte Fast Pair account key and request the device's personalized
  name, a 24-byte EAD session-key/IV bundle, or a 16-byte Bluetooth IRK;
- enable or disable automatic Classic and LAN friendly-name discovery.

The key label is only a local description. A decrypted name is promoted only
after AES-CCM or Fast Pair HMAC authentication succeeds; an IRK identity is
promoted only after its address hash resolves. Removing a key stops future
decryption while retaining past name evidence for auditability.

### Find-My owned-tracker catalog

If you own AirTags / Find-My-enabled accessories, you can extract
each accessory's **master secret** (28 B EC P-224 private key + 32 B
symmetric key) using
[OpenHaystack on macOS](https://github.com/seemoo-lab/openhaystack)
and paste it into the Find-My tab. Watchtower then:

1. Pre-computes the next ~7 days of slot-rotated EC P-224 public keys
   for that tracker (ANSI X9.63 KDF, deterministic);
2. Stores the 22-byte payload slice + expected MAC for each slot in
   `findmy_key_catalog`;
3. On every Find-My BLE event, looks up the observed payload's
   pubkey-22 against the catalog. Match → labels the event as that
   tracker.

This is the only way to *cryptographically* identify a Find-My
accessory as yours; everyone else's keys are EC-P224-private to them.
Master secrets are stored as side files at
`/var/lib/watchtower/findmy_owned_secrets/` mode 0600.

### OpenHaystack-style Find-My broadcaster

Watchtower can also *broadcast* its own Find-My beacon (Pi-as-AirTag).
A self-generated EC P-224 keypair is persisted at
`/var/lib/watchtower/findmy_tracker.key.pem`. Useful for verifying
that a friend's iPhone receives the beacon (proof the listener path
works), and as a calibration emitter for testing Find-My alerting.

### BLE honeypot

Optional. Periodically rotates the Pi's local BLE name through a
small catalog of plausible everyday device names ("Tesla Model Y",
"AirPods Pro", "Hue Bridge", …) and watches `bluetoothctl devices
Connected` for inbound GATT connection attempts. Anyone who sees
"AirPods Pro" advertised, decides to connect, and tries to read GATT
characteristics fires the `honeypot_engaged` rule.

---

## Detection rules

All rules live in `analytics.py:_evaluate_rules`. Each runs on every
analytics tick (every 30 s). Severity drives dashboard color and ntfy
priority; thresholds and toggles live in the **Settings** tab and
take effect immediately without restart.

| Rule | Fires when |
| --- | --- |
| `anchor_absent_unknown_linger` | An unknown entity has been continuously present for longer than `linger_threshold_sec` (default 600 s) while no anchor is home |
| `unknown_keyfob_emission` | A sub-GHz **key-fob** protocol was decoded (315 / 433 / 868 MHz, etc.) and we don't have a household device with that protocol fingerprint enrolled |
| `unknown_garage_emission` | Same, but for garage-door protocols (Liftmaster Security+, Genie Intellicode, Chamberlain, Marantec, Stanley) |
| `airtag_findmy_present` | A protocol-confirmed Apple, Tile, or DULT tracker is strongly in range; separated state increases its risk score |
| `findmy_persistent_tracker` | The same unclassified tracker cluster has been present for ≥ `findmy_persistent_min_minutes_per_day` (default 180 min) on each of the last `findmy_persistent_min_consecutive_days` (default 3) days |
| `first_time_visitor_after_hours` | New entity first-seen between `after_hours_start_utc` and `after_hours_end_utc` (default 22:00-06:00 UTC). Requires at least one anchor enrolled so a fresh setup doesn't blast alerts |
| `close_unknown_signal` | Unknown BLE entity with avg RSSI > `close_perimeter_rssi_dbm` (default −50 dBm) and recurring presence (skips stationary IoT) |
| `rogue_hotspot` | Named AP beacon with a locally-administered BSSID that is genuinely new, repeats, and is stronger than −55 dBm. Established APs and the Watchtower recovery SSID are excluded |
| `honeypot_engaged` | Inbound GATT connection to the Pi's lure name |
| `flipper_zero_detected` | Official `Flipper <device-name>` BLE format and 0x3080–0x3083 serial-service UUID appear together. Name-only matches are informational to avoid easy spoofing |
| `multi_signal_intrusion` | At least two independent signal families occur in a five-minute episode, the context-adjusted score crosses its threshold, and one signal is decisive (key-fob/garage traffic, honeypot contact, or high-confidence Flipper detection). Multiple BLE symptoms never stack as independent evidence |

Severity is one of `critical / high / medium / low` and drives the
dashboard banner color and (when configured) the ntfy push priority.

---

## The dashboard on port 80

| Tab | What you see |
| --- | --- |
| **Overview** | Hero state (CALM / WATCHING / EYES UP / SETUP / AWAY · QUIET), explainable presence episodes and short-lived anonymous BLE flows, live RF radar with RSSI as radial distance, top anomalies, scanner activity bars, baseline learning progress, and the "entropy of the room" envelope plot |
| **Discover** | Ranked enrollment queue containing the top 30 recent, unclassified candidates that have repeated observations, strong name evidence, or an Apple grouped signal. One-tap classify into Anchor / Satellite / Known guest / Untrusted. |
| **Entities** | Searchable, paged inventory of tracked radio identities with explicit “showing X of Y” counts, anomaly bars, and regularity meters. Each row shows source antenna + frequency band and IEEE OUI vendor when known. |
| **Timeline** | 1 h / 6 h / 24 h / 3 d / 7 d scrubbable visit timeline, color-coded by classification and anomaly score |
| **Spectrum** | Live energy waterfall per band (HF / FM / VHF / NOAA / Keyfob-303 / Keyfob-315 / TPMS-345 / Garage-390 / EU-Keyfob-418 / ISM-433 / FRS-GMRS / EU-SRD-868 / ISM-902 / Cellular-850 / LTE-700 / ADS-B / GPS / Sat-DL …), plus the protocol-decode log for any sub-GHz traffic the live + offline rtl_433 caught |
| **Find-My** | Live observer table (rotating MACs in the last 5 min), stable cluster list with co-presence-inferred owners, owned-tracker catalog with paste-master-secret enrollment, daily presence chart |
| **Zones** | Calibrated locations from phone probe captures |
| **Alerts** | Rule fires with severity, structured evidence, ack + thumbs up/down feedback (the feedback signal becomes training data for v2's ML) |
| **Settings** | Per-rule on/off toggles, anomaly thresholds, after-hours window, ntfy / webhook / MQTT integration setup, danger-zone DB tools |

A separate mobile-first webapp lives at `/probe`: walk to a location,
dwell 30 s, save the RF fingerprint as a zone. Used during initial
setup to tell the system the difference between "Front Porch" and
"Driveway".

---

## Performance and concurrency model

Single asyncio process, 5 cooperatively-scheduled tasks plus a
worker thread pool:

- **Scanner tasks** (BLE, Wi-Fi, sub-GHz, mid-band) — push events
  onto the bus
- **Analytics task** — drains 30 s worth of events, runs
  enrichment + rule evaluation, writes to SQLite. Offloaded to the
  thread pool so the asyncio loop stays responsive.
- **API server** — aiohttp serving `/api/*` JSON + static SPA + a
  background `_cache_warmer_loop` that recomputes the heaviest
  cache entries every 7 s in a thread so dashboard polls always
  serve from a warm cache.
- **GATT prober** task — opportunistic active naming
- **Honeypot** task (optional) — rotating BLE lure
- **Find-My broadcaster** task (optional) — Pi-as-AirTag

SQLite is opened with WAL journaling, `synchronous = NORMAL`, 64 MB
page cache, 256 MB mmap, and 5 s busy timeout. Every API endpoint
that touches the DB does so via `asyncio.to_thread` so a 200 ms
query never blocks the event loop. Hot endpoints (`/api/state`,
`/api/findmy/observers`, `/api/findmy/clusters`) are server-side
cached for 4-30 s so the dashboard's 5-second poll cadence rarely
hits the DB.

Live measurements on the reference build:

- BLE event rate: ≈10 events/s during normal household activity
- Database growth: ~700 MB / 24 h (with 7-day retention this caps
  at ~5 GB; pruner keeps it bounded)
- Analytics step: 1-3 s typical, throttled inferences run every
  10 min and add ~30 s
- Dashboard parallel tab-switch (8 endpoints in parallel):
  ~270 ms wall-clock cold, ~10 ms warm

---

## Schema (v10)

SQLite at `/var/lib/watchtower/watchtower.db`. WAL mode.

| Table | Purpose | Retention |
| --- | --- | --- |
| `raw_events` | every BLE / Wi-Fi / sub-GHz / midband event, indexed on `(scanner, kind)`, `mac`, and `ts_unix` | **7 days** (configurable) |
| `entities` | one row per stable identity, with classification, anomaly score, regularity, OUI vendor | indefinite |
| `entity_visits` | one row per contiguous visit window (gap > 5 min closes a visit) | indefinite |
| `baseline_stats` | Welford running stats per `(feature × hour-of-week)` for anomaly scoring | indefinite |
| `alerts` | fired alerts with structured evidence + user feedback | indefinite |
| `zones` / `zone_samples` / `probe_captures` | RF fingerprints from the phone calibration page | indefinite / cleared on save |
| `findmy_clusters` / `findmy_cluster_macs` | rotating-MAC tracking + cluster identity | clusters pruned after 7 days idle |
| `findmy_owned_trackers` / `findmy_key_catalog` | user-owned AirTag enrollment + pre-computed slot pubkeys | indefinite |
| `presence_tracklets` / `presence_tracklet_macs` | temporary advertisement-shape continuity across BLE privacy-address handoffs; explicitly not permanent device identities | marked departed after 5 min idle; query window is bounded |
| `intrusion_signals` / `intrusion_episodes` | auditable multi-radio behavioral evidence, family-level scores, context, and alert decisions | signals pruned after 24 h; episodes retained |
| `analytics_state` | rollup watermark, runtime settings overrides, honeypot state | indefinite |

---

## Quickstart

### Pi prep (one-time, on the Pi)

```bash
ssh admin@watchtower.local "bash" < deploy/pi-setup.sh
sudo reboot   # to apply the DVB-driver blacklist
```

Installs `bluez`, `rtl-sdr`, `rtl-433`, `iw`, `sqlite3`; blacklists
the kernel DVB drivers so RTL-SDR can claim the dongles; installs
udev rules for non-root SDR access; adds `admin` to the `bluetooth`
and `plugdev` groups; creates the watchtower data directories.

### Develop on your host

```bash
cd /path/to/watchtower
uv sync
uv run pytest -v
```

67 unit tests + 8 integration tests (skipped unless
`WATCHTOWER_PI_HOST` is set). Mock-driven; doesn't require hardware.

### Deploy to the Pi

```bash
./deploy/deploy.sh watchtower.local
```

Rsyncs source, installs `uv` on the Pi, syncs the venv, drops the
example config to `/etc/watchtower/watchtower.toml` if not already
present, installs the systemd unit, and (re)starts the service.

### Verify

```bash
ssh admin@watchtower.local
systemctl is-active watchtower
sudo journalctl -u watchtower -f
```

Open `http://watchtower.local` in a browser.

### Network and boot recovery

Deployment installs `watchtower-wifi-reconnect.timer`. Once a minute, while
`wlan0` is disconnected, it unblocks the radio and tries every saved
NetworkManager Wi-Fi profile. Saved profiles retry indefinitely and Wi-Fi
power saving is disabled. If none connects, the Pi starts an open
`Watchtower` recovery SSID at `http://10.42.0.1/`; NetworkManager shared mode
provides DHCP, DNS forwarding, and NAT. The hotspot pauses briefly every five
minutes to retry known client networks and returns if none connects. On first
install, if NetworkManager has no Wi-Fi
profiles, the installer migrates Raspberry Pi Imager's root-only
`/boot/firmware/network-config` into netplan without copying credentials into
this repository.

Open the Settings gear in the dashboard to scan nearby networks, select an
SSID, choose WPA2/WPA3/open security, and connect. Wi-Fi mutations require a
setup token so an unauthenticated browser on the LAN cannot replace the Pi's
network configuration. Retrieve the token once on the Pi:

```bash
cat /etc/watchtower/wifi-admin.token
```

First-time setup from a client directly connected to the recovery subnet is
the narrow exception: while the fallback AP is active, a `10.42.0.0/24`
client may submit one connection without a token. Forgetting profiles and all
ordinary LAN changes remain token-protected.

The browser keeps that token in `sessionStorage` only. Passwords are handed to
a root-owned NetworkManager helper through a mode-0600 runtime file, never a
shell command or process argument. The helper activates the new profile before
removing an older duplicate, and the recovery timer keeps retrying every saved
SSID after reboot or an outage.

The main service retries indefinitely at 15-second intervals after a failure,
each radio scanner restarts independently after a transient failure, and SQLite-locked event batches are queued for retry rather than discarded.

### First-run flow

1. Open the dashboard. State will be **SETUP**.
2. Click **Discover**. Mark your phone (look for "phone (random
   MAC)" with high observation count, or your phone's local name)
   as **Anchor**. Mark your watch / earbuds / kids' phones as
   **Satellite**.
3. Open `/probe` on your phone, pick a location (Front Porch,
   Driveway, …), tap **Start capture · 30 s**, and stand still.
   Save the fingerprint. Repeat for every meaningful zone.
4. *(Optional)* If you own AirTags, open **Find-My → Owned
   trackers**, run OpenHaystack on macOS to extract each
   accessory's master secret, paste in `tracker_id, name, ec
   private (28 B base64), symmetric key (32 B base64)`, save.
5. *(Optional)* Configure ntfy / webhook / MQTT in **Settings →
   Integrations** to receive push alerts off-device.
6. State should switch to **CALM** (anchor home) or **AWAY ·
   QUIET** (anchor away). Detection rules are now armed.

---

## Configuration

Settings live in `/etc/watchtower/watchtower.toml` (example at
`config/watchtower.example.toml`). Detection thresholds and
per-rule toggles are tunable from the **Settings** tab in the
dashboard at runtime — no restart needed.

The most-edited keys:

| Key | Default | Notes |
| --- | --- | --- |
| `[scanners.subghz] rtl_433_args` | hops 315 / 318 / 345 / 390 / 433.92 / 868.35 MHz with `-Y autolevel -g 40 -H 5` | Add or remove `-f` arguments here to extend coverage |
| `[scanners.midband] sweep_freqs_hz` | 36-frequency sub-GHz-dense list, see `scanners/midband.py` | Each frequency listed twice gets ~2× coverage relative to others |
| `[scanners.midband] dwell_seconds` | 0.5 | Lower = faster sweep, more chance to catch transient bursts; higher = more stable energy reading |
| `[storage] retention_days` | 7 | Pruner removes raw_events older than this |
| `[storage] db_path` | `/var/lib/watchtower/watchtower.db` | |

Settings UI (toggleable from the dashboard at runtime):

- All 9 detection rules: per-rule enable/disable
- `anomaly_severity_high_threshold` / `medium_threshold`
- `linger_threshold_sec`, `anchor_timeout_sec`,
  `close_perimeter_rssi_dbm`, after-hours window
- ntfy URL/topic/min-severity, webhook URL, MQTT host/port/topic
  prefix
- Honeypot enable + rotation cadence
- Find-My tracker broadcaster enable
- Local BLE name-resolution probing enable
- Bluetooth Classic remote-name discovery and LAN mDNS/UPnP/DHCP enrichment
- Encrypted EAD / Fast Pair / IRK key management for owned devices

---

## Roadmap

- **v1.5 (next)** — UPS HAT support, heartbeat / watchdog, tamper detection,
  and stronger multi-sensor tracker co-travel scoring
- **v2** — vulcan (or other) cloud sink for cold-tier storage, ML
  training pipeline using user feedback as labels, Hailo-8L NPU for
  on-device autoencoder anomaly scoring
- **v3** — multi-Pi mesh with TDOA localization, Frigate / camera
  fusion for zone-correlated tracking, acoustic glass-break detection

---

## Project layout

```
src/watchtower/
├── cli.py                  # entrypoint: starts all the asyncio tasks
├── bus.py                  # asyncio pub/sub event bus
├── events.py               # Event / Features dataclasses, EventKind enum
├── config.py               # TOML loader + dataclass schemas
├── scanners/
│   ├── ble.py              # bleak passive scan + dedup + Apple Continuity decode
│   ├── wifi.py             # iw scan parser
│   ├── subghz.py           # rtl_433 child process manager
│   └── midband.py          # pyrtlsdr sweep + spike-detect IQ capture
├── sub_decoder.py          # offline rtl_433 -r capture decoder
├── apple_continuity.py     # 0x4C00 subtype decoders (Find-My, Nearby-Info,
│                           #   Proximity-Pairing 25-model lookup, AirDrop)
├── flipper.py              # confidence-scored official BLE fingerprint
├── rf_identity.py          # stable IDs from decoded/rolling RF envelopes
├── wifi.py                 # safe NetworkManager status/request API
├── findmy_clusters.py      # rotating-MAC cluster tracker + co-presence inference
├── findmy_owned.py         # owned-tracker enrollment + EC-P224 catalog
├── findmy_tracker.py       # Pi-as-AirTag broadcaster
├── honeypot.py             # rotating BLE lure + connection log
├── active_probe.py         # GATT probe for unknown devices
├── name_crypto.py          # EAD/Fast Pair/IRK crypto + encrypted key vault
├── bluetooth_identity.py   # BlueZ names, pairing, authorized key/name reads
├── local_discovery.py      # mDNS/DNS-SD, UPnP, DHCP, reverse-DNS names
├── oui.py                  # IEEE OUI registry loader (≈50 k prefixes)
├── analytics.py            # enrichment + rules + alert dispatch
├── api.py                  # aiohttp HTTP server + JSON API + cache warmer
├── storage/
│   ├── schema.sql          # v8 schema
│   ├── db.py               # connection helper with PRAGMA tuning
│   └── pruner.py           # retention pruner
└── static/
    ├── index.html          # Alpine.js + Tailwind dashboard
    ├── probe.html          # mobile site-survey page
    └── assets/app.js       # ~1 k LOC dashboard logic

tests/                      # unit tests plus 8 Raspberry Pi integration tests
deploy/                     # systemd unit + pi-setup.sh + deploy.sh
docs/superpowers/           # design specs and milestone plans
```

---

## Licensing & non-goals

This is a personal-use security tool.

**Do not** deploy in shared housing without informed consent of all
residents — passive RF monitoring captures a lot of incidental
signal, and any household member's enrolled phone becomes part of
the inferred presence model.

Cellular IMSI capture is explicitly **not** implemented and is
illegal in most jurisdictions.

The project is open source under whatever license the repository
ships with; in spirit it's "do whatever, but don't deploy this
against people who haven't consented to being measured."
