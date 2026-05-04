"""Analytics pipeline: roll raw_events into entities, visits, baseline stats, and alerts.

Runs as a background task inside the watchtower service. Idempotent — uses
analytics_state to track watermark of last processed event_id.

M2/M3-lite scope:
- Entity = "ble:MAC" / "subghz:proto:id" / etc. (Full random-MAC defeat is M2-full work.)
- Visit = contiguous observations with gap < 5 min.
- Regularity = 1 - normalized entropy of visit-hour-of-week distribution.
- Anomaly score = weighted blend of (lingering-vs-history, anchor-absent-while-unknown-present, freshness, RSSI proximity).
- Baseline = Welford running stats per (feature × hour-of-week).
- Alerts = rule-based with anomaly score multiplier.
"""
from __future__ import annotations

import json
import logging
import math
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from ulid import ULID

from watchtower.storage.db import get_connection

log = logging.getLogger(__name__)

# Roll-up tunables (sensible v1 defaults; mirrored in DEFAULT_SETTINGS for runtime override).
VISIT_GAP_SEC = 300         # 5 min gap closes a visit
LINGER_THRESHOLD_SEC = 600  # 10 min linger = casing-class
ANCHOR_TIMEOUT_SEC = 600    # anchor absent > 10 min = "away"
RECENT_RSSI_FLOOR_DBM = -85 # ignore very-far devices for anomaly
SUBGHZ_HISTORICAL_RATIO = 5 # if we see >5x the historical rate of an unknown subghz protocol, flag

DEFAULT_SETTINGS = {
    "linger_threshold_sec": 600,
    "anchor_timeout_sec": 600,
    "close_perimeter_rssi_dbm": -50,
    "after_hours_start_utc": 22,
    "after_hours_end_utc": 6,
    "rule_anchor_absent_unknown_linger": True,
    "rule_unknown_keyfob_emission": True,
    "rule_unknown_garage_emission": True,
    "rule_airtag_findmy_present": True,
    "rule_first_time_visitor_after_hours": True,
    "rule_close_unknown_signal": True,
    "rule_rogue_hotspot": True,
    "rule_honeypot_engaged": True,
    "rule_findmy_persistent_tracker": True,
    "findmy_persistent_min_minutes_per_day": 180,
    "findmy_persistent_min_consecutive_days": 3,
    "anomaly_severity_high_threshold": 0.6,
    "anomaly_severity_medium_threshold": 0.4,
    # M3+ extensions:
    "active_probing_enabled": False,         # GATT probe to fetch friendly names
    "honeypot_enabled": False,                # rotating BLE lure broadcaster
    "honeypot_rotate_minutes": 30,            # cycle through lure list every N min
    "findmy_tracker_enabled": False,          # broadcast as a Find-My-compatible AirTag
    # ntfy push notifications:
    "ntfy_enabled": False,
    "ntfy_url": "https://ntfy.sh",            # base URL of ntfy server
    "ntfy_topic": "",                         # the topic; empty = disabled
    "ntfy_min_severity": "high",              # one of: low, medium, high, critical
    # External event sinks for active deterrence:
    "webhook_enabled": False,
    "webhook_url": "",                        # POST alerts to this URL
    "mqtt_enabled": False,
    "mqtt_host": "",
    "mqtt_port": 1883,
    "mqtt_topic_prefix": "watchtower",
}

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def load_settings(db_path) -> dict:
    """Read overrides from analytics_state.settings_json; merge over defaults."""
    out = dict(DEFAULT_SETTINGS)
    try:
        with get_connection(db_path) as conn:
            row = conn.execute(
                "SELECT value FROM analytics_state WHERE key = 'settings_json'"
            ).fetchone()
            if row and row[0]:
                overrides = json.loads(row[0])
                for k, v in overrides.items():
                    if k in out:
                        out[k] = v
    except Exception:  # noqa: BLE001
        pass
    return out


def save_settings(db_path, settings: dict) -> None:
    """Persist settings overrides."""
    cleaned = {k: v for k, v in settings.items() if k in DEFAULT_SETTINGS}
    with get_connection(db_path) as conn:
        conn.execute(
            "INSERT INTO analytics_state(key, value, updated_unix) VALUES ('settings_json', ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_unix = excluded.updated_unix",
            (json.dumps(cleaned), int(time.time())),
        )


def _dispatch_external(settings: dict, alert_payload: dict) -> None:
    """Fire-and-forget external delivery: ntfy push, webhook POST, MQTT publish.

    Called inline from _fire(). Non-blocking-ish: short timeouts, exceptions
    swallowed (logged) so a flaky external never breaks rule evaluation.
    """
    severity = alert_payload.get("severity") or "medium"
    rule_id = alert_payload.get("rule_id") or "alert"
    sev_rank = _SEVERITY_RANK.get(severity, 1)

    # ---- ntfy ----
    if settings.get("ntfy_enabled") and settings.get("ntfy_topic"):
        min_sev = _SEVERITY_RANK.get(settings.get("ntfy_min_severity") or "high", 2)
        if sev_rank >= min_sev:
            try:
                import urllib.request
                base = (settings.get("ntfy_url") or "https://ntfy.sh").rstrip("/")
                topic = settings["ntfy_topic"].strip("/")
                url = f"{base}/{topic}"
                evidence = alert_payload.get("evidence") or {}
                ev_brief = " · ".join(f"{k}={v}" for k, v in list(evidence.items())[:4])
                body = f"[{severity.upper()}] {rule_id}\n{alert_payload.get('entity_id') or ''}\n{ev_brief}".encode("utf-8")
                # ntfy reads Title/Priority/Tags from headers
                priority_map = {"low": 2, "medium": 3, "high": 4, "critical": 5}
                tag_map = {"low": "speech_balloon", "medium": "warning", "high": "rotating_light", "critical": "rotating_light"}
                req = urllib.request.Request(
                    url,
                    data=body,
                    headers={
                        "Title": f"Watchtower · {rule_id}",
                        "Priority": str(priority_map.get(severity, 3)),
                        "Tags": tag_map.get(severity, "warning"),
                        "Click": "http://watchtower.local:8080/",
                    },
                )
                urllib.request.urlopen(req, timeout=4)
            except Exception:  # noqa: BLE001
                log.exception("ntfy dispatch failed")

    # ---- webhook ----
    if settings.get("webhook_enabled") and settings.get("webhook_url"):
        try:
            import urllib.request
            req = urllib.request.Request(
                settings["webhook_url"],
                data=json.dumps(alert_payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=4)
        except Exception:  # noqa: BLE001
            log.exception("webhook dispatch failed")

    # ---- MQTT ----
    if settings.get("mqtt_enabled") and settings.get("mqtt_host"):
        try:
            import paho.mqtt.publish as mqtt_publish
            prefix = (settings.get("mqtt_topic_prefix") or "watchtower").strip("/")
            topic = f"{prefix}/alerts/{severity}"
            mqtt_publish.single(
                topic,
                payload=json.dumps(alert_payload),
                hostname=settings["mqtt_host"],
                port=int(settings.get("mqtt_port") or 1883),
                keepalive=10,
                retain=False,
            )
        except Exception:  # noqa: BLE001
            log.exception("mqtt dispatch failed")


def _hour_of_week(ts_unix: int) -> int:
    """0..167. Monday 00:00 UTC = 0, Sunday 23:00 UTC = 167."""
    import datetime
    dt = datetime.datetime.fromtimestamp(ts_unix, tz=datetime.timezone.utc)
    return dt.weekday() * 24 + dt.hour


def _apple_continuity_kind(mfr_hex: str) -> str | None:
    """Decode Apple Continuity manufacturer data; return a stable group label.

    For AirPods/Beats with a recognized model number, we return the SPECIFIC
    model (e.g., "AirPods-Pro-2") so each model collapses to its own entity.
    For other subtypes we return the subtype name. None for non-Apple data.
    """
    from watchtower.apple_continuity import decode_continuity, label_for_decoded
    decoded = decode_continuity(mfr_hex or "")
    if not decoded:
        return None
    return label_for_decoded(decoded).replace("/", "-")


def _ble_entity_id(features: dict, scanner: str, kind: str) -> str | None:
    """Decide what *kind of identity* a BLE event represents.

    Strategy: collapse random-MAC noise into vendor/service-keyed groups so the
    dashboard surfaces meaningful devices instead of one row per 15-minute MAC rotation.

    - Universal (non-random) MAC → stable per-device identity ("ble:mac:aa:bb:..").
    - BLE local name present → identity by local name ("ble:named:Bose QC45").
    - Apple Continuity manufacturer data with known subtype → grouped per subtype
      ("ble:apple:Find-My"), since those rotate keys but the subtype is stable.
    - Random MAC, no name, no useful Continuity subtype → return None
      (counts toward baseline noise but does not create an entity row).
    """
    mac = features.get("mac")
    if not mac:
        return None
    if features.get("is_random_mac") is False:
        return f"ble:mac:{mac.lower()}"
    name = (features.get("local_name") or "").strip()
    if name:
        # Named devices keep their identity even when MAC rotates. Devices
        # with very generic names (e.g., a single space, "BLE", "iPhone")
        # would still group together — acceptable for v1.
        if 2 <= len(name) <= 64:
            return f"ble:named:{name}"
    mfr_hex = features.get("manufacturer_data_hex") or ""
    apple_kind = _apple_continuity_kind(mfr_hex)
    if apple_kind:
        # Group by Apple Continuity subtype. Multiple iPhones broadcasting
        # Nearby-Info will share an entity — we report population, not per-device.
        return f"ble:apple:{apple_kind}"
    # Otherwise: random MAC with no useful identifier → background noise.
    return None


def _entity_id_for(ev_features: dict, scanner: str, kind: str) -> str | None:
    """Map an event to an entity_id. Returns None if event is not entity-bearing."""
    if scanner == "ble_scanner":
        return _ble_entity_id(ev_features, scanner, kind)
    if scanner == "subghz_scanner":
        proto = ev_features.get("protocol")
        decoded = ev_features.get("decoded") or {}
        ident = decoded.get("id") or decoded.get("rolling_code") or decoded.get("button_id") or "unknown"
        if not proto:
            return None
        return f"subghz:{proto}:{ident}"
    if scanner == "wifi_scanner":
        mac = ev_features.get("mac")
        if not mac:
            return None
        # WiFi probe requests use random MACs heavily — same logic as BLE.
        if ev_features.get("is_random_mac") is False:
            return f"wifi:mac:{mac.lower()}"
        ssid = (ev_features.get("ssid") or "").strip()
        if ssid:
            return f"wifi:ssid:{ssid}"
        return None
    # midband -> baseline-only, no entity
    return None


def _classify_entity_kind(scanner: str, kind: str, features: dict) -> str:
    if scanner == "ble_scanner":
        services = features.get("service_uuids") or []
        if any(uuid in services for uuid in ("fd6f",)):
            return "ble_findmy"
        if features.get("local_name") and "AirPods" in str(features.get("local_name") or ""):
            return "ble_headphones"
        if features.get("is_random_mac"):
            return "ble_phone"
        return "ble_device"
    if scanner == "subghz_scanner":
        if kind == "keyfob_emission":
            return "subghz_keyfob"
        if kind == "garage_emission":
            return "subghz_garage"
        return "subghz_device"
    return "unknown"


def _welford_update(n: int, mean: float, m2: float, x: float) -> tuple[int, float, float]:
    n_new = n + 1
    delta = x - mean
    mean_new = mean + delta / n_new
    delta2 = x - mean_new
    m2_new = m2 + delta * delta2
    return n_new, mean_new, m2_new


def _stddev(n: int, m2: float) -> float:
    return math.sqrt(m2 / n) if n > 1 else 0.0


def _normalized_entropy_of_distribution(counts: list[int]) -> float:
    """Shannon entropy / log(K), where K = number of bins. Returns 0..1.

    Empty/zero distribution returns 0.0.
    Uniform distribution returns 1.0.
    """
    total = sum(counts)
    if total == 0:
        return 0.0
    k = len(counts)
    if k <= 1:
        return 0.0
    h = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            h -= p * math.log(p)
    h_max = math.log(k)
    return h / h_max if h_max > 0 else 0.0


class Analytics:
    """Runs roll-ups + scoring + alert generation. Call .step() periodically."""

    def __init__(self, db_path: Path | str) -> None:
        self._db = Path(db_path)

    def _get_state(self, conn, key: str, default: str) -> str:
        row = conn.execute("SELECT value FROM analytics_state WHERE key = ?", (key,)).fetchone()
        return row[0] if row else default

    def _set_state(self, conn, key: str, value: str) -> None:
        conn.execute(
            "INSERT INTO analytics_state(key, value, updated_unix) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_unix = excluded.updated_unix",
            (key, value, int(time.time())),
        )

    def step(self) -> dict[str, Any]:
        """Run one roll-up pass. Returns summary stats."""
        with get_connection(self._db) as conn:
            last_id = self._get_state(conn, "rollup_last_event_id", "")
            cutoff_unix = int(time.time()) - 7 * 86400  # only last 7d
            rows = conn.execute(
                """SELECT event_id, ts_unix, scanner, kind, features_json
                   FROM raw_events
                   WHERE event_id > ? AND ts_unix > ?
                   ORDER BY event_id ASC
                   LIMIT 50000""",
                (last_id, cutoff_unix),
            ).fetchall()

            if not rows:
                return {"processed": 0, "entities_touched": 0}

            # Aggregate: entity_id -> stats. Also collect per-scanner per-hour-of-week feature values.
            entity_seen: dict[str, dict[str, Any]] = defaultdict(lambda: {
                "scanner": "", "kind": "", "first": None, "last": None, "obs": 0,
                "rssis": [], "is_random_mac": None, "vendor": None, "name": None,
                "obs_log": [],   # list of (ts_unix, rssi) for visit segmentation
            })
            scanner_hour_counts: dict[tuple[str, int], int] = defaultdict(int)
            midband_hour_energy: dict[tuple[str, int], list[float]] = defaultdict(list)

            for event_id, ts_unix, scanner, kind, feats_json in rows:
                feats = json.loads(feats_json) if feats_json else {}
                hw = _hour_of_week(ts_unix)
                scanner_hour_counts[(scanner, hw)] += 1

                if scanner == "midband_scanner":
                    band = feats.get("band_name") or "unknown"
                    energy = feats.get("energy_dbm")
                    if energy is not None:
                        midband_hour_energy[(f"midband:{band}", hw)].append(float(energy))

                eid = _entity_id_for(feats, scanner, kind)
                if not eid:
                    continue
                e = entity_seen[eid]
                e["scanner"] = scanner
                e["kind"] = _classify_entity_kind(scanner, kind, feats)
                e["first"] = ts_unix if e["first"] is None else min(e["first"], ts_unix)
                e["last"] = ts_unix if e["last"] is None else max(e["last"], ts_unix)
                e["obs"] += 1
                # If this is Apple Continuity, decode and remember most recent state.
                if scanner == "ble_scanner":
                    mfr_hex = feats.get("manufacturer_data_hex") or ""
                    if mfr_hex.lower().startswith("4c00"):
                        from watchtower.apple_continuity import decode_continuity, short_state_summary
                        decoded = decode_continuity(mfr_hex)
                        if decoded:
                            e.setdefault("continuity_state", "")
                            summary = short_state_summary(decoded)
                            if summary:
                                e["continuity_state"] = summary
                rssi_int = None
                rssi = feats.get("rssi")
                if rssi is not None:
                    try:
                        rssi_int = int(rssi)
                        e["rssis"].append(rssi_int)
                    except (TypeError, ValueError):
                        pass
                e["obs_log"].append((ts_unix, rssi_int))
                e["is_random_mac"] = feats.get("is_random_mac") if e["is_random_mac"] is None else e["is_random_mac"]
                e["vendor"] = e["vendor"] or feats.get("vendor_oui")
                e["name"] = e["name"] or feats.get("local_name")

            # Upsert entities.
            now = int(time.time())
            for eid, e in entity_seen.items():
                rssis = e["rssis"]
                avg = sum(rssis) / len(rssis) if rssis else None
                lo = min(rssis) if rssis else None
                hi = max(rssis) if rssis else None
                continuity_state = e.get("continuity_state")
                conn.execute("""
                    INSERT INTO entities (
                        entity_id, scanner, kind, first_seen_unix, last_seen_unix,
                        visit_count, total_observations, is_random_mac, avg_rssi, min_rssi, max_rssi,
                        vendor, friendly_name, notes_inferred
                    ) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(entity_id) DO UPDATE SET
                        scanner = excluded.scanner,
                        kind = excluded.kind,
                        last_seen_unix = MAX(entities.last_seen_unix, excluded.last_seen_unix),
                        total_observations = entities.total_observations + excluded.total_observations,
                        avg_rssi = COALESCE(
                            (entities.avg_rssi * entities.total_observations + excluded.avg_rssi * excluded.total_observations)
                              / NULLIF(entities.total_observations + excluded.total_observations, 0),
                            excluded.avg_rssi),
                        min_rssi = MIN(COALESCE(entities.min_rssi, excluded.min_rssi), COALESCE(excluded.min_rssi, entities.min_rssi)),
                        max_rssi = MAX(COALESCE(entities.max_rssi, excluded.max_rssi), COALESCE(excluded.max_rssi, entities.max_rssi)),
                        vendor = COALESCE(entities.vendor, excluded.vendor),
                        friendly_name = COALESCE(entities.friendly_name, excluded.friendly_name),
                        notes_inferred = COALESCE(excluded.notes_inferred, entities.notes_inferred)
                """, (eid, e["scanner"], e["kind"], e["first"], e["last"],
                      e["obs"], 1 if e["is_random_mac"] else 0 if e["is_random_mac"] is False else None,
                      avg, lo, hi, e["vendor"], e["name"], continuity_state))

            # Update baseline_stats with Welford for scanner counts (per hour-of-week).
            for (scanner, hw), cnt in scanner_hour_counts.items():
                row = conn.execute(
                    "SELECT n, mean, m2 FROM baseline_stats WHERE feature = ? AND hour_of_week = ?",
                    (f"{scanner}_count", hw),
                ).fetchone()
                if row:
                    n, mean, m2 = row
                else:
                    n, mean, m2 = 0, 0.0, 0.0
                n2, mean2, m22 = _welford_update(n, mean, m2, float(cnt))
                conn.execute("""
                    INSERT INTO baseline_stats (feature, hour_of_week, n, mean, m2, last_updated_unix)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(feature, hour_of_week) DO UPDATE SET
                        n = excluded.n, mean = excluded.mean, m2 = excluded.m2,
                        last_updated_unix = excluded.last_updated_unix
                """, (f"{scanner}_count", hw, n2, mean2, m22, now))

            # Midband band energy baseline.
            for (feat, hw), values in midband_hour_energy.items():
                if not values:
                    continue
                avg = sum(values) / len(values)
                row = conn.execute(
                    "SELECT n, mean, m2 FROM baseline_stats WHERE feature = ? AND hour_of_week = ?",
                    (feat, hw),
                ).fetchone()
                n, mean, m2 = row if row else (0, 0.0, 0.0)
                n2, mean2, m22 = _welford_update(n, mean, m2, avg)
                conn.execute("""
                    INSERT INTO baseline_stats (feature, hour_of_week, n, mean, m2, last_updated_unix)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(feature, hour_of_week) DO UPDATE SET
                        n = excluded.n, mean = excluded.mean, m2 = excluded.m2,
                        last_updated_unix = excluded.last_updated_unix
                """, (feat, hw, n2, mean2, m22, now))

            # Roll up visits for entities we just touched, using the in-memory observation logs.
            self._update_visits_from_logs(conn, entity_seen)

            # Compute regularity + anomaly scores for ALL entities (cheap).
            self._score_entities(conn)

            # Evaluate rules → alerts.
            self._evaluate_rules(conn)

            # Update watermark.
            last_seen_id = rows[-1][0]
            self._set_state(conn, "rollup_last_event_id", last_seen_id)

            return {
                "processed": len(rows),
                "entities_touched": len(entity_seen),
                "high_water_id": last_seen_id,
            }

    def _update_visits_from_logs(self, conn, entity_seen: dict[str, dict]) -> None:
        """Append observation timestamps to entity_visits.

        Strategy: for each entity, find the most-recent existing visit. If the
        new observations connect to it (gap < VISIT_GAP_SEC), extend it.
        Otherwise close that visit and start a new one. This is incremental
        and idempotent across reruns.
        """
        for eid, data in entity_seen.items():
            obs = sorted(data["obs_log"], key=lambda x: x[0])
            if not obs:
                continue
            # Find the most-recent existing visit for this entity.
            row = conn.execute(
                "SELECT visit_id, start_unix, end_unix, observation_count, max_rssi, avg_rssi FROM entity_visits WHERE entity_id = ? ORDER BY end_unix DESC LIMIT 1",
                (eid,),
            ).fetchone()
            current = None
            if row:
                vid, vstart, vend, vcount, vmax, vavg = row
                # Connect if first new obs is within gap.
                if obs[0][0] - vend <= VISIT_GAP_SEC:
                    current = {
                        "visit_id": vid, "start": vstart, "end": vend,
                        "obs_count": vcount, "rssis": [],
                        "avg_seed_count": vcount, "avg_seed_value": vavg,
                        "max_rssi": vmax,
                    }
            new_visits: list[dict] = []
            for ts, rssi in obs:
                if current is None or (ts - current["end"]) > VISIT_GAP_SEC:
                    if current is not None:
                        new_visits.append(current)
                    current = {
                        "visit_id": str(ULID()), "start": ts, "end": ts,
                        "obs_count": 0, "rssis": [],
                        "avg_seed_count": 0, "avg_seed_value": None,
                        "max_rssi": None,
                    }
                current["end"] = ts
                current["obs_count"] += 1
                if rssi is not None:
                    current["rssis"].append(rssi)
                    if current["max_rssi"] is None or rssi > current["max_rssi"]:
                        current["max_rssi"] = rssi
            if current is not None:
                new_visits.append(current)

            for v in new_visits:
                # Re-compute incremental avg from seed + new rssis.
                seed_count = v["avg_seed_count"]
                seed_value = v["avg_seed_value"] or 0.0
                new_n = len(v["rssis"])
                total_n = seed_count + new_n
                if total_n > 0:
                    sum_existing = seed_value * seed_count
                    sum_new = sum(v["rssis"])
                    avg = (sum_existing + sum_new) / total_n
                else:
                    avg = None
                conn.execute("""
                    INSERT INTO entity_visits
                        (visit_id, entity_id, start_unix, end_unix, duration_sec, observation_count, avg_rssi, max_rssi)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(visit_id) DO UPDATE SET
                        end_unix = excluded.end_unix,
                        duration_sec = excluded.duration_sec,
                        observation_count = excluded.observation_count,
                        avg_rssi = excluded.avg_rssi,
                        max_rssi = excluded.max_rssi
                """, (v["visit_id"], eid, v["start"], v["end"], max(1, v["end"] - v["start"]),
                      v["obs_count"], avg, v["max_rssi"]))

            conn.execute(
                "UPDATE entities SET visit_count = (SELECT COUNT(*) FROM entity_visits WHERE entity_id = ?) WHERE entity_id = ?",
                (eid, eid),
            )

    def _roll_visits(self, conn, entity_ids: list[str]) -> None:
        """Build entity_visits from raw_events for the given entities. Idempotent: deletes the last open visit for each entity then rebuilds tail."""
        if not entity_ids:
            return
        cutoff_unix = int(time.time()) - 7 * 86400
        for eid in entity_ids:
            scanner_prefix, _, _ = eid.partition(":")
            scanner = "ble_scanner" if eid.startswith("ble:") else (
                "subghz_scanner" if eid.startswith("subghz:") else "wifi_scanner"
            )
            # Read raw_events for this entity over last 7d.
            mac_match = eid.split(":", 1)[1] if eid.startswith(("ble:", "wifi:")) else None
            rows = []
            if mac_match:
                rows = conn.execute(
                    """SELECT ts_unix, json_extract(features_json, '$.rssi') AS rssi
                       FROM raw_events
                       WHERE scanner = ? AND ts_unix > ?
                         AND lower(json_extract(features_json, '$.mac')) = ?
                       ORDER BY ts_unix ASC""",
                    (scanner, cutoff_unix, mac_match),
                ).fetchall()
            elif eid.startswith("subghz:"):
                _, proto_id = eid.split(":", 1)
                proto, _, ident = proto_id.partition(":")
                rows = conn.execute(
                    """SELECT ts_unix, json_extract(features_json, '$.rssi') AS rssi
                       FROM raw_events
                       WHERE scanner = ? AND ts_unix > ?
                         AND json_extract(features_json, '$.protocol') = ?
                       ORDER BY ts_unix ASC""",
                    (scanner, cutoff_unix, proto),
                ).fetchall()

            if not rows:
                continue

            # Wipe existing visits for this entity, rebuild from raw.
            conn.execute("DELETE FROM entity_visits WHERE entity_id = ?", (eid,))
            visits = []
            current_start = rows[0][0]
            current_end = rows[0][0]
            current_obs = 1
            current_rssis: list[int] = []
            if rows[0][1] is not None:
                try:
                    current_rssis.append(int(rows[0][1]))
                except (TypeError, ValueError):
                    pass

            for ts_unix, rssi in rows[1:]:
                if ts_unix - current_end > VISIT_GAP_SEC:
                    visits.append((current_start, current_end, current_obs, list(current_rssis)))
                    current_start = ts_unix
                    current_obs = 0
                    current_rssis = []
                current_end = ts_unix
                current_obs += 1
                if rssi is not None:
                    try:
                        current_rssis.append(int(rssi))
                    except (TypeError, ValueError):
                        pass
            visits.append((current_start, current_end, current_obs, current_rssis))

            for start, end, obs, rssis in visits:
                avg = sum(rssis) / len(rssis) if rssis else None
                hi = max(rssis) if rssis else None
                conn.execute("""
                    INSERT INTO entity_visits
                        (visit_id, entity_id, start_unix, end_unix, duration_sec, observation_count, avg_rssi, max_rssi)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (str(ULID()), eid, start, end, max(1, end - start), obs, avg, hi))

            conn.execute(
                "UPDATE entities SET visit_count = (SELECT COUNT(*) FROM entity_visits WHERE entity_id = ?) WHERE entity_id = ?",
                (eid, eid),
            )

    def _score_entities(self, conn) -> None:
        """Compute regularity + anomaly_score per entity."""
        now = int(time.time())
        # Anchor-aware: if no anchors are enrolled at all, skip the
        # "anchor-absent" anomaly contribution — every entity would be
        # flagged "while away" and the dashboard would be wall-to-wall red.
        any_anchor_enrolled = conn.execute(
            "SELECT 1 FROM entities WHERE classification = 'anchor' LIMIT 1"
        ).fetchone() is not None
        # Pull all entities with their visits.
        rows = conn.execute(
            """SELECT e.entity_id, e.classification, e.last_seen_unix, e.visit_count, e.avg_rssi
               FROM entities e
               WHERE e.last_seen_unix > ?""",
            (now - 7 * 86400,),
        ).fetchall()

        for entity_id, classification, last_seen, visit_count, avg_rssi in rows:
            visits = conn.execute(
                """SELECT start_unix, duration_sec, max_rssi
                   FROM entity_visits
                   WHERE entity_id = ?
                   ORDER BY start_unix ASC""",
                (entity_id,),
            ).fetchall()

            # Regularity: entropy of visit hour-of-week distribution / log(N_buckets_observed).
            # 1.0 = perfectly regular (always same hour); 0.0 = chaotic.
            if visits:
                hw_counts = Counter(_hour_of_week(s) for s, _, _ in visits)
                # Compute over only the observed buckets (so a once-a-week visitor scores high).
                if len(hw_counts) >= 2:
                    counts = list(hw_counts.values())
                    h_norm = _normalized_entropy_of_distribution(counts)
                    regularity = 1.0 - h_norm
                else:
                    # Single bucket: regular by definition.
                    regularity = 1.0 if visit_count >= 3 else 0.5
            else:
                regularity = 0.0

            # Anomaly score (0..1). WiFi APs and very-high-volume stationary BLE
            # IoT (TVs, smart bulbs) are excluded from the linger/strong-RSSI
            # boosts — they're infrastructure, not a threat signal.
            is_wifi = entity_id.startswith("wifi:")
            is_stationary_ble = visit_count >= 1 and conn.execute(
                "SELECT total_observations FROM entities WHERE entity_id = ?",
                (entity_id,)
            ).fetchone()
            stationary = is_wifi or (is_stationary_ble and is_stationary_ble[0] > 5000)

            anomaly = 0.0
            # 1) Long lingering: longest visit > LINGER_THRESHOLD_SEC contributes —
            # but only for non-stationary entities.
            longest = max((d for _, d, _ in visits), default=0)
            if longest > LINGER_THRESHOLD_SEC and not stationary:
                anomaly += 0.35 * min(1.0, (longest - LINGER_THRESHOLD_SEC) / LINGER_THRESHOLD_SEC)
            # 2) Currently lingering AND no anchor in last ANCHOR_TIMEOUT_SEC.
            # Skip entirely if no anchors enrolled (everything would flag).
            currently_present = (now - last_seen) < 120
            if any_anchor_enrolled and currently_present and classification not in ("anchor", "satellite", "known_guest"):
                anchor_present = conn.execute(
                    "SELECT 1 FROM entities WHERE classification = 'anchor' AND last_seen_unix > ? LIMIT 1",
                    (now - ANCHOR_TIMEOUT_SEC,),
                ).fetchone()
                if not anchor_present:
                    anomaly += 0.4
            # 3) Strong RSSI (close perimeter) — also gated on non-stationary.
            if avg_rssi is not None and avg_rssi > -55 and not stationary:
                anomaly += 0.15
            # 4) Erratic visit pattern (low regularity).
            anomaly += 0.10 * (1.0 - regularity)
            anomaly = min(1.0, anomaly)

            conn.execute(
                """UPDATE entities SET regularity = ?, anomaly_score = ?,
                                       last_anomaly_at = CASE WHEN ? > 0.5 THEN ? ELSE last_anomaly_at END
                   WHERE entity_id = ?""",
                (regularity, anomaly, anomaly, now, entity_id),
            )

    def _evaluate_rules(self, conn) -> None:
        """Fire alerts for entities meeting rule criteria. Dedupe by (rule_id, entity_id, 5-min window)."""
        now = int(time.time())
        recent_threshold = now - 300
        S = load_settings(self._db)

        anchor_timeout = S["anchor_timeout_sec"]
        linger_threshold = S["linger_threshold_sec"]
        close_perim_rssi = S["close_perimeter_rssi_dbm"]
        after_start = S["after_hours_start_utc"]
        after_end = S["after_hours_end_utc"]

        anchor_present = conn.execute(
            "SELECT 1 FROM entities WHERE classification = 'anchor' AND last_seen_unix > ? LIMIT 1",
            (now - anchor_timeout,),
        ).fetchone()
        any_anchor_enrolled = conn.execute(
            "SELECT 1 FROM entities WHERE classification = 'anchor' LIMIT 1"
        ).fetchone() is not None
        # If no anchors are enrolled at all, we can't tell home vs away — mark unknown.
        if not any_anchor_enrolled:
            home_state = "unknown"
        elif anchor_present:
            home_state = "home"
        else:
            home_state = "away"

        # Hour-of-day for after-hours boost (local-time would be ideal but UTC works for v1).
        hour_utc = (now // 3600) % 24
        if after_start <= after_end:
            is_after_hours = after_start <= hour_utc < after_end
        else:  # wraps midnight, e.g. 22:00 -> 06:00
            is_after_hours = hour_utc >= after_start or hour_utc < after_end

        def _fire(rule_id, severity, entity_id, score, evidence):
            existing = conn.execute(
                "SELECT 1 FROM alerts WHERE rule_id = ? AND entity_id IS ? AND ts_unix > ? LIMIT 1",
                (rule_id, entity_id, recent_threshold),
            ).fetchone()
            if existing:
                return
            alert_id = str(ULID())
            conn.execute(
                """INSERT INTO alerts (alert_id, ts_unix, rule_id, severity, entity_id, score, home_state, evidence_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (alert_id, now, rule_id, severity, entity_id,
                 score, home_state, json.dumps(evidence)),
            )
            # Fire-and-forget external delivery (ntfy / webhook / MQTT).
            _dispatch_external(S, {
                "alert_id": alert_id, "ts_unix": now, "rule_id": rule_id,
                "severity": severity, "entity_id": entity_id, "score": score,
                "home_state": home_state, "evidence": evidence,
            })

        # ---- Rule 1: anchor_absent_unknown_linger ----
        # Only meaningful if we know who's home — i.e., at least one anchor enrolled.
        if any_anchor_enrolled and S["rule_anchor_absent_unknown_linger"]:
            candidates = conn.execute(
                """SELECT e.entity_id, e.last_seen_unix, e.avg_rssi, e.anomaly_score, e.regularity,
                          (SELECT MAX(duration_sec) FROM entity_visits v WHERE v.entity_id = e.entity_id AND v.end_unix > ?) AS longest_recent
                   FROM entities e
                   WHERE e.last_seen_unix > ?
                     AND e.classification IS NULL
                     AND COALESCE(e.anomaly_score, 0) >= 0.5""",
                (now - 600, now - 120),
            ).fetchall()
            for entity_id, last_seen, avg_rssi, anomaly, regularity, longest in candidates:
                if longest is None or longest < linger_threshold:
                    continue
                severity = "high" if (home_state == "away" and anomaly >= 0.6) else "medium"
                _fire("anchor_absent_unknown_linger", severity, entity_id, anomaly, {
                    "longest_recent_sec": longest,
                    "anomaly_score": round(anomaly, 3),
                    "regularity": round(regularity or 0, 3),
                    "avg_rssi": avg_rssi,
                    "home_state": home_state,
                })

        # ---- Rule 2: sub-GHz keyfob / garage emission from unknown source ----
        for kind, rule in (("subghz_keyfob", "unknown_keyfob_emission"),
                            ("subghz_garage", "unknown_garage_emission")):
            if not S.get(f"rule_{rule}", True):
                continue
            recent = conn.execute(
                """SELECT entity_id, last_seen_unix
                   FROM entities
                   WHERE kind = ? AND last_seen_unix > ? AND classification IS NULL""",
                (kind, recent_threshold),
            ).fetchall()
            for entity_id, last_seen in recent:
                _fire(rule, "high" if home_state == "away" else "medium",
                      entity_id, 0.8, {"home_state": home_state})

        # ---- Rule 3: AirTag / Find-My broadcast ----
        # Continuous Find-My presence near the property is worth flagging.
        if S["rule_airtag_findmy_present"]:
            airtag = conn.execute(
                """SELECT e.entity_id, e.last_seen_unix, e.avg_rssi
                   FROM entities e
                   WHERE e.entity_id IN ('ble:apple:Find-My', 'ble:apple:find-my')
                     AND e.last_seen_unix > ?
                     AND e.classification IS NULL""",
                (now - 600,),
            ).fetchone()
            if airtag:
                entity_id, last_seen, avg_rssi = airtag
                # Only fire when the Find-My broadcast is *close* — Apple devices
                # in range from a neighbor's apartment etc. are noise. Require
                # avg_rssi > -65 dBm (~10-15m through walls) to alert.
                if avg_rssi is not None and avg_rssi > -65:
                    severity = "high" if home_state == "away" else "medium"
                    _fire("airtag_findmy_present", severity, entity_id, 0.7, {
                        "avg_rssi": avg_rssi,
                        "home_state": home_state,
                        "explanation": (
                            "Apple Find-My (AirTag / lost AirPods / Find-My-enabled device) "
                            "broadcasting strongly close to the Pi (RSSI > -65 dBm). "
                            "If this is yours, mark it as known."
                        ),
                    })

        # ---- Rule 4: first-time visitor at after-hours ----
        # Skip if no anchors are enrolled (we can't reason about who "should" be here).
        if is_after_hours and any_anchor_enrolled and S["rule_first_time_visitor_after_hours"]:
            new_recent = conn.execute(
                """SELECT entity_id, first_seen_unix, last_seen_unix, avg_rssi
                   FROM entities
                   WHERE first_seen_unix > ?
                     AND last_seen_unix > ?
                     AND classification IS NULL""",
                (now - 1800, now - 300),
            ).fetchall()
            for entity_id, first_seen, last_seen, avg_rssi in new_recent:
                # Skip very-distant signals.
                if avg_rssi is not None and avg_rssi < -85:
                    continue
                _fire("first_time_visitor_after_hours", "medium" if home_state == "home" else "high",
                      entity_id, 0.55, {
                          "first_seen_minutes_ago": (now - first_seen) // 60,
                          "avg_rssi": avg_rssi,
                          "home_state": home_state,
                      })

        # ---- Rule 5: strong RSSI on close perimeter from unknown ----
        # Limit to BLE entities (WiFi APs are stationary by nature; their RSSI being close
        # is expected). Also require recent visit churn (varying presence) so we don't fire
        # on stationary BLE IoT (TVs, smart bulbs).
        if not S["rule_close_unknown_signal"]:
            close_results = []
        else:
            close_results = conn.execute(
                """SELECT e.entity_id, e.avg_rssi, e.visit_count, e.total_observations
                   FROM entities e
                   WHERE e.classification IS NULL
                     AND e.avg_rssi IS NOT NULL AND e.avg_rssi > ?
                     AND e.last_seen_unix > ?
                     AND e.entity_id LIKE 'ble:%'
                     AND e.visit_count > 1
                     AND e.total_observations < 5000""",
                (close_perim_rssi, now - 300),
            ).fetchall()
        for entity_id, avg_rssi, visit_count, total_obs in close_results:
            severity = "high" if home_state == "away" else "medium"
            _fire("close_unknown_signal", severity, entity_id, 0.6, {
                "avg_rssi": avg_rssi,
                "visit_count": visit_count,
                "home_state": home_state,
                "explanation": "Unknown mobile device very close to the Pi (RSSI > -50 dBm) "
                               "with recurring presence. If this is yours, enroll it on the Discover tab.",
            })

        # ---- Rule 7: persistent Find-My tracker (anti-AirTag stalking) ----
        # Apple Find-My beacon keys rotate every ~15 min so we can't track a
        # specific AirTag long-term. But we can ask: has *any* Find-My
        # broadcast been near the Pi for many minutes per day across multiple
        # consecutive days? If yes, that's strong evidence of a stationary or
        # following tracker (someone's planted an AirTag on the user's car or
        # bag, or the user has their own — either way, surface it).
        if S.get("rule_findmy_persistent_tracker", True):
            min_min = int(S.get("findmy_persistent_min_minutes_per_day", 180))
            min_days = int(S.get("findmy_persistent_min_consecutive_days", 3))
            # Count distinct minutes-with-Find-My-events per day for last 7 days.
            rows = conn.execute("""
                WITH minute_buckets AS (
                    SELECT date(ts_unix, 'unixepoch', 'localtime') AS day,
                           CAST(ts_unix / 60 AS INTEGER) AS minute_bucket
                    FROM raw_events
                    WHERE scanner = 'ble_scanner'
                      AND ts_unix > strftime('%s','now') - 7 * 86400
                      AND substr(json_extract(features_json, '$.manufacturer_data_hex'), 1, 6) = '4c0012'
                    GROUP BY day, minute_bucket
                )
                SELECT day, COUNT(*) AS minutes_with_findmy
                FROM minute_buckets
                GROUP BY day
                ORDER BY day DESC
            """).fetchall()
            # Walk back: how many consecutive recent days had >= min_min minutes of Find-My?
            consecutive = 0
            for day, minutes in rows:
                if minutes >= min_min:
                    consecutive += 1
                else:
                    break
            if consecutive >= min_days:
                _fire("findmy_persistent_tracker", "high", None, 0.8, {
                    "consecutive_days": consecutive,
                    "min_minutes_per_day": min_min,
                    "recent_days": [{"day": d, "minutes_with_findmy": m} for d, m in rows[:7]],
                    "explanation": (
                        f"Apple Find-My beacons (AirTag, lost-AirPods, etc.) have been "
                        f"in range >= {min_min} min/day for {consecutive} consecutive days. "
                        f"This means a tracker is persistently near the property. If it's "
                        f"yours (your wallet/keys/bag), enroll it. If not, someone may have "
                        f"planted an AirTag on your car or belongings to track you."
                    ),
                })

        # ---- Rule 6: rogue hotspot — randomized-MAC WiFi BSSID with strong signal ----
        if not S["rule_rogue_hotspot"]:
            return
        rogue_wifi = conn.execute(
            """SELECT entity_id, avg_rssi, friendly_name
               FROM entities
               WHERE entity_id LIKE 'wifi:mac:%'
                 AND is_random_mac = 1
                 AND avg_rssi IS NOT NULL AND avg_rssi > -65
                 AND last_seen_unix > ?
                 AND classification IS NULL""",
            (now - 300,),
        ).fetchall()
        for entity_id, avg_rssi, name in rogue_wifi:
            _fire("rogue_hotspot", "medium", entity_id, 0.5, {
                "avg_rssi": avg_rssi,
                "ssid": name,
                "explanation": "A random-BSSID Wi-Fi AP with strong signal — looks like a phone hotspot "
                               "or rogue AP very close to the property.",
            })
