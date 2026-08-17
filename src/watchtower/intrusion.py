"""Near-real-time anonymous presence and multi-signal intrusion correlation.

This module deliberately creates transient *tracklets*, not durable device
identities.  BLE privacy addresses can rotate and several devices can share an
advertisement shape, so every correlation retains its evidence and expires
quickly.  Alerts require independent signal families to reduce false alarms.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Iterable

from ulid import ULID


TRACKLET_JOIN_GAP_SEC = 90
TRACKLET_DEPARTED_SEC = 300
EPISODE_WINDOW_SEC = 300
DECISIVE_SIGNAL_TYPES = {
    "flipper_zero",
    "honeypot_engaged",
    "subghz_garage",
    "subghz_keyfob",
}


def _clean_text(value: Any, limit: int = 80) -> str | None:
    text = " ".join(str(value or "").strip().split())
    return text[:limit] if text else None


def ble_presence_signature(features: dict[str, Any]) -> tuple[str, str, dict[str, Any]] | None:
    """Build a non-secret advertisement-shape signature for a BLE flow.

    Rotating payload bytes and the MAC are excluded.  The signature is useful
    only for short-lived continuity and must never be presented as a permanent
    identity.
    """
    if str(features.get("address_type") or "").lower() != "random":
        return None
    decoded = features.get("decoded") or {}
    if (decoded.get("authorized_identity") or {}).get("key_id"):
        return None

    name = _clean_text(features.get("local_name"))
    services = sorted(str(v).lower() for v in (features.get("service_uuids") or []))[:12]
    service_keys = sorted(str(v).lower() for v in (features.get("service_data_hex") or {}).keys())[:12]
    mfr = str(features.get("manufacturer_data_hex") or "").lower()
    company_id = mfr[:4] if len(mfr) >= 4 else None
    continuity = decoded.get("apple_continuity") or {}
    apple_subtype = _clean_text(continuity.get("subtype"))
    apple_model = _clean_text(continuity.get("model"))
    tracker = decoded.get("location_tracker") or {}
    tracker_family = _clean_text(tracker.get("family"))
    detection = decoded.get("device_detection") or {}
    device_signature = _clean_text(detection.get("device_signature"))

    parts = {
        "name": name.casefold() if name else None,
        "services": services,
        "service_keys": service_keys,
        "company_id": company_id,
        "apple_subtype": apple_subtype,
        "apple_model": apple_model,
        "tracker_family": tracker_family,
        "device_signature": device_signature,
        "tx_power": features.get("tx_power"),
    }
    if not any((name, services, service_keys, company_id, tracker_family, device_signature)):
        return None
    canonical = json.dumps(parts, sort_keys=True, separators=(",", ":"))
    signature = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]
    if name:
        label = name
    elif apple_model:
        label = f"Anonymous {apple_model} flow"
    elif apple_subtype:
        label = f"Anonymous Apple {apple_subtype} flow"
    elif tracker_family:
        label = f"Anonymous {tracker_family.replace('_', ' ')} tracker flow"
    elif device_signature:
        label = f"Anonymous {device_signature.replace('_', ' ')} flow"
    elif company_id:
        label = f"Anonymous BLE company 0x{company_id} flow"
    else:
        label = "Anonymous BLE service flow"
    evidence = {k: v for k, v in parts.items() if v not in (None, [], "")}
    evidence["limitation"] = (
        "Short-lived advertisement correlation; not a permanent device identity."
    )
    return signature, label, evidence


def _parse_rows(rows: Iterable[tuple]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for row in rows:
        try:
            features = json.loads(row[5]) if isinstance(row[5], str) else dict(row[5])
        except (TypeError, ValueError):
            continue
        events.append({
            "event_id": row[0], "ts_unix": int(row[2]), "scanner": row[3],
            "kind": row[4], "features": features,
        })
    return events


def _upsert_tracklets(conn, events: list[dict[str, Any]], now: int) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for event in events:
        if event["scanner"] != "ble_scanner":
            continue
        features = event["features"]
        signature_info = ble_presence_signature(features)
        mac = _clean_text(features.get("mac"), 32)
        if not signature_info or not mac:
            continue
        signature, label, evidence = signature_info
        key = (signature, mac.lower())
        rssi = features.get("rssi")
        try:
            rssi = int(rssi) if rssi is not None else None
        except (TypeError, ValueError):
            rssi = None
        item = grouped.setdefault(key, {
            "signature": signature, "mac": mac.lower(), "label": label,
            "evidence": evidence, "first": event["ts_unix"],
            "last": event["ts_unix"], "count": 0, "rssis": [],
        })
        item["first"] = min(item["first"], event["ts_unix"])
        item["last"] = max(item["last"], event["ts_unix"])
        item["count"] += 1
        if rssi is not None:
            item["rssis"].append(rssi)

    conn.execute(
        """UPDATE presence_tracklets SET state = 'departed'
           WHERE state = 'active' AND last_seen_unix < ?""",
        (now - TRACKLET_DEPARTED_SEC,),
    )
    updated: list[dict[str, Any]] = []
    for item in sorted(grouped.values(), key=lambda value: value["first"]):
        first_sample_rssi = item["rssis"][0] if item["rssis"] else None
        sample_rssi = item["rssis"][-1] if item["rssis"] else None
        mapped = conn.execute(
            """SELECT t.tracklet_id
               FROM presence_tracklet_macs m
               JOIN presence_tracklets t ON t.tracklet_id = m.tracklet_id
               WHERE m.mac = ? AND t.signature = ?
                 AND t.last_seen_unix >= ?
               ORDER BY t.last_seen_unix DESC LIMIT 1""",
            (item["mac"], item["signature"], item["first"] - TRACKLET_DEPARTED_SEC),
        ).fetchone()
        tracklet_id = mapped[0] if mapped else None
        if not tracklet_id:
            candidates = conn.execute(
                """SELECT tracklet_id, last_seen_unix, last_rssi
                   FROM presence_tracklets
                   WHERE signature = ? AND state = 'active'
                     AND last_seen_unix BETWEEN ? AND ?
                   ORDER BY last_seen_unix DESC LIMIT 8""",
                (item["signature"], item["first"] - TRACKLET_JOIN_GAP_SEC,
                 item["first"] + 5),
            ).fetchall()
            best: tuple[float, str] | None = None
            for candidate_id, candidate_last, candidate_rssi in candidates:
                overlap = conn.execute(
                    """SELECT 1 FROM presence_tracklet_macs
                       WHERE tracklet_id = ? AND mac != ? AND last_seen_unix > ?
                       LIMIT 1""",
                    # If the previous address is still transmitting after the
                    # new address appears, these are concurrent flows.  A
                    # genuine privacy rotation normally has a clean handoff:
                    # old address stops, then the new one begins.
                    (candidate_id, item["mac"], item["first"]),
                ).fetchone()
                if overlap:
                    continue
                rssi_delta = (abs(sample_rssi - candidate_rssi)
                              if sample_rssi is not None and candidate_rssi is not None else 6)
                if rssi_delta > 16:
                    continue
                score = (item["first"] - candidate_last) + rssi_delta * 2
                if best is None or score < best[0]:
                    best = (score, candidate_id)
            tracklet_id = best[1] if best else None

        rssi_sum = sum(item["rssis"])
        rssi_count = len(item["rssis"])
        if not tracklet_id:
            tracklet_id = str(ULID())
            conn.execute(
                """INSERT INTO presence_tracklets
                       (tracklet_id,signature,label,first_seen_unix,last_seen_unix,
                        observation_count,address_count,first_rssi,last_rssi,
                        avg_rssi,max_rssi,state,confidence,evidence_json)
                   VALUES (?,?,?,?,?,?,1,?,?,?,?, 'active',0.35,?)""",
                (tracklet_id, item["signature"], item["label"], item["first"],
                 item["last"], item["count"], first_sample_rssi, sample_rssi,
                 (rssi_sum / rssi_count) if rssi_count else None,
                 max(item["rssis"]) if item["rssis"] else None,
                 json.dumps(item["evidence"])),
            )
        else:
            row = conn.execute(
                """SELECT observation_count,avg_rssi,first_rssi,max_rssi
                   FROM presence_tracklets WHERE tracklet_id = ?""",
                (tracklet_id,),
            ).fetchone()
            old_count, old_avg, first_rssi, old_max = row
            if rssi_count:
                weighted_count = old_count if old_avg is not None else 0
                avg_rssi = ((old_avg or 0) * weighted_count + rssi_sum) / (
                    weighted_count + rssi_count
                )
            else:
                avg_rssi = old_avg
            conn.execute(
                """UPDATE presence_tracklets
                   SET label=?, last_seen_unix=MAX(last_seen_unix,?),
                       observation_count=observation_count+?,
                       first_rssi=COALESCE(first_rssi,?),
                       last_rssi=COALESCE(?,last_rssi), avg_rssi=?,
                       max_rssi=MAX(COALESCE(max_rssi,?),COALESCE(?,max_rssi)),
                       state='active', evidence_json=?
                   WHERE tracklet_id=?""",
                (item["label"], item["last"], item["count"], sample_rssi,
                 sample_rssi, avg_rssi, sample_rssi, sample_rssi,
                 json.dumps(item["evidence"]), tracklet_id),
            )
        conn.execute(
            """INSERT INTO presence_tracklet_macs
                   (tracklet_id,mac,first_seen_unix,last_seen_unix,observation_count)
               VALUES (?,?,?,?,?)
               ON CONFLICT(tracklet_id,mac) DO UPDATE SET
                   last_seen_unix=MAX(last_seen_unix,excluded.last_seen_unix),
                   observation_count=observation_count+excluded.observation_count""",
            (tracklet_id, item["mac"], item["first"], item["last"], item["count"]),
        )
        address_count = conn.execute(
            "SELECT COUNT(*) FROM presence_tracklet_macs WHERE tracklet_id=?",
            (tracklet_id,),
        ).fetchone()[0]
        track = conn.execute(
            """SELECT first_seen_unix,last_seen_unix,observation_count,
                      first_rssi,last_rssi,avg_rssi,max_rssi
               FROM presence_tracklets WHERE tracklet_id=?""",
            (tracklet_id,),
        ).fetchone()
        first_seen, last_seen, observations, first_rssi, last_rssi, avg_rssi, max_rssi = track
        confidence = min(0.90, 0.30 + min(observations, 10) * 0.025
                         + min(max(0, address_count - 1), 3) * 0.12)
        conn.execute(
            """UPDATE presence_tracklets
               SET address_count=?,confidence=? WHERE tracklet_id=?""",
            (address_count, confidence, tracklet_id),
        )
        updated.append({
            "tracklet_id": tracklet_id, "label": item["label"],
            "first_seen_unix": first_seen, "last_seen_unix": last_seen,
            "observation_count": observations, "address_count": address_count,
            "first_rssi": first_rssi, "last_rssi": last_rssi,
            "avg_rssi": avg_rssi, "max_rssi": max_rssi,
            "confidence": confidence, "evidence": item["evidence"],
        })
    return updated


def _insert_signal(conn, ts_unix: int, signal_type: str, family: str,
                   source_id: str, weight: float, evidence: dict[str, Any]) -> None:
    bucket = ts_unix // 60
    conn.execute(
        """INSERT OR IGNORE INTO intrusion_signals
               (signal_id,ts_unix,bucket,signal_type,family,source_id,weight,evidence_json)
           VALUES (?,?,?,?,?,?,?,?)""",
        (str(ULID()), ts_unix, bucket, signal_type, family, source_id,
         weight, json.dumps(evidence)),
    )


def _collect_signals(conn, events: list[dict[str, Any]], tracklets: list[dict[str, Any]], now: int) -> None:
    for track in tracklets:
        if track["observation_count"] >= 3 and (track["max_rssi"] or -127) >= -68:
            _insert_signal(conn, track["last_seen_unix"], "anonymous_ble_close", "ble",
                           track["tracklet_id"], 20, {
                               "label": track["label"], "max_rssi": track["max_rssi"],
                               "address_count": track["address_count"],
                               "confidence": round(track["confidence"], 2),
                           })
        first_rssi, last_rssi = track["first_rssi"], track["last_rssi"]
        if (track["observation_count"] >= 4 and first_rssi is not None
                and last_rssi is not None and last_rssi - first_rssi >= 8
                and track["last_seen_unix"] - track["first_seen_unix"] >= 10):
            _insert_signal(conn, track["last_seen_unix"], "anonymous_ble_approach", "ble",
                           track["tracklet_id"], 30, {
                               "label": track["label"], "rssi_change_db": last_rssi - first_rssi,
                               "duration_sec": track["last_seen_unix"] - track["first_seen_unix"],
                               "address_count": track["address_count"],
                           })

    for event in events:
        features = event["features"]
        decoded = features.get("decoded") or {}
        if event["scanner"] == "subghz_scanner" and event["kind"] in {
            "keyfob_emission", "garage_emission",
        }:
            protocol = str(features.get("protocol") or "unknown")
            stable = None
            try:
                from watchtower.rf_identity import stable_subghz_identity
                stable = stable_subghz_identity(features.get("decoded") or {})
            except Exception:  # noqa: BLE001
                pass
            source = f"{protocol}:{stable[1] if stable else 'unknown'}"
            signal_type = ("subghz_keyfob" if event["kind"] == "keyfob_emission"
                           else "subghz_garage")
            _insert_signal(conn, event["ts_unix"], signal_type, "subghz", source, 35, {
                "protocol": protocol, "stable_identity": stable[1] if stable else None,
            })
        detection = decoded.get("device_detection") or {}
        if (event["scanner"] == "ble_scanner"
                and detection.get("device_signature") == "flipper_zero"
                and detection.get("alert_eligible")):
            _insert_signal(conn, event["ts_unix"], "flipper_zero", "ble",
                           str(features.get("mac") or "flipper"), 45, {
                               "local_name": features.get("local_name"),
                               "rssi": features.get("rssi"), "confidence": "high",
                           })
        if (event["scanner"] == "wifi_scanner" and features.get("is_random_mac")):
            try:
                rssi = int(features.get("rssi"))
            except (TypeError, ValueError):
                rssi = -127
            mac = str(features.get("mac") or "").lower()
            ssid = _clean_text(
                features.get("ssid")
                or features.get("local_name")
                or decoded.get("ssid")
            )
            # Locally administered BSSIDs are also used by ordinary APs and
            # phone hotspots.  Count one only while it is genuinely new to
            # this sensor; a strong, repeatedly observed local AP is context,
            # not an intrusion signal.
            history = conn.execute(
                """SELECT MIN(ts_unix),COUNT(*) FROM raw_events
                   WHERE scanner='wifi_scanner'
                     AND lower(json_extract(features_json,'$.mac'))=?""",
                (mac,),
            ).fetchone() if mac else None
            first_seen = int(history[0]) if history and history[0] is not None else now
            observations = int(history[1]) if history else 0
            is_new = first_seen >= now - EPISODE_WINDOW_SEC
            if rssi >= -55 and mac and ssid and ssid.casefold() != "watchtower" and is_new:
                _insert_signal(conn, event["ts_unix"], "random_wifi_hotspot", "wifi",
                               mac, 20, {
                                   "ssid": ssid, "rssi": rssi,
                                   "first_seen_unix": first_seen,
                                   "observation_count": observations,
                                   "limitation": (
                                       "A randomized BSSID can be a benign hotspot; "
                                       "it is supporting evidence only."
                                   ),
                               })

    # Honeypot touches are already strong, separately audited alerts. Fold
    # them into an episode without issuing another signal on every sink flush.
    for alert_id, ts_unix, evidence_json in conn.execute(
        """SELECT alert_id,ts_unix,evidence_json FROM alerts
           WHERE rule_id='honeypot_engaged' AND ts_unix>?""",
        (now - EPISODE_WINDOW_SEC,),
    ).fetchall():
        try:
            evidence = json.loads(evidence_json or "{}")
        except (TypeError, ValueError):
            evidence = {}
        _insert_signal(conn, ts_unix, "honeypot_engaged", "honeypot",
                       alert_id, 50, evidence)


def _episode_settings(conn) -> dict[str, Any]:
    defaults = {
        "rule_multi_signal_intrusion": True,
        "intrusion_episode_window_sec": EPISODE_WINDOW_SEC,
        "intrusion_away_threshold": 60,
        "intrusion_home_threshold": 75,
        "anchor_timeout_sec": 600,
        "after_hours_start_utc": 22,
        "after_hours_end_utc": 6,
    }
    row = conn.execute(
        "SELECT value FROM analytics_state WHERE key='settings_json'"
    ).fetchone()
    if row and row[0]:
        try:
            saved = json.loads(row[0])
            defaults.update({k: saved[k] for k in defaults if k in saved})
        except (TypeError, ValueError):
            pass
    return defaults


def _evaluate_episode(conn, now: int) -> list[dict[str, Any]]:
    settings = _episode_settings(conn)
    window = max(60, min(900, int(settings["intrusion_episode_window_sec"])))
    conn.execute("DELETE FROM intrusion_signals WHERE ts_unix < ?", (now - 86400,))
    conn.execute(
        """UPDATE intrusion_episodes SET status='closed'
           WHERE status IN ('observing','alerted') AND last_seen_unix < ?""",
        (now - window,),
    )
    rows = conn.execute(
        """SELECT signal_type,family,source_id,weight,evidence_json,MAX(ts_unix)
           FROM intrusion_signals WHERE ts_unix>?
           GROUP BY signal_type,source_id
           ORDER BY MAX(ts_unix) DESC""",
        (now - window,),
    ).fetchall()
    if not rows:
        return []
    strongest: dict[str, dict[str, Any]] = {}
    for signal_type, family, source_id, weight, evidence_json, ts_unix in rows:
        try:
            evidence = json.loads(evidence_json or "{}")
        except (TypeError, ValueError):
            evidence = {}
        item = {"type": signal_type, "family": family, "source_id": source_id,
                "weight": float(weight), "ts_unix": ts_unix, "evidence": evidence}
        if signal_type not in strongest or weight > strongest[signal_type]["weight"]:
            strongest[signal_type] = item
    signals = list(strongest.values())
    families = sorted({signal["family"] for signal in signals})
    strongest_by_family: dict[str, dict[str, Any]] = {}
    for signal in signals:
        family = signal["family"]
        if (family not in strongest_by_family
                or signal["weight"] > strongest_by_family[family]["weight"]):
            strongest_by_family[family] = signal

    any_anchor = conn.execute(
        "SELECT 1 FROM entities WHERE classification='anchor' LIMIT 1"
    ).fetchone() is not None
    anchor_present = conn.execute(
        """SELECT 1 FROM entities WHERE classification='anchor'
           AND last_seen_unix>? LIMIT 1""",
        (now - int(settings["anchor_timeout_sec"]),),
    ).fetchone() is not None
    home_state = "unknown" if not any_anchor else "home" if anchor_present else "away"
    hour_utc = (now // 3600) % 24
    start = int(settings["after_hours_start_utc"])
    end = int(settings["after_hours_end_utc"])
    after_hours = (start <= hour_utc < end if start <= end
                   else hour_utc >= start or hour_utc < end)
    # Correlated symptoms from one radio family are alternate explanations,
    # not independent votes.  Only the strongest signal in each family scores.
    score = sum(signal["weight"] for signal in strongest_by_family.values())
    if home_state == "away":
        score += 15
    if after_hours:
        score += 10
    score = min(100, int(round(score)))
    threshold = (int(settings["intrusion_away_threshold"]) if home_state == "away"
                 else int(settings["intrusion_home_threshold"]))
    decisive_types = sorted({
        signal["type"] for signal in signals
        if signal["type"] in DECISIVE_SIGNAL_TYPES
    })
    qualifies = (
        settings["rule_multi_signal_intrusion"]
        and len(families) >= 2
        and bool(decisive_types)
        and score >= threshold
    )

    active = conn.execute(
        """SELECT episode_id,alert_id,start_unix FROM intrusion_episodes
           WHERE status IN ('observing','alerted') AND last_seen_unix>?
           ORDER BY last_seen_unix DESC LIMIT 1""",
        (now - window,),
    ).fetchone()
    episode_id = active[0] if active else str(ULID())
    alert_id = active[1] if active else None
    start_unix = active[2] if active else min(signal["ts_unix"] for signal in signals)
    status = "alerted" if alert_id or qualifies else "observing"
    evidence = {
        "score": score, "threshold": threshold, "home_state": home_state,
        "after_hours": after_hours, "independent_families": families,
        "family_scores": {
            family: signal["weight"]
            for family, signal in sorted(strongest_by_family.items())
        },
        "decisive_signal_types": decisive_types,
        "alert_qualified": qualifies,
        "signals": signals,
        "explanation": (
            "Independent nearby radio behaviors occurred within one short window. "
            "An alert additionally requires a decisive interaction signal such as "
            "a keyfob/garage transmission, honeypot contact, or high-confidence "
            "Flipper detection. This is behavioral correlation, not proof of a "
            "person's identity."
        ),
    }
    if active:
        conn.execute(
            """UPDATE intrusion_episodes
               SET last_seen_unix=?,status=?,score=?,severity=?,home_state=?,
                   signal_types_json=?,evidence_json=? WHERE episode_id=?""",
            (max(signal["ts_unix"] for signal in signals), status, score,
             "high" if qualifies else "low", home_state,
             json.dumps(sorted(strongest)), json.dumps(evidence), episode_id),
        )
    else:
        conn.execute(
            """INSERT INTO intrusion_episodes
                   (episode_id,start_unix,last_seen_unix,status,score,severity,
                    home_state,signal_types_json,evidence_json)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (episode_id, start_unix, max(signal["ts_unix"] for signal in signals),
             status, score, "high" if qualifies else "low", home_state,
             json.dumps(sorted(strongest)), json.dumps(evidence)),
        )
    if not qualifies or alert_id:
        return []
    severity = "critical" if score >= 90 else "high"
    alert_id = str(ULID())
    conn.execute(
        """INSERT INTO alerts
               (alert_id,ts_unix,rule_id,severity,entity_id,score,home_state,evidence_json)
           VALUES (?,?,?,?,NULL,?,?,?)""",
        (alert_id, now, "multi_signal_intrusion", severity, score / 100,
         home_state, json.dumps({"episode_id": episode_id, **evidence})),
    )
    conn.execute(
        """UPDATE intrusion_episodes SET alert_id=?,status='alerted',severity=?
           WHERE episode_id=?""",
        (alert_id, severity, episode_id),
    )
    return [{
        "alert_id": alert_id, "ts_unix": now,
        "rule_id": "multi_signal_intrusion", "severity": severity,
        "entity_id": None, "score": score / 100, "home_state": home_state,
        "evidence": {"episode_id": episode_id, **evidence},
    }]


def process_signal_batch(conn, rows: Iterable[tuple], now: int | None = None) -> list[dict[str, Any]]:
    """Update transient intelligence from one already-normalized sink batch."""
    events = _parse_rows(rows)
    if not events:
        return []
    current = int(now if now is not None else max(time.time(), max(e["ts_unix"] for e in events)))
    tracklets = _upsert_tracklets(conn, events, current)
    _collect_signals(conn, events, tracklets, current)
    return _evaluate_episode(conn, current)
