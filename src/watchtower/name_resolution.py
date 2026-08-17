"""Confidence-scored, local-only friendly-name resolution.

This module normalizes disclosed names plus names decrypted with explicitly
authorized local keys, records provenance, and selects the best candidate
without overwriting an explicit user label.
"""
from __future__ import annotations

import json
import re
import time
import unicodedata
from typing import Any


SOURCE_CONFIDENCE: dict[str, float] = {
    "user": 1.00,
    "fast_pair_personalized_name": 0.995,
    "ble_ead_local_name": 0.99,
    "bluez_paired_alias": 0.985,
    "apple_companion_name": 0.975,
    "apple_bonjour_bluetooth_link": 0.970,
    "airplay_display_name": 0.965,
    "apple_device_info_name": 0.960,
    "apple_mobile_device_name": 0.955,
    "homekit_accessory_name": 0.950,
    "ble_irk_identity": 0.98,
    "ble_gatt_device_name": 0.96,
    "bluetooth_remote_name": 0.93,
    "apple_bonjour_host_name": 0.925,
    "mdns_service_name": 0.92,
    "apple_sleep_proxy_name": 0.90,
    "apple_ble_local_name": 0.90,
    "apple_continuity_model": 0.88,
    "apple_bonjour_model": 0.86,
    "bonjour_model": 0.84,
    "upnp_friendly_name": 0.92,
    "dhcp_hostname": 0.86,
    "reverse_dns": 0.75,
    "signature": 0.94,
    "wifi_wps_device_name": 0.90,
    "ble_gatt_model": 0.84,
    "wifi_wps_model": 0.80,
    "ble_advertised_name": 0.74,
    "service_fingerprint": 0.68,
    "legacy": 0.60,
    "wifi_ssid": 0.56,
    "vendor": 0.35,
}

_MAC_LIKE = re.compile(r"^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.I)
_HEX_ID = re.compile(r"^(?:0x)?[0-9a-f]{8,}$", re.I)
_NUMERIC_ID = re.compile(r"^[0-9_-]{6,}$")
_FACTORY_ID = re.compile(r"^[A-Z0-9_-]{14,}$")
_GENERIC = {
    "unknown", "unnamed", "none", "null", "n/a", "na", "ble", "bluetooth",
    "device", "default", "wifi", "wireless", "access point", "ap",
}


def clean_name(value: Any, *, max_length: int = 120) -> str | None:
    """Return safe normalized display text, or None for opaque/generic IDs."""
    if not isinstance(value, str):
        return None
    value = unicodedata.normalize("NFC", value.replace("\ufffd", ""))
    value = "".join(ch for ch in value if unicodedata.category(ch) != "Cc")
    value = " ".join(value.split()).strip(" .\t\r\n")
    if not value or value.casefold() in _GENERIC:
        return None
    if _MAC_LIKE.fullmatch(value) or _HEX_ID.fullmatch(value) or _NUMERIC_ID.fullmatch(value):
        return None
    # Factory serial-like advertisement strings are identifiers, not names.
    # Keep meaningful mixed-case model names, but reject long all-caps tokens
    # containing several digits (for example AL0012A1GP5V04308A).
    if _FACTORY_ID.fullmatch(value) and sum(ch.isdigit() for ch in value) >= 4:
        return None
    return value[:max_length] or None


def _safe_evidence(evidence: dict[str, Any] | None) -> str:
    try:
        return json.dumps(evidence or {}, separators=(",", ":"), sort_keys=True)[:1000]
    except (TypeError, ValueError):
        return "{}"


def record_name_candidate(
    conn,
    entity_id: str,
    name: Any,
    source: str,
    *,
    confidence: float | None = None,
    evidence: dict[str, Any] | None = None,
    observed_unix: int | None = None,
) -> bool:
    """Store a candidate and refresh the entity's selected friendly name.

    Returns True when a usable candidate was recorded.  The caller must have
    already inserted the entity row so the candidate's foreign key is valid.
    """
    cleaned = clean_name(name)
    if not cleaned:
        return False
    now = int(observed_unix or time.time())
    score = max(0.0, min(1.0, float(
        SOURCE_CONFIDENCE.get(source, 0.50) if confidence is None else confidence
    )))
    conn.execute(
        """INSERT INTO entity_name_candidates
               (entity_id, name, source, confidence, first_seen_unix, last_seen_unix, evidence_json)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(entity_id, source, name) DO UPDATE SET
               confidence = MAX(entity_name_candidates.confidence, excluded.confidence),
               last_seen_unix = MAX(entity_name_candidates.last_seen_unix, excluded.last_seen_unix),
               evidence_json = excluded.evidence_json""",
        (entity_id, cleaned, source, score, now, now, _safe_evidence(evidence)),
    )
    resolve_entity_name(conn, entity_id)
    return True


def resolve_entity_name(conn, entity_id: str) -> dict[str, Any] | None:
    """Choose the strongest candidate, with user labels always winning."""
    row = conn.execute(
        """SELECT name, source, confidence, last_seen_unix, evidence_json
           FROM entity_name_candidates
           WHERE entity_id = ?
           ORDER BY (source = 'user') DESC, confidence DESC, last_seen_unix DESC,
                    length(name) DESC, name COLLATE NOCASE
           LIMIT 1""",
        (entity_id,),
    ).fetchone()
    if not row:
        conn.execute(
            """UPDATE entities SET friendly_name = NULL, friendly_name_source = NULL,
                   friendly_name_confidence = NULL, friendly_name_updated_unix = NULL
               WHERE entity_id = ?""",
            (entity_id,),
        )
        return None
    name, source, confidence, updated, evidence_json = row
    conn.execute(
        """UPDATE entities SET friendly_name = ?, friendly_name_source = ?,
               friendly_name_confidence = ?, friendly_name_updated_unix = ?
           WHERE entity_id = ?""",
        (name, source, confidence, updated, entity_id),
    )
    try:
        evidence = json.loads(evidence_json or "{}")
    except (TypeError, ValueError):
        evidence = {}
    return {"name": name, "source": source, "confidence": confidence,
            "last_seen_unix": updated, "evidence": evidence}


def set_user_name(conn, entity_id: str, name: Any) -> str | None:
    """Set or clear the user's immutable top-priority label."""
    conn.execute(
        "DELETE FROM entity_name_candidates WHERE entity_id = ? AND source = 'user'",
        (entity_id,),
    )
    cleaned = clean_name(name)
    if cleaned:
        record_name_candidate(conn, entity_id, cleaned, "user", confidence=1.0)
    else:
        resolve_entity_name(conn, entity_id)
    return cleaned


def candidates_for_entity(conn, entity_id: str, limit: int = 20) -> list[dict[str, Any]]:
    cursor = conn.execute(
        """SELECT name, source, confidence, first_seen_unix, last_seen_unix, evidence_json
           FROM entity_name_candidates WHERE entity_id = ?
           ORDER BY (source = 'user') DESC, confidence DESC, last_seen_unix DESC LIMIT ?""",
        (entity_id, limit),
    )
    out = []
    for name, source, confidence, first_seen, last_seen, evidence_json in cursor.fetchall():
        try:
            evidence = json.loads(evidence_json or "{}")
        except (TypeError, ValueError):
            evidence = {}
        out.append({"name": name, "source": source, "confidence": confidence,
                    "first_seen_unix": first_seen, "last_seen_unix": last_seen,
                    "evidence": evidence})
    return out


def revalidate_name_candidates(conn) -> int:
    """Remove derived names that no longer pass current display-name hygiene."""
    invalid: list[tuple[str, str, str]] = []
    for entity_id, name, source in conn.execute(
        "SELECT entity_id, name, source FROM entity_name_candidates WHERE source != 'user'"
    ).fetchall():
        if clean_name(name) is None:
            invalid.append((entity_id, source, name))
    touched = {entity_id for entity_id, _, _ in invalid}
    if invalid:
        conn.executemany(
            "DELETE FROM entity_name_candidates WHERE entity_id = ? AND source = ? AND name = ?",
            invalid,
        )
        for entity_id in touched:
            resolve_entity_name(conn, entity_id)
    return len(invalid)


def backfill_apple_audio_groups(conn) -> int:
    """Make previously grouped Apple audio traffic visible after upgrades."""
    from watchtower.apple_continuity import decode_continuity

    definitions = (
        ("ble:apple:proximity-pairing", "Apple proximity accessory",
         "proximity-pairing", "4c0007"),
        ("ble:apple:airpods-connected", "Apple audio accessory",
         "airpods-connected", "4c0016"),
    )
    count = 0
    for canonical_eid, label, subtype, packet_prefix in definitions:
        entity_rows = conn.execute(
            "SELECT entity_id FROM entities WHERE lower(entity_id) = ?",
            (canonical_eid,),
        ).fetchall()
        if not entity_rows:
            continue
        evidence: dict[str, Any] = {
            "subtype": subtype,
            "model_resolved": False,
            "grouped_observations": True,
        }
        raw = conn.execute(
            """SELECT json_extract(features_json, '$.manufacturer_data_hex')
               FROM raw_events
               WHERE scanner = 'ble_scanner'
                 AND lower(substr(json_extract(features_json, '$.manufacturer_data_hex'), 1, 6)) = ?
               ORDER BY ts_unix DESC LIMIT 1""",
            (packet_prefix,),
        ).fetchone()
        decoded = decode_continuity(raw[0]) if raw and raw[0] else None
        if decoded and decoded.get("model_id"):
            evidence["model_id"] = decoded["model_id"]
        for (entity_id,) in entity_rows:
            conn.execute(
                """DELETE FROM entity_name_candidates
                   WHERE entity_id = ? AND source = 'service_fingerprint'
                     AND name IN ('Apple proximity accessory', 'Apple audio accessory')
                     AND name != ?""",
                (entity_id, label),
            )
            conn.execute(
                "UPDATE entities SET kind = 'ble_headphones' WHERE entity_id = ?",
                (entity_id,),
            )
            if record_name_candidate(
                conn, entity_id, label, "service_fingerprint", evidence=evidence,
            ):
                count += 1
    return count


def candidates_from_features(scanner: str, feats: dict[str, Any]) -> list[tuple[str, str, dict]]:
    """Extract disclosed name candidates from one normalized scanner event."""
    decoded = feats.get("decoded") or {}
    out: list[tuple[str, str, dict]] = []
    if scanner == "ble_scanner":
        if feats.get("local_name"):
            out.append((feats["local_name"], "ble_advertised_name", {}))
        mfr_hex = str(feats.get("manufacturer_data_hex") or "")
        if mfr_hex.casefold().startswith("4c00"):
            from watchtower.apple_continuity import decode_continuity
            # Re-decode from the raw packet so decoder upgrades also correct
            # historical events whose normalized payload used an older layout.
            continuity = decode_continuity(mfr_hex) or decoded.get("apple_continuity")
            if feats.get("local_name"):
                out.append((feats["local_name"], "apple_ble_local_name",
                            {"protocol": "apple_continuity"}))
            if continuity and continuity.get("model"):
                evidence = {"subtype": continuity.get("subtype")}
                if continuity.get("model_id"):
                    evidence["model_id"] = continuity["model_id"]
                out.append((continuity["model"], "apple_continuity_model", evidence))
            elif continuity and continuity.get("subtype") in {
                "proximity-pairing", "airpods-connected",
            }:
                subtype = continuity["subtype"]
                evidence = {
                    "subtype": subtype,
                    "model_resolved": False,
                }
                if continuity.get("model_id"):
                    evidence["model_id"] = continuity["model_id"]
                label = ("Apple audio accessory" if subtype == "airpods-connected"
                         else "Apple proximity accessory")
                out.append((label, "service_fingerprint", evidence))
        for item in decoded.get("authorized_names") or []:
            if isinstance(item, dict) and item.get("name") and item.get("source"):
                out.append((item["name"], item["source"], item.get("evidence") or {}))
        detection = decoded.get("device_detection") or {}
        if detection.get("device_signature") == "flipper_zero":
            out.append(("Flipper Zero", "signature", {"detector": "ble_signature"}))
        tracker = decoded.get("location_tracker") or {}
        family_names = {
            "dult": f"{str(tracker.get('provider') or 'Unknown').title()} compatible location tracker",
            "apple_findmy": "Apple Find My tracker",
            "tile": "Tile-compatible tracker",
            "google_findhub": "Google Find Hub tracker",
            "samsung_smartthings_find": "Samsung SmartThings Find tracker",
        }
        family = tracker.get("family")
        if family in family_names:
            out.append((family_names[family], "service_fingerprint",
                        {"family": family, "detector": tracker.get("detector")}))
    elif scanner == "wifi_scanner":
        if decoded.get("wps_device_name"):
            out.append((decoded["wps_device_name"], "wifi_wps_device_name", {}))
        if decoded.get("wps_model"):
            model = decoded["wps_model"]
            mfr = decoded.get("wps_manufacturer")
            out.append((f"{mfr} {model}" if mfr and mfr.casefold() not in model.casefold() else model,
                        "wifi_wps_model", {}))
        if decoded.get("ssid") or feats.get("local_name"):
            out.append((decoded.get("ssid") or feats.get("local_name"), "wifi_ssid", {}))
    return out
