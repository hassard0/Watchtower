"""Find-My cluster tracker + co-presence inference.

Apple rotates the BLE address of Find-My beacons every ~15 minutes, so we
can't follow a single tracker for hours by exact MAC. This module gives
each tracker a stable internal cluster_id by joining rotations together
based on RSSI continuity (same RSSI ±8 dBm, MAC change within a few
seconds → same physical tracker).

Once we have stable cluster IDs, we run co-presence inference: for each
cluster, score how often it's present at the same time as each enrolled
*anchor* entity (your phone). High correlation → almost certainly your
tracker. We label clusters with the most-likely owner.

Net effect: instead of seeing "ble:apple:find-my (37 sightings)", you
see "Find-My cluster #3 — probably Ian's AirTag (87% co-presence with
Ian's iPhone over 4 days)". Suspicious clusters that DON'T correlate
with any anchor stand out as candidates for the persistent-tracker rule.

Limitations:
- Inference, not cryptographic identification. RSSI continuity is noisy;
  occasional cluster misjoins happen.
- Only labels YOUR trackers (the ones that stay near YOUR anchor). Other
  people's AirTags stay anonymous.
- For guaranteed labeling, the master-secret enrollment path (planned)
  decrypts rotation deterministically.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from ulid import ULID

from watchtower.storage.db import get_connection

log = logging.getLogger(__name__)

# Cluster matching thresholds.
ROTATION_GAP_MAX_SEC = 8         # MAC handoff window; rotations are ~15 min apart but BLE address changes are sub-second
RSSI_TOLERANCE_DBM = 8           # ±8 dBm = ~3-5m positional uncertainty
CLUSTER_INACTIVE_SEC = 1800      # cluster considered "gone" if not seen for 30 min
CLUSTER_PRUNE_AGE_SEC = 7 * 86400  # forget clusters not seen in a week

# Co-presence inference.
COPRESENCE_BUCKET_SEC = 300      # 5-minute presence buckets
COPRESENCE_LOOKBACK_SEC = 4 * 86400  # 4 days of history
COPRESENCE_MIN_BUCKETS = 12      # need at least 12 buckets (~1 hr) of tracker presence to score
COPRESENCE_THRESHOLD = 0.55      # Jaccard similarity ≥ 0.55 to label as owned


def _now() -> int:
    return int(time.time())


def assign_cluster(conn, mac: str, rssi: int | None, status: str | None,
                   ts_unix: int) -> str:
    """Find or create a cluster for this Find-My event.

    Heuristic: an existing cluster matches if (a) we've seen this exact
    rotating_mac before for that cluster, OR (b) the cluster was last seen
    within ROTATION_GAP_MAX_SEC AND its last_rssi is within RSSI_TOLERANCE_DBM.

    Returns the cluster_id.
    """
    mac = mac.lower()

    # 1. Direct hit on rotating_mac.
    row = conn.execute(
        "SELECT cluster_id FROM findmy_cluster_macs WHERE rotating_mac = ?",
        (mac,),
    ).fetchone()
    if row:
        cluster_id = row[0]
        conn.execute(
            "UPDATE findmy_cluster_macs SET last_seen_unix = ?, sighting_count = sighting_count + 1 "
            "WHERE rotating_mac = ?",
            (ts_unix, mac),
        )
        _bump_cluster(conn, cluster_id, mac, rssi, status, ts_unix, new_rotation=False)
        return cluster_id

    # 2. RSSI-continuity rotation. Find an active cluster whose last RSSI
    #    is close to ours and whose last_seen is within rotation window.
    if rssi is not None:
        cand = conn.execute(
            """SELECT cluster_id, last_rssi
               FROM findmy_clusters
               WHERE last_seen_unix > ?
                 AND last_rssi IS NOT NULL
                 AND ABS(last_rssi - ?) <= ?
               ORDER BY ABS(last_rssi - ?) ASC
               LIMIT 1""",
            (ts_unix - ROTATION_GAP_MAX_SEC, rssi, RSSI_TOLERANCE_DBM, rssi),
        ).fetchone()
        if cand:
            cluster_id = cand[0]
            conn.execute(
                """INSERT INTO findmy_cluster_macs (rotating_mac, cluster_id,
                    first_seen_unix, last_seen_unix, sighting_count)
                   VALUES (?, ?, ?, ?, 1)""",
                (mac, cluster_id, ts_unix, ts_unix),
            )
            _bump_cluster(conn, cluster_id, mac, rssi, status, ts_unix, new_rotation=True)
            return cluster_id

    # 3. New cluster.
    cluster_id = str(ULID())
    conn.execute(
        """INSERT INTO findmy_clusters
            (cluster_id, first_seen_unix, last_seen_unix, sighting_count, rotation_count,
             last_rssi, avg_rssi, last_status, last_mac)
           VALUES (?, ?, ?, 1, 1, ?, ?, ?, ?)""",
        (cluster_id, ts_unix, ts_unix, rssi, float(rssi) if rssi is not None else None,
         status, mac),
    )
    conn.execute(
        """INSERT INTO findmy_cluster_macs (rotating_mac, cluster_id,
            first_seen_unix, last_seen_unix, sighting_count)
           VALUES (?, ?, ?, ?, 1)""",
        (mac, cluster_id, ts_unix, ts_unix),
    )
    return cluster_id


def _bump_cluster(conn, cluster_id: str, mac: str, rssi: int | None,
                  status: str | None, ts_unix: int, new_rotation: bool) -> None:
    """Roll the running stats forward for an existing cluster."""
    delta_rotations = 1 if new_rotation else 0
    if rssi is not None:
        # Exponential moving average over RSSI to track movement smoothly.
        conn.execute(
            """UPDATE findmy_clusters SET
                last_seen_unix = ?,
                sighting_count = sighting_count + 1,
                rotation_count = rotation_count + ?,
                last_rssi = ?,
                avg_rssi = COALESCE(avg_rssi * 0.9 + ? * 0.1, ?),
                last_status = COALESCE(?, last_status),
                last_mac = ?
               WHERE cluster_id = ?""",
            (ts_unix, delta_rotations, rssi, float(rssi), float(rssi), status, mac, cluster_id),
        )
    else:
        conn.execute(
            """UPDATE findmy_clusters SET
                last_seen_unix = ?,
                sighting_count = sighting_count + 1,
                rotation_count = rotation_count + ?,
                last_status = COALESCE(?, last_status),
                last_mac = ?
               WHERE cluster_id = ?""",
            (ts_unix, delta_rotations, status, mac, cluster_id),
        )


def process_findmy_event(conn, mac: str | None, mfr_hex: str | None,
                         rssi: int | None, ts_unix: int) -> str | None:
    """Top-level entry point: given a Find-My BLE event, ensure cluster exists
    and is up to date. Returns cluster_id (or None if not Find-My)."""
    if not mfr_hex or not mfr_hex.lower().startswith("4c0012"):
        return None
    if not mac:
        return None
    # Decode status nibble.
    status: str | None = None
    try:
        first_payload_byte = int(mfr_hex[8:10], 16)
        status_nibble = (first_payload_byte >> 4) & 0x0F
        status = {0: "unowned", 4: "owned", 8: "separated", 2: "lost-mode", 0xC: "unowned-paired"}.get(status_nibble)
    except (ValueError, IndexError):
        pass
    return assign_cluster(conn, mac, rssi, status, ts_unix)


def prune_old_clusters(conn) -> int:
    """Drop clusters not seen in a week. Cascade kills the cluster_macs rows."""
    cutoff = _now() - CLUSTER_PRUNE_AGE_SEC
    cur = conn.execute("DELETE FROM findmy_clusters WHERE last_seen_unix < ?", (cutoff,))
    return cur.rowcount or 0


# ---- Co-presence inference --------------------------------------------------

def _bucket_set(rows, bucket_sec: int) -> set[int]:
    """Convert a list of (ts_unix,) rows into a set of bucket indices."""
    return {ts // bucket_sec for (ts,) in rows}


def _jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def score_cluster_copresence(conn, cluster_id: str) -> tuple[str | None, float]:
    """Compute the strongest anchor co-presence for a cluster.

    Returns (best_anchor_entity_id_or_None, best_jaccard_score).
    """
    now = _now()
    since = now - COPRESENCE_LOOKBACK_SEC

    # Cluster presence buckets: union of presence buckets of all rotating MACs
    # belonging to this cluster.
    cluster_macs = [r[0] for r in conn.execute(
        "SELECT rotating_mac FROM findmy_cluster_macs WHERE cluster_id = ?",
        (cluster_id,),
    ).fetchall()]
    if not cluster_macs:
        return None, 0.0
    placeholders = ",".join("?" for _ in cluster_macs)
    cluster_rows = conn.execute(
        f"""SELECT DISTINCT ts_unix
            FROM raw_events
            WHERE scanner = 'ble_scanner'
              AND ts_unix > ?
              AND lower(json_extract(features_json, '$.mac')) IN ({placeholders})""",
        (since, *cluster_macs),
    ).fetchall()
    cluster_buckets = _bucket_set(cluster_rows, COPRESENCE_BUCKET_SEC)
    if len(cluster_buckets) < COPRESENCE_MIN_BUCKETS:
        return None, 0.0

    # For each enrolled anchor entity, get its presence buckets.
    anchors = conn.execute(
        "SELECT entity_id FROM entities WHERE classification = 'anchor'"
    ).fetchall()
    best_anchor, best_score = None, 0.0
    for (anchor_eid,) in anchors:
        # Translate anchor entity_id back to a query — for ble:mac:X, find raw_events with that MAC.
        # For ble:named:X or ble:apple:X, find raw_events whose features match.
        anchor_macs = _anchor_macs(conn, anchor_eid)
        if not anchor_macs:
            continue
        ph = ",".join("?" for _ in anchor_macs)
        rows = conn.execute(
            f"""SELECT DISTINCT ts_unix
                FROM raw_events
                WHERE scanner = 'ble_scanner'
                  AND ts_unix > ?
                  AND lower(json_extract(features_json, '$.mac')) IN ({ph})""",
            (since, *anchor_macs),
        ).fetchall()
        anchor_buckets = _bucket_set(rows, COPRESENCE_BUCKET_SEC)
        score = _jaccard(cluster_buckets, anchor_buckets)
        if score > best_score:
            best_score, best_anchor = score, anchor_eid

    return best_anchor, best_score


def _anchor_macs(conn, entity_id: str) -> list[str]:
    """Get the MACs that have been seen for this anchor entity over the lookback window."""
    if entity_id.startswith("ble:mac:"):
        return [entity_id[len("ble:mac:"):]]
    since = _now() - COPRESENCE_LOOKBACK_SEC
    if entity_id.startswith("ble:named:"):
        name = entity_id[len("ble:named:"):]
        rows = conn.execute(
            """SELECT DISTINCT lower(json_extract(features_json, '$.mac'))
               FROM raw_events
               WHERE scanner = 'ble_scanner'
                 AND ts_unix > ?
                 AND json_extract(features_json, '$.local_name') = ?""",
            (since, name),
        ).fetchall()
        return [r[0] for r in rows if r[0]]
    if entity_id.startswith("ble:apple:"):
        kind = entity_id[len("ble:apple:"):]
        rows = conn.execute(
            """SELECT DISTINCT lower(json_extract(features_json, '$.mac'))
               FROM raw_events
               WHERE scanner = 'ble_scanner'
                 AND ts_unix > ?
                 AND substr(json_extract(features_json, '$.manufacturer_data_hex'), 1, 4) = '4c00'
               LIMIT 200""",
            (since,),
        ).fetchall()
        # We don't filter by Apple subtype here for the MAC list — anchor's
        # rotating MACs come from ALL its broadcasts, not just one subtype.
        return [r[0] for r in rows if r[0]]
    return []


def update_cluster_inferences(conn) -> int:
    """Recompute inferred owner for active clusters; persist results.

    Called periodically from analytics. Returns number of clusters scored.
    """
    now = _now()
    active_rows = conn.execute(
        "SELECT cluster_id FROM findmy_clusters WHERE last_seen_unix > ?",
        (now - 24 * 3600,),
    ).fetchall()
    n = 0
    for (cluster_id,) in active_rows:
        anchor, score = score_cluster_copresence(conn, cluster_id)
        if score >= COPRESENCE_THRESHOLD:
            conn.execute(
                """UPDATE findmy_clusters SET
                    inferred_owner_anchor = ?,
                    inferred_owner_score = ?
                   WHERE cluster_id = ?""",
                (anchor, score, cluster_id),
            )
        else:
            conn.execute(
                """UPDATE findmy_clusters SET
                    inferred_owner_anchor = NULL,
                    inferred_owner_score = ?
                   WHERE cluster_id = ?""",
                (score, cluster_id),
            )
        n += 1
    return n
