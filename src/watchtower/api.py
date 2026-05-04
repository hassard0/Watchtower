"""HTTP API + dashboard server.

Embedded in the watchtower process as an asyncio task. Listens on
0.0.0.0:8080 by default. Serves:
  - JSON API at /api/*
  - Static SPA dashboard at /
  - Mobile probe UI at /probe
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from aiohttp import web
from ulid import ULID

from watchtower.analytics import DEFAULT_SETTINGS, load_settings, save_settings
from watchtower.storage.db import get_connection

log = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"


def _row_to_dict(cursor, row) -> dict[str, Any]:
    return {col[0]: row[i] for i, col in enumerate(cursor.description)}


def _hour_of_week_label(hw: int) -> str:
    days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    return f"{days[hw // 24]} {hw % 24:02d}:00"


class ApiServer:
    def __init__(self, db_path: Path | str, host: str = "0.0.0.0", port: int = 8080) -> None:
        self._db = Path(db_path)
        self._host = host
        self._port = port
        self._app = web.Application()
        self._app.router.add_get("/api/state", self.state)
        self._app.router.add_get("/api/entities", self.entities)
        self._app.router.add_get("/api/entities/{eid}", self.entity_detail)
        self._app.router.add_post("/api/entities/{eid}/classify", self.classify_entity)
        self._app.router.add_post("/api/entities/{eid}/name", self.rename_entity)
        self._app.router.add_get("/api/alerts", self.alerts)
        self._app.router.add_post("/api/alerts/{aid}/feedback", self.alert_feedback)
        self._app.router.add_post("/api/alerts/{aid}/ack", self.alert_ack)
        self._app.router.add_get("/api/timeline", self.timeline)
        self._app.router.add_get("/api/baseline", self.baseline)
        self._app.router.add_get("/api/health", self.health)
        # Zone + probe APIs
        self._app.router.add_get("/api/zones", self.list_zones)
        self._app.router.add_post("/api/zones", self.create_zone)
        self._app.router.add_post("/api/zones/{zone_id}/edit", self.edit_zone)
        self._app.router.add_delete("/api/zones/{zone_id}", self.delete_zone)
        self._app.router.add_post("/api/probe/start", self.probe_start)
        self._app.router.add_get("/api/probe/{capture_id}", self.probe_get)
        self._app.router.add_post("/api/probe/{capture_id}/save", self.probe_save)
        self._app.router.add_delete("/api/probe/{capture_id}", self.probe_discard)
        # Spectrum live read
        self._app.router.add_get("/api/spectrum", self.spectrum)
        # Discovery — auto-suggest enrollment candidates
        self._app.router.add_get("/api/discovery", self.discovery)
        # Settings
        self._app.router.add_get("/api/settings", self.settings_get)
        self._app.router.add_post("/api/settings", self.settings_set)
        # Admin / database tools
        self._app.router.add_post("/api/admin/reset-entities", self.admin_reset_entities)
        self._app.router.add_post("/api/alerts/ack-all", self.alerts_ack_all)
        # Static dashboard
        self._app.router.add_get("/", self.index)
        self._app.router.add_get("/probe", self.probe_page)
        if STATIC_DIR.exists():
            self._app.router.add_static("/assets", STATIC_DIR / "assets")
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None
        self._probe_task: asyncio.Task | None = None
        self._stopping = False

    async def start(self) -> None:
        self._runner = web.AppRunner(self._app, access_log=None)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, self._host, self._port)
        await self._site.start()
        self._probe_task = asyncio.create_task(self._probe_finalizer_loop())
        log.info("api: listening on http://%s:%d", self._host, self._port)

    async def stop(self) -> None:
        self._stopping = True
        if self._probe_task:
            self._probe_task.cancel()
            try:
                await self._probe_task
            except asyncio.CancelledError:
                pass
        if self._site:
            await self._site.stop()
        if self._runner:
            await self._runner.cleanup()

    async def _probe_finalizer_loop(self) -> None:
        """Watch for probe captures whose window has ended; compute fingerprints."""
        while not self._stopping:
            try:
                await asyncio.get_event_loop().run_in_executor(None, self._finalize_due_probes)
            except Exception:  # noqa: BLE001
                log.exception("probe finalizer error")
            try:
                await asyncio.sleep(2)
            except asyncio.CancelledError:
                break

    def _finalize_due_probes(self) -> None:
        now = int(time.time())
        with get_connection(self._db) as conn:
            rows = conn.execute("""
                SELECT capture_id, zone_name, started_unix, ends_unix
                FROM probe_captures
                WHERE status = 'pending' AND ends_unix <= ?
            """, (now,)).fetchall()
            for cid, zone_name, started, ends in rows:
                fp = self._compute_fingerprint(conn, started, ends)
                conn.execute(
                    "UPDATE probe_captures SET status = 'done', fingerprint_json = ? WHERE capture_id = ?",
                    (json.dumps(fp), cid),
                )

    def _compute_fingerprint(self, conn, start_unix: int, end_unix: int) -> dict:
        """Build a fingerprint of the RF environment during a capture window."""
        # BLE: top MACs by observation count + average RSSI.
        ble_rows = conn.execute("""
            SELECT lower(json_extract(features_json, '$.mac')) AS mac,
                   AVG(CAST(json_extract(features_json, '$.rssi') AS INTEGER)) AS avg_rssi,
                   MAX(CAST(json_extract(features_json, '$.rssi') AS INTEGER)) AS max_rssi,
                   COUNT(*) AS n,
                   MAX(json_extract(features_json, '$.local_name')) AS name
            FROM raw_events
            WHERE scanner = 'ble_scanner' AND ts_unix BETWEEN ? AND ?
              AND json_extract(features_json, '$.mac') IS NOT NULL
            GROUP BY mac
            HAVING n >= 2
            ORDER BY avg_rssi DESC NULLS LAST, n DESC
            LIMIT 50
        """, (start_unix, end_unix)).fetchall()
        ble = [{"mac": m, "avg_rssi": a, "max_rssi": x, "samples": n, "name": nm}
               for m, a, x, n, nm in ble_rows]

        # Build RSSI distribution histogram (5 dBm bins from -100 to -20).
        rssi_rows = conn.execute("""
            SELECT CAST(json_extract(features_json, '$.rssi') AS INTEGER) AS rssi
            FROM raw_events
            WHERE scanner = 'ble_scanner' AND ts_unix BETWEEN ? AND ?
              AND json_extract(features_json, '$.rssi') IS NOT NULL
        """, (start_unix, end_unix)).fetchall()
        bins = Counter()
        for (rssi,) in rssi_rows:
            if rssi is None:
                continue
            r = max(-100, min(-20, int(rssi)))
            b = (r // 5) * 5
            bins[b] += 1
        rssi_hist = sorted([{"bin_dbm": k, "count": v} for k, v in bins.items()],
                          key=lambda x: x["bin_dbm"])

        # Mid-band energies (latest per band in window).
        mid = conn.execute("""
            SELECT json_extract(features_json, '$.band_name') AS band,
                   AVG(CAST(json_extract(features_json, '$.energy_dbm') AS REAL)) AS avg_e,
                   MAX(CAST(json_extract(features_json, '$.energy_dbm') AS REAL)) AS max_e,
                   COUNT(*) AS n
            FROM raw_events
            WHERE scanner = 'midband_scanner' AND ts_unix BETWEEN ? AND ?
            GROUP BY band
        """, (start_unix, end_unix)).fetchall()
        mid_band = [{"band": b, "avg_dbm": a, "max_dbm": x, "samples": n}
                    for b, a, x, n in mid if b]

        # WiFi APs in window.
        wifi = conn.execute("""
            SELECT lower(json_extract(features_json, '$.mac')) AS bssid,
                   json_extract(features_json, '$.local_name') AS ssid,
                   AVG(CAST(json_extract(features_json, '$.rssi') AS INTEGER)) AS avg_rssi,
                   COUNT(*) AS n
            FROM raw_events
            WHERE scanner = 'wifi_scanner' AND ts_unix BETWEEN ? AND ?
            GROUP BY bssid
            ORDER BY avg_rssi DESC NULLS LAST
            LIMIT 30
        """, (start_unix, end_unix)).fetchall()
        wifi_aps = [{"bssid": b, "ssid": s, "avg_rssi": a, "samples": n} for b, s, a, n in wifi if b]

        # Top RSSI seen — the closest signal.
        top_rssi = max((row["max_rssi"] for row in ble if row["max_rssi"] is not None), default=None)

        return {
            "duration_sec": end_unix - start_unix,
            "ble_macs": ble,
            "ble_unique_count": len(ble),
            "rssi_histogram": rssi_hist,
            "top_rssi": top_rssi,
            "midband": mid_band,
            "wifi_aps": wifi_aps,
        }

    # ---- API handlers ----

    async def health(self, request: web.Request) -> web.Response:
        return web.json_response({"ok": True, "ts_unix": int(time.time())})

    async def state(self, request: web.Request) -> web.Response:
        now = int(time.time())
        with get_connection(self._db) as conn:
            scanners = conn.execute("""
                SELECT scanner, COUNT(*) AS n,
                       MIN(ts_unix) AS first, MAX(ts_unix) AS last
                FROM raw_events
                WHERE ts_unix > ?
                GROUP BY scanner
            """, (now - 3600,)).fetchall()
            scanner_data = [
                {"scanner": s, "events_last_hour": n, "first_unix": f, "last_unix": l}
                for s, n, f, l in scanners
            ]
            entity_summary = conn.execute("""
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN classification = 'anchor' THEN 1 ELSE 0 END) AS anchors,
                    SUM(CASE WHEN classification = 'satellite' THEN 1 ELSE 0 END) AS satellites,
                    SUM(CASE WHEN classification = 'known_guest' THEN 1 ELSE 0 END) AS known_guests,
                    SUM(CASE WHEN classification IS NULL THEN 1 ELSE 0 END) AS unknown,
                    SUM(CASE WHEN last_seen_unix > ? THEN 1 ELSE 0 END) AS active_now,
                    SUM(CASE WHEN COALESCE(anomaly_score,0) >= 0.5 AND last_seen_unix > ? THEN 1 ELSE 0 END) AS anomalous_now
                FROM entities
                WHERE last_seen_unix > ?
            """, (now - 120, now - 120, now - 7 * 86400)).fetchone()
            anchor_present = conn.execute(
                "SELECT 1 FROM entities WHERE classification = 'anchor' AND last_seen_unix > ? LIMIT 1",
                (now - 600,),
            ).fetchone()
            any_anchor = conn.execute(
                "SELECT 1 FROM entities WHERE classification = 'anchor' LIMIT 1"
            ).fetchone() is not None
            unack_alerts = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE acknowledged = 0 AND ts_unix > ?",
                (now - 86400,),
            ).fetchone()[0]
            baseline_progress = conn.execute(
                "SELECT COUNT(DISTINCT (feature || ':' || hour_of_week)) AS buckets, COUNT(DISTINCT feature) AS features FROM baseline_stats"
            ).fetchone()

        if not any_anchor:
            home_state = "unknown"
        elif anchor_present:
            home_state = "home"
        else:
            home_state = "away"
        return web.json_response({
            "ts_unix": now,
            "home_state": home_state,
            "any_anchor_enrolled": any_anchor,
            "scanners": scanner_data,
            "entities": {
                "total_7d": entity_summary[0] or 0,
                "anchors": entity_summary[1] or 0,
                "satellites": entity_summary[2] or 0,
                "known_guests": entity_summary[3] or 0,
                "unknown": entity_summary[4] or 0,
                "active_now": entity_summary[5] or 0,
                "anomalous_now": entity_summary[6] or 0,
            },
            "alerts_unack_24h": unack_alerts,
            "baseline_progress": {
                "buckets_seen": baseline_progress[0] or 0,
                "features": baseline_progress[1] or 0,
                "max_buckets": (baseline_progress[1] or 0) * 168,
            },
        })

    async def entities(self, request: web.Request) -> web.Response:
        order = request.query.get("order", "active")
        limit = int(request.query.get("limit", "200"))
        scope = request.query.get("scope", "all")  # all|active|anomalous|unknown|enrolled
        now = int(time.time())
        order_sql = {
            "active": "last_seen_unix DESC",
            "anomaly": "COALESCE(anomaly_score, 0) DESC, last_seen_unix DESC",
            "regular": "COALESCE(regularity, 0) DESC, visit_count DESC",
            "first_seen": "first_seen_unix DESC",
            "visits": "visit_count DESC",
        }.get(order, "last_seen_unix DESC")
        scope_where = {
            "all": "1=1",
            "active": "last_seen_unix > strftime('%s','now') - 120",
            "anomalous": "COALESCE(anomaly_score, 0) >= 0.4 AND last_seen_unix > strftime('%s','now') - 86400",
            "unknown": "classification IS NULL",
            "enrolled": "classification IS NOT NULL",
        }.get(scope, "1=1")
        with get_connection(self._db) as conn:
            cursor = conn.execute(f"""
                SELECT entity_id, scanner, kind, friendly_name, classification,
                       first_seen_unix, last_seen_unix, visit_count, total_observations,
                       avg_rssi, min_rssi, max_rssi, regularity, anomaly_score,
                       vendor, is_random_mac
                FROM entities
                WHERE {scope_where}
                ORDER BY {order_sql}
                LIMIT ?
            """, (limit,))
            rows = [_row_to_dict(cursor, r) for r in cursor.fetchall()]
        for r in rows:
            r["seconds_since_seen"] = now - (r["last_seen_unix"] or 0)
            r["currently_present"] = r["seconds_since_seen"] < 120
        return web.json_response({"entities": rows, "ts_unix": now})

    async def entity_detail(self, request: web.Request) -> web.Response:
        eid = request.match_info["eid"]
        with get_connection(self._db) as conn:
            cursor = conn.execute("""
                SELECT entity_id, scanner, kind, friendly_name, classification,
                       first_seen_unix, last_seen_unix, visit_count, total_observations,
                       avg_rssi, min_rssi, max_rssi, regularity, anomaly_score,
                       vendor, is_random_mac, notes_inferred
                FROM entities WHERE entity_id = ?
            """, (eid,))
            row = cursor.fetchone()
            if not row:
                return web.json_response({"error": "entity not found"}, status=404)
            entity = _row_to_dict(cursor, row)

            visits_cursor = conn.execute("""
                SELECT visit_id, start_unix, end_unix, duration_sec, observation_count, avg_rssi, max_rssi
                FROM entity_visits WHERE entity_id = ? ORDER BY start_unix DESC LIMIT 200
            """, (eid,))
            visits = [_row_to_dict(visits_cursor, r) for r in visits_cursor.fetchall()]

            # Co-presence: top 10 entities seen in same 60s windows.
            copresence_cursor = conn.execute("""
                SELECT e.entity_id, e.kind, e.friendly_name, COUNT(*) AS overlap_count
                FROM entity_visits a
                JOIN entity_visits b ON ABS(a.start_unix - b.start_unix) < 60
                JOIN entities e ON e.entity_id = b.entity_id
                WHERE a.entity_id = ? AND b.entity_id != ?
                GROUP BY b.entity_id
                ORDER BY overlap_count DESC
                LIMIT 10
            """, (eid, eid))
            copresence = [_row_to_dict(copresence_cursor, r) for r in copresence_cursor.fetchall()]
        return web.json_response({"entity": entity, "visits": visits, "copresence": copresence})

    async def classify_entity(self, request: web.Request) -> web.Response:
        eid = request.match_info["eid"]
        body = await request.json()
        classification = body.get("classification")
        if classification not in (None, "anchor", "satellite", "known_guest", "untrusted"):
            return web.json_response({"error": "invalid classification"}, status=400)
        with get_connection(self._db) as conn:
            cur = conn.execute(
                "UPDATE entities SET classification = ? WHERE entity_id = ?",
                (classification, eid),
            )
            if cur.rowcount == 0:
                return web.json_response({"error": "entity not found"}, status=404)
        return web.json_response({"ok": True, "classification": classification})

    async def rename_entity(self, request: web.Request) -> web.Response:
        eid = request.match_info["eid"]
        body = await request.json()
        name = (body.get("friendly_name") or "").strip() or None
        with get_connection(self._db) as conn:
            cur = conn.execute(
                "UPDATE entities SET friendly_name = ? WHERE entity_id = ?",
                (name, eid),
            )
            if cur.rowcount == 0:
                return web.json_response({"error": "entity not found"}, status=404)
        return web.json_response({"ok": True, "friendly_name": name})

    async def alerts(self, request: web.Request) -> web.Response:
        since = int(request.query.get("since", str(int(time.time()) - 86400)))
        with get_connection(self._db) as conn:
            cursor = conn.execute("""
                SELECT a.alert_id, a.ts_unix, a.rule_id, a.severity, a.entity_id, a.score,
                       a.home_state, a.evidence_json, a.acknowledged, a.user_feedback,
                       e.friendly_name, e.kind, e.classification
                FROM alerts a
                LEFT JOIN entities e ON a.entity_id = e.entity_id
                WHERE a.ts_unix > ?
                ORDER BY a.ts_unix DESC
                LIMIT 500
            """, (since,))
            cols = [c[0] for c in cursor.description]
            rows = []
            for r in cursor.fetchall():
                d = dict(zip(cols, r))
                d["evidence"] = json.loads(d.pop("evidence_json")) if d.get("evidence_json") else {}
                rows.append(d)
        return web.json_response({"alerts": rows, "ts_unix": int(time.time())})

    async def alert_feedback(self, request: web.Request) -> web.Response:
        aid = request.match_info["aid"]
        body = await request.json()
        f = body.get("feedback")
        if f not in (-1, 1, None):
            return web.json_response({"error": "feedback must be -1, 1, or null"}, status=400)
        with get_connection(self._db) as conn:
            conn.execute("UPDATE alerts SET user_feedback = ? WHERE alert_id = ?", (f, aid))
        return web.json_response({"ok": True})

    async def alert_ack(self, request: web.Request) -> web.Response:
        aid = request.match_info["aid"]
        with get_connection(self._db) as conn:
            conn.execute("UPDATE alerts SET acknowledged = 1 WHERE alert_id = ?", (aid,))
        return web.json_response({"ok": True})

    async def timeline(self, request: web.Request) -> web.Response:
        # Returns one row per (entity, visit). Use for timeline visualization.
        now = int(time.time())
        from_unix = int(request.query.get("from", str(now - 86400)))
        to_unix = int(request.query.get("to", str(now)))
        with get_connection(self._db) as conn:
            cursor = conn.execute("""
                SELECT v.visit_id, v.entity_id, v.start_unix, v.end_unix, v.duration_sec,
                       v.observation_count, v.avg_rssi, v.max_rssi,
                       e.kind, e.friendly_name, e.classification, e.anomaly_score, e.regularity
                FROM entity_visits v
                JOIN entities e ON e.entity_id = v.entity_id
                WHERE v.start_unix BETWEEN ? AND ?
                ORDER BY v.start_unix ASC
                LIMIT 5000
            """, (from_unix, to_unix))
            rows = [_row_to_dict(cursor, r) for r in cursor.fetchall()]
        return web.json_response({
            "from_unix": from_unix, "to_unix": to_unix,
            "visits": rows,
        })

    async def baseline(self, request: web.Request) -> web.Response:
        with get_connection(self._db) as conn:
            cursor = conn.execute("""
                SELECT feature, hour_of_week, n, mean, m2
                FROM baseline_stats
                ORDER BY feature, hour_of_week
            """)
            rows = []
            for feature, hw, n, mean, m2 in cursor.fetchall():
                stddev = (m2 / n) ** 0.5 if n > 1 else 0.0
                rows.append({
                    "feature": feature,
                    "hour_of_week": hw,
                    "label": _hour_of_week_label(hw),
                    "n": n, "mean": mean, "stddev": stddev,
                })
        # group by feature
        grouped: dict[str, list] = {}
        for r in rows:
            grouped.setdefault(r["feature"], []).append(r)
        return web.json_response({"baseline": grouped})

    async def index(self, request: web.Request) -> web.Response:
        index_html = STATIC_DIR / "index.html"
        if index_html.exists():
            return web.FileResponse(index_html)
        return web.Response(text="dashboard not installed", status=404)

    async def probe_page(self, request: web.Request) -> web.Response:
        page = STATIC_DIR / "probe.html"
        if page.exists():
            return web.FileResponse(page)
        return web.Response(text="probe page not installed", status=404)

    # ---- ZONES ----

    async def list_zones(self, request: web.Request) -> web.Response:
        with get_connection(self._db) as conn:
            cursor = conn.execute("""
                SELECT z.zone_id, z.name, z.perimeter, z.excluded_alerts,
                       z.created_unix, z.sample_count, z.notes
                FROM zones z ORDER BY z.name COLLATE NOCASE
            """)
            zones = [_row_to_dict(cursor, r) for r in cursor.fetchall()]
        return web.json_response({"zones": zones})

    async def create_zone(self, request: web.Request) -> web.Response:
        body = await request.json()
        name = (body.get("name") or "").strip()
        if not name:
            return web.json_response({"error": "name required"}, status=400)
        perimeter = 1 if body.get("perimeter") else 0
        excluded = 1 if body.get("excluded_alerts") else 0
        zid = str(ULID())
        with get_connection(self._db) as conn:
            try:
                conn.execute("""
                    INSERT INTO zones (zone_id, name, perimeter, excluded_alerts, created_unix)
                    VALUES (?, ?, ?, ?, ?)
                """, (zid, name, perimeter, excluded, int(time.time())))
            except Exception as ex:  # noqa: BLE001
                return web.json_response({"error": str(ex)}, status=409)
        return web.json_response({"ok": True, "zone_id": zid, "name": name})

    async def edit_zone(self, request: web.Request) -> web.Response:
        zid = request.match_info["zone_id"]
        body = await request.json()
        sets, vals = [], []
        if "name" in body:
            sets.append("name = ?")
            vals.append(body["name"].strip())
        if "perimeter" in body:
            sets.append("perimeter = ?")
            vals.append(1 if body["perimeter"] else 0)
        if "excluded_alerts" in body:
            sets.append("excluded_alerts = ?")
            vals.append(1 if body["excluded_alerts"] else 0)
        if "notes" in body:
            sets.append("notes = ?")
            vals.append(body["notes"])
        if not sets:
            return web.json_response({"error": "no fields"}, status=400)
        vals.append(zid)
        with get_connection(self._db) as conn:
            conn.execute(f"UPDATE zones SET {', '.join(sets)} WHERE zone_id = ?", vals)
        return web.json_response({"ok": True})

    async def delete_zone(self, request: web.Request) -> web.Response:
        zid = request.match_info["zone_id"]
        with get_connection(self._db) as conn:
            conn.execute("DELETE FROM zones WHERE zone_id = ?", (zid,))
        return web.json_response({"ok": True})

    # ---- PROBE / SITE SURVEY ----

    async def probe_start(self, request: web.Request) -> web.Response:
        body = await request.json()
        zone_name = (body.get("zone_name") or "").strip()
        duration = int(body.get("duration_sec") or 30)
        duration = max(5, min(120, duration))
        if not zone_name:
            return web.json_response({"error": "zone_name required"}, status=400)
        cid = str(ULID())
        now = int(time.time())
        with get_connection(self._db) as conn:
            conn.execute("""
                INSERT INTO probe_captures (capture_id, zone_name, started_unix, ends_unix, status)
                VALUES (?, ?, ?, ?, 'pending')
            """, (cid, zone_name, now, now + duration))
        return web.json_response({
            "capture_id": cid,
            "zone_name": zone_name,
            "started_unix": now,
            "ends_unix": now + duration,
            "duration_sec": duration,
        })

    async def probe_get(self, request: web.Request) -> web.Response:
        cid = request.match_info["capture_id"]
        with get_connection(self._db) as conn:
            cursor = conn.execute("""
                SELECT capture_id, zone_name, started_unix, ends_unix, status, fingerprint_json
                FROM probe_captures WHERE capture_id = ?
            """, (cid,))
            row = cursor.fetchone()
        if not row:
            return web.json_response({"error": "capture not found"}, status=404)
        cap = _row_to_dict(cursor, row)
        if cap.get("fingerprint_json"):
            cap["fingerprint"] = json.loads(cap.pop("fingerprint_json"))
        else:
            cap.pop("fingerprint_json", None)
            cap["fingerprint"] = None
        cap["seconds_remaining"] = max(0, cap["ends_unix"] - int(time.time()))
        return web.json_response(cap)

    async def probe_save(self, request: web.Request) -> web.Response:
        cid = request.match_info["capture_id"]
        with get_connection(self._db) as conn:
            row = conn.execute("""
                SELECT zone_name, fingerprint_json, status, started_unix, ends_unix
                FROM probe_captures WHERE capture_id = ?
            """, (cid,)).fetchone()
            if not row:
                return web.json_response({"error": "capture not found"}, status=404)
            zone_name, fp_json, status, started, ends = row
            if status != "done" or not fp_json:
                return web.json_response({"error": "capture not finalized"}, status=409)
            zrow = conn.execute("SELECT zone_id FROM zones WHERE name = ?", (zone_name,)).fetchone()
            if zrow:
                zid = zrow[0]
            else:
                zid = str(ULID())
                conn.execute("""
                    INSERT INTO zones (zone_id, name, perimeter, excluded_alerts, created_unix)
                    VALUES (?, ?, 0, 0, ?)
                """, (zid, zone_name, int(time.time())))
            sample_id = str(ULID())
            conn.execute("""
                INSERT INTO zone_samples (sample_id, zone_id, captured_unix, duration_sec, fingerprint_json)
                VALUES (?, ?, ?, ?, ?)
            """, (sample_id, zid, started, max(1, ends - started), fp_json))
            conn.execute("UPDATE zones SET sample_count = sample_count + 1 WHERE zone_id = ?", (zid,))
            conn.execute("DELETE FROM probe_captures WHERE capture_id = ?", (cid,))
        return web.json_response({"ok": True, "zone_id": zid, "sample_id": sample_id})

    async def probe_discard(self, request: web.Request) -> web.Response:
        cid = request.match_info["capture_id"]
        with get_connection(self._db) as conn:
            conn.execute("DELETE FROM probe_captures WHERE capture_id = ?", (cid,))
        return web.json_response({"ok": True})

    # ---- SPECTRUM ----

    async def spectrum(self, request: web.Request) -> web.Response:
        """Return the latest energy reading per midband and sub-GHz band, last 5 minutes."""
        now = int(time.time())
        with get_connection(self._db) as conn:
            cursor = conn.execute("""
                SELECT json_extract(features_json, '$.band_name') AS band,
                       json_extract(features_json, '$.frequency_hz') AS freq,
                       json_extract(features_json, '$.energy_dbm') AS energy,
                       ts_unix
                FROM raw_events
                WHERE scanner = 'midband_scanner' AND ts_unix > ?
                ORDER BY ts_unix DESC
                LIMIT 2000
            """, (now - 300,))
            samples = [
                {"band": b, "freq_hz": f, "energy_dbm": e, "ts_unix": t}
                for b, f, e, t in cursor.fetchall() if b and e is not None
            ]
            sub_cursor = conn.execute("""
                SELECT ts_unix, json_extract(features_json, '$.protocol') AS proto,
                       json_extract(features_json, '$.frequency_hz') AS freq
                FROM raw_events
                WHERE scanner = 'subghz_scanner' AND ts_unix > ?
                ORDER BY ts_unix DESC
                LIMIT 100
            """, (now - 3600,))
            subghz_decodes = [
                {"ts_unix": t, "protocol": p, "freq_hz": f}
                for t, p, f in sub_cursor.fetchall()
            ]
        return web.json_response({
            "ts_unix": now,
            "midband_samples": samples,
            "subghz_decodes": subghz_decodes,
        })

    # ---- ADMIN ----

    async def admin_reset_entities(self, request: web.Request) -> web.Response:
        with get_connection(self._db) as conn:
            conn.execute("DELETE FROM entity_visits")
            conn.execute("DELETE FROM entities")
            conn.execute("DELETE FROM analytics_state WHERE key = 'rollup_last_event_id'")
        return web.json_response({"ok": True})

    async def alerts_ack_all(self, request: web.Request) -> web.Response:
        with get_connection(self._db) as conn:
            conn.execute("UPDATE alerts SET acknowledged = 1 WHERE acknowledged = 0")
        return web.json_response({"ok": True})

    # ---- SETTINGS ----

    async def settings_get(self, request: web.Request) -> web.Response:
        s = load_settings(self._db)
        # also expose the schema (defaults + types) so the UI can render generically
        meta = {}
        for k, default in DEFAULT_SETTINGS.items():
            meta[k] = {"default": default, "type": type(default).__name__}
        return web.json_response({"settings": s, "schema": meta})

    async def settings_set(self, request: web.Request) -> web.Response:
        body = await request.json()
        if not isinstance(body, dict):
            return web.json_response({"error": "object expected"}, status=400)
        current = load_settings(self._db)
        for k, v in body.items():
            if k not in DEFAULT_SETTINGS:
                return web.json_response({"error": f"unknown key: {k}"}, status=400)
            current[k] = v
        save_settings(self._db, current)
        return web.json_response({"ok": True, "settings": current})

    # ---- DISCOVERY ----

    async def discovery(self, request: web.Request) -> web.Response:
        """Auto-suggest enrollment candidates: stable, frequently-seen, unclassified entities."""
        now = int(time.time())
        with get_connection(self._db) as conn:
            # Surface entities with consistent presence and unknown classification.
            cursor = conn.execute("""
                SELECT entity_id, scanner, kind, friendly_name, vendor,
                       first_seen_unix, last_seen_unix,
                       visit_count, total_observations,
                       avg_rssi, regularity, anomaly_score
                FROM entities
                WHERE classification IS NULL
                  AND total_observations >= 50
                  AND last_seen_unix > ?
                ORDER BY total_observations DESC
                LIMIT 50
            """, (now - 7 * 86400,))
            candidates = [_row_to_dict(cursor, r) for r in cursor.fetchall()]
        # Rank: stable named devices > apple-grouped > everything else
        for c in candidates:
            score = c.get("total_observations", 0) / 100
            if c.get("friendly_name"):
                score += 5
            if c.get("entity_id", "").startswith("ble:mac:"):
                score += 3
            elif c.get("entity_id", "").startswith("ble:named:"):
                score += 4
            elif c.get("entity_id", "").startswith("ble:apple:"):
                score += 2
            c["candidacy_score"] = score
        candidates.sort(key=lambda c: c["candidacy_score"], reverse=True)
        return web.json_response({"candidates": candidates[:30]})
