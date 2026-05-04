"""HTTP API + dashboard server.

Embedded in the watchtower process as an asyncio task. Listens on
0.0.0.0:8080 by default. Serves:
  - JSON API at /api/*
  - Static SPA dashboard at /
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from aiohttp import web

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
        # Static dashboard
        self._app.router.add_get("/", self.index)
        if STATIC_DIR.exists():
            self._app.router.add_static("/assets", STATIC_DIR / "assets")
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None

    async def start(self) -> None:
        self._runner = web.AppRunner(self._app, access_log=None)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, self._host, self._port)
        await self._site.start()
        log.info("api: listening on http://%s:%d", self._host, self._port)

    async def stop(self) -> None:
        if self._site:
            await self._site.stop()
        if self._runner:
            await self._runner.cleanup()

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
            unack_alerts = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE acknowledged = 0 AND ts_unix > ?",
                (now - 86400,),
            ).fetchone()[0]
            baseline_progress = conn.execute(
                "SELECT COUNT(DISTINCT (feature || ':' || hour_of_week)) AS buckets, COUNT(DISTINCT feature) AS features FROM baseline_stats"
            ).fetchone()

        return web.json_response({
            "ts_unix": now,
            "home_state": "home" if anchor_present else "away",
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
