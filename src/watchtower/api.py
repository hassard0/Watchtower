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

from watchtower.active_probe import probe_one, _apply_probe_result
from watchtower.analytics import DEFAULT_SETTINGS, load_settings, save_settings
from watchtower.storage.db import get_connection

log = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"

# Tiny in-memory cache for expensive aggregate queries. Each entry is keyed
# by name and holds (computed_at_unix, value). Reads beyond TTL recompute.
_query_cache: dict[str, tuple[float, Any]] = {}


def _cached(key: str, ttl_sec: float, compute):
    """Memoize the result of `compute()` for `ttl_sec` seconds."""
    now = time.time()
    hit = _query_cache.get(key)
    if hit and (now - hit[0]) < ttl_sec:
        return hit[1]
    value = compute()
    _query_cache[key] = (now, value)
    return value


async def _offload(fn, *args, **kwargs):
    """Run a synchronous DB function in a worker thread.

    sqlite3 calls block the asyncio loop. When the dashboard fires several
    endpoints in parallel on tab-switch, each blocking call serializes the
    others — making page loads feel flakey even when individual queries
    are fast. Wrapping the synchronous block in asyncio.to_thread keeps
    the loop responsive so concurrent handlers actually run concurrently.
    """
    return await asyncio.to_thread(fn, *args, **kwargs)


def _row_to_dict(cursor, row) -> dict[str, Any]:
    return {col[0]: row[i] for i, col in enumerate(cursor.description)}


def _read_lan_macs() -> set[str]:
    """Return MACs of devices visible on the LAN via /proc/net/arp.

    Pi's wlan0 connects to the user's home AP, so the ARP table contains
    other clients on the same LAN — typically phones, tablets, laptops,
    smart-home hubs. These are very strong anchor/satellite candidates.
    """
    out: set[str] = set()
    try:
        with open("/proc/net/arp", "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                if i == 0:  # header
                    continue
                parts = line.split()
                if len(parts) < 4:
                    continue
                mac = parts[3].lower()
                if mac == "00:00:00:00:00:00":
                    continue
                if ":" in mac and len(mac) == 17:
                    out.add(mac)
    except FileNotFoundError:
        pass
    return out


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
        self._app.router.add_post("/api/entities/{eid}/probe", self.probe_entity)
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
        # Find-My tracker (OpenHaystack mode)
        self._app.router.add_get("/api/findmy/tracker", self.findmy_tracker_status)
        # Find-My listener — live view of nearby AirTag/Find-My broadcasts
        self._app.router.add_get("/api/findmy/observers", self.findmy_observers)
        # Find-My stable clusters — joined across MAC rotations
        self._app.router.add_get("/api/findmy/clusters", self.findmy_clusters_list)
        self._app.router.add_post("/api/findmy/clusters/{cid}/label", self.findmy_clusters_label)
        # Owned-tracker enrollment (catalog matching)
        self._app.router.add_get("/api/findmy/owned", self.findmy_owned_list)
        self._app.router.add_post("/api/findmy/owned", self.findmy_owned_add)
        self._app.router.add_delete("/api/findmy/owned/{tid}", self.findmy_owned_delete)
        self._app.router.add_post("/api/findmy/owned/{tid}/regenerate", self.findmy_owned_regen)
        # Discovery — auto-suggest enrollment candidates
        self._app.router.add_get("/api/discovery", self.discovery)
        # Morning summary — what happened recently
        self._app.router.add_get("/api/recap", self.recap)
        # Settings
        self._app.router.add_get("/api/settings", self.settings_get)
        self._app.router.add_post("/api/settings", self.settings_set)
        # Admin / database tools
        self._app.router.add_post("/api/admin/reset-entities", self.admin_reset_entities)
        self._app.router.add_post("/api/admin/test-ntfy", self.admin_test_ntfy)
        self._app.router.add_post("/api/alerts/ack-all", self.alerts_ack_all)
        # CSV exports
        self._app.router.add_get("/api/export/entities.csv", self.export_entities_csv)
        self._app.router.add_get("/api/export/alerts.csv", self.export_alerts_csv)
        self._app.router.add_get("/api/export/visits.csv", self.export_visits_csv)
        # Static dashboard
        self._app.router.add_get("/", self.index)
        self._app.router.add_get("/probe", self.probe_page)
        if STATIC_DIR.exists():
            self._app.router.add_static("/assets", STATIC_DIR / "assets")
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None
        self._probe_task: asyncio.Task | None = None
        self._stopping = False
        self._pause_scanner_factory = None
        self._findmy_tracker = None

    def set_pause_scanner_factory(self, factory) -> None:
        """Inject a coordinator so on-demand probes can pause the BLE scanner."""
        self._pause_scanner_factory = factory

    def set_findmy_tracker(self, tracker) -> None:
        """Inject the FindMyTracker so /api/findmy can expose the keypair."""
        self._findmy_tracker = tracker

    async def start(self) -> None:
        self._runner = web.AppRunner(self._app, access_log=None)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, self._host, self._port)
        await self._site.start()
        self._probe_task = asyncio.create_task(self._probe_finalizer_loop())
        self._warmer_task = asyncio.create_task(self._cache_warmer_loop())
        log.info("api: listening on http://%s:%d", self._host, self._port)

    async def _cache_warmer_loop(self) -> None:
        """Pre-warm the heaviest endpoint caches in the background.

        Without this, the first browser refresh after a 10-second idle
        hits a cold cache and waits ~750 ms for /api/state. With this
        loop running every 7 s the cache is never older than 7 s and
        page reloads always hit warm.
        """
        await asyncio.sleep(2.0)  # let the service finish settling
        while not self._stopping:
            try:
                # Just call our own _build_state_db_block helper. Keep it
                # opportunistic — don't crash the loop on a transient DB
                # error, just retry next tick.
                await self._refresh_state_cache()
            except Exception:  # noqa: BLE001
                log.warning("cache_warmer: state refresh failed (will retry)")
            try:
                await asyncio.wait_for(asyncio.shield(asyncio.sleep(7.0)), timeout=10.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                break

    async def _refresh_state_cache(self) -> None:
        """Run the state DB block now and write the result into the cache."""
        now_unix = int(time.time())
        db_path = self._db

        def _query():
            return self._state_db_block_inner(db_path, now_unix)

        result = await _offload(_query)
        _query_cache["state_db_block"] = (time.time(), result)

    @staticmethod
    def _state_db_block_inner(db_path, now_unix):
        # Mirrors the logic in `state` so the warmer and the request
        # handler stay in lock-step.
        with get_connection(db_path) as conn:
            scanners = conn.execute("""
                SELECT scanner, COUNT(*) AS n,
                       MIN(ts_unix) AS first, MAX(ts_unix) AS last
                FROM raw_events
                WHERE ts_unix > ?
                GROUP BY scanner
            """, (now_unix - 3600,)).fetchall()
            scanner_data = [
                {"scanner": s, "events_last_hour": n, "first_unix": f, "last_unix": l}
                for s, n, f, l in scanners
            ]
            SUBGHZ_EMISSION_KINDS = (
                "keyfob_emission", "garage_emission", "walkietalkie_emission",
                "lora_emission", "subghz_protocol_decoded", "unknown_subghz_burst",
            )
            placeholders = ",".join("?" * len(SUBGHZ_EMISSION_KINDS))
            row = conn.execute(
                f"SELECT COUNT(*), MIN(ts_unix), MAX(ts_unix) FROM raw_events "
                f"WHERE kind IN ({placeholders}) AND ts_unix > ?",
                (*SUBGHZ_EMISSION_KINDS, now_unix - 3600),
            ).fetchone()
            subghz_emission_n, subghz_first, subghz_last = row
            existing = next((s for s in scanner_data if s["scanner"] == "subghz_scanner"), None)
            if existing is not None:
                if subghz_emission_n > (existing.get("events_last_hour") or 0):
                    existing["events_last_hour"] = subghz_emission_n
                    existing["first_unix"] = subghz_first
                    existing["last_unix"] = subghz_last
            elif subghz_emission_n:
                scanner_data.append({
                    "scanner": "subghz_scanner",
                    "events_last_hour": subghz_emission_n,
                    "first_unix": subghz_first,
                    "last_unix": subghz_last,
                })
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
            """, (now_unix - 120, now_unix - 120, now_unix - 7 * 86400)).fetchone()
            anchor_present = conn.execute(
                "SELECT 1 FROM entities WHERE classification = 'anchor' AND last_seen_unix > ? LIMIT 1",
                (now_unix - 600,),
            ).fetchone()
            any_anchor = conn.execute(
                "SELECT 1 FROM entities WHERE classification = 'anchor' LIMIT 1"
            ).fetchone() is not None
            unack_alerts = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE acknowledged = 0 AND ts_unix > ?",
                (now_unix - 86400,),
            ).fetchone()[0]
            baseline_progress = conn.execute(
                "SELECT COUNT(DISTINCT (feature || ':' || hour_of_week)) AS buckets, COUNT(DISTINCT feature) AS features FROM baseline_stats"
            ).fetchone()
            hp_row = conn.execute(
                "SELECT value, updated_unix FROM analytics_state WHERE key = 'honeypot_active_lure'"
            ).fetchone()
            honeypot_active = None
            if hp_row and hp_row[0]:
                try:
                    hpd = json.loads(hp_row[0])
                    hpd["set_at_unix"] = hpd.get("set_at_unix") or hp_row[1]
                    honeypot_active = hpd
                except Exception:  # noqa: BLE001
                    pass
        settings = load_settings(db_path)
        return (scanner_data, entity_summary, anchor_present, any_anchor,
                unack_alerts, baseline_progress, honeypot_active, settings)

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
        db_path = self._db

        # /api/state is the heaviest poll target — fired every 5 s by the
        # dashboard. The cold call is ~750 ms because it runs 7 sequential
        # queries against a 700 MB DB; subsequent calls within TTL are
        # cache hits at <2 ms. TTL of 10 s comfortably covers the 5 s poll
        # cadence so we never alternate hot/cold (which felt "flakey" to
        # the user). The data underneath changes once per 30 s analytics
        # cycle so 10 s is well within the freshness budget.
        cache_hit = _query_cache.get("state_db_block")
        if cache_hit and (time.time() - cache_hit[0]) < 10.0:
            cached_result = cache_hit[1]
            (scanner_data, entity_summary, anchor_present, any_anchor,
             unack_alerts, baseline_progress, honeypot_active, settings) = cached_result
        else:
            result = await _offload(self._state_db_block_inner, db_path, now)
            _query_cache["state_db_block"] = (time.time(), result)
            (scanner_data, entity_summary, anchor_present, any_anchor,
             unack_alerts, baseline_progress, honeypot_active, settings) = result

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
            "honeypot": {
                "enabled": bool(settings.get("honeypot_enabled")),
                "active_lure": honeypot_active,
            },
            "active_probing_enabled": bool(settings.get("active_probing_enabled")),
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
        db_path = self._db

        def _query():
            with get_connection(db_path) as conn:
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
                return [_row_to_dict(cursor, r) for r in cursor.fetchall()]

        rows = await _offload(_query)
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

    async def probe_entity(self, request: web.Request) -> web.Response:
        """Synchronously fire a GATT probe at the entity's MAC and return the result.

        Handles three entity_id shapes:
        - ble:mac:<mac>     -> probe directly
        - ble:named:<name>  -> look up the most recently seen MAC matching that local_name
        - ble:apple:<kind>  -> look up the strongest-RSSI recent MAC with matching apple subtype
        """
        eid = request.match_info["eid"]
        mac: str | None = None
        chosen_via = ""
        if eid.startswith("ble:mac:"):
            mac = eid[len("ble:mac:"):]
            chosen_via = "stable MAC"
        elif eid.startswith("ble:named:"):
            name = eid[len("ble:named:"):]
            with get_connection(self._db) as conn:
                row = conn.execute(
                    """SELECT json_extract(features_json,'$.mac'), MAX(ts_unix)
                       FROM raw_events
                       WHERE scanner='ble_scanner' AND ts_unix > strftime('%s','now') - 600
                         AND json_extract(features_json,'$.local_name') = ?
                       GROUP BY json_extract(features_json,'$.mac')
                       ORDER BY MAX(ts_unix) DESC LIMIT 1""",
                    (name,),
                ).fetchone()
            if row and row[0]:
                mac = row[0].lower()
                chosen_via = f"current MAC for local_name={name!r}"
        elif eid.startswith("ble:apple:") or eid.startswith("ble:random:"):
            return web.json_response({
                "ok": True,
                "result": {
                    "ok": False,
                    "error": (
                        "this entity is grouped by Apple Continuity subtype / fingerprint, "
                        "not a single MAC. probing requires a specific device — open the "
                        "Entities tab and pick a stable-MAC entity, or wait for the device "
                        "to surface as ble:mac:* once we see its non-random MAC."
                    ),
                },
            })
        else:
            return web.json_response({
                "ok": True,
                "result": {"ok": False, "error": f"non-BLE entity ({eid}) — GATT probe N/A"},
            })

        if not mac:
            return web.json_response({
                "ok": True,
                "result": {"ok": False, "error": "no recent MAC found for this entity (last 10 min)"},
            })
        result = await probe_one(mac, pause_scanner=self._pause_scanner_factory)
        result["probed_mac"] = mac
        result["chosen_via"] = chosen_via
        with get_connection(self._db) as conn:
            _apply_probe_result(conn, eid, result)
        return web.json_response({"ok": True, "result": result})

    async def alerts(self, request: web.Request) -> web.Response:
        # Default window is 4 hours and 100 rows so the dashboard's 5-second
        # poll doesn't drag down a 200 KB payload. The Alerts tab can pass
        # ?since=<unix>&limit=500 when the user scrolls back. Without this
        # the page-refresh feel was flakey on weak Wi-Fi: 200 KB / 5 s of
        # the same data being re-fetched ate the connection.
        now_unix = int(time.time())
        since = int(request.query.get("since", str(now_unix - 4 * 3600)))
        limit = max(1, min(500, int(request.query.get("limit", "100"))))
        db_path = self._db

        def _query():
            with get_connection(db_path) as conn:
                cursor = conn.execute("""
                    SELECT a.alert_id, a.ts_unix, a.rule_id, a.severity, a.entity_id, a.score,
                           a.home_state, a.evidence_json, a.acknowledged, a.user_feedback,
                           e.friendly_name, e.kind, e.classification
                    FROM alerts a
                    LEFT JOIN entities e ON a.entity_id = e.entity_id
                    WHERE a.ts_unix > ?
                    ORDER BY a.ts_unix DESC
                    LIMIT ?
                """, (since, limit))
                cols = [c[0] for c in cursor.description]
                rows = []
                for r in cursor.fetchall():
                    d = dict(zip(cols, r))
                    d["evidence"] = json.loads(d.pop("evidence_json")) if d.get("evidence_json") else {}
                    rows.append(d)
                return rows

        rows = await _offload(_query)
        return web.json_response({"alerts": rows, "ts_unix": now_unix})

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
        db_path = self._db

        def _query():
            with get_connection(db_path) as conn:
                cursor = conn.execute("""
                    SELECT feature, hour_of_week, n, mean, m2
                    FROM baseline_stats
                    ORDER BY feature, hour_of_week
                """)
                out = []
                for feature, hw, n, mean, m2 in cursor.fetchall():
                    stddev = (m2 / n) ** 0.5 if n > 1 else 0.0
                    out.append({
                        "feature": feature,
                        "hour_of_week": hw,
                        "label": _hour_of_week_label(hw),
                        "n": n, "mean": mean, "stddev": stddev,
                    })
                return out

        rows = await _offload(_query)
        grouped: dict[str, list] = {}
        for r in rows:
            grouped.setdefault(r["feature"], []).append(r)
        return web.json_response({"baseline": grouped})

    async def index(self, request: web.Request) -> web.Response:
        index_html = STATIC_DIR / "index.html"
        if index_html.exists():
            # Never cache the HTML — it embeds the cache-busting ?v= for the
            # JS bundle, and a stale HTML pointing at an old JS version means
            # the dashboard runs on outdated code (which is what made the
            # radar disappear after a deploy: index.html cached, app.js fresh).
            return web.FileResponse(index_html, headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            })
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
        """Return the latest energy reading per midband and sub-GHz band.

        Window is adaptive: starts at last 5 min; if empty (e.g. midband
        scanner is down), expands to 1 hour and includes a `stale` flag so
        the UI can warn the user.
        """
        now = int(time.time())
        with get_connection(self._db) as conn:
            samples = []
            window_sec = 300
            for win in (300, 3600, 86400):  # 5 min → 1 h → 24 h
                cursor = conn.execute("""
                    SELECT json_extract(features_json, '$.band_name') AS band,
                           json_extract(features_json, '$.frequency_hz') AS freq,
                           json_extract(features_json, '$.energy_dbm') AS energy,
                           ts_unix
                    FROM raw_events
                    WHERE scanner = 'midband_scanner' AND ts_unix > ?
                    ORDER BY ts_unix DESC
                    LIMIT 2000
                """, (now - win,))
                samples = [
                    {"band": b, "freq_hz": f, "energy_dbm": e, "ts_unix": t}
                    for b, f, e, t in cursor.fetchall() if b and e is not None
                ]
                window_sec = win
                if samples:
                    break

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
        most_recent = max((s["ts_unix"] for s in samples), default=0)
        stale = (now - most_recent) > 120 if most_recent else True
        return web.json_response({
            "ts_unix": now,
            "midband_samples": samples,
            "subghz_decodes": subghz_decodes,
            "window_sec": window_sec,
            "stale": stale,
            "stale_age_sec": (now - most_recent) if most_recent else None,
        })

    # ---- CSV EXPORTS ----

    def _csv_response(self, rows, headers):
        import csv, io
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(headers)
        for r in rows:
            w.writerow(r)
        return web.Response(
            text=buf.getvalue(),
            content_type="text/csv",
            headers={"Content-Disposition": "attachment"},
        )

    async def export_entities_csv(self, request: web.Request) -> web.Response:
        with get_connection(self._db) as conn:
            rows = conn.execute("""
                SELECT entity_id, scanner, kind, friendly_name, classification,
                       first_seen_unix, last_seen_unix, visit_count, total_observations,
                       avg_rssi, min_rssi, max_rssi, regularity, anomaly_score,
                       vendor, is_random_mac
                FROM entities ORDER BY last_seen_unix DESC
            """).fetchall()
        return self._csv_response(rows, [
            "entity_id","scanner","kind","friendly_name","classification",
            "first_seen_unix","last_seen_unix","visit_count","total_observations",
            "avg_rssi","min_rssi","max_rssi","regularity","anomaly_score",
            "vendor","is_random_mac",
        ])

    async def export_alerts_csv(self, request: web.Request) -> web.Response:
        with get_connection(self._db) as conn:
            rows = conn.execute("""
                SELECT alert_id, ts_unix, rule_id, severity, entity_id, score,
                       home_state, evidence_json, acknowledged, user_feedback
                FROM alerts ORDER BY ts_unix DESC
            """).fetchall()
        return self._csv_response(rows, [
            "alert_id","ts_unix","rule_id","severity","entity_id","score",
            "home_state","evidence_json","acknowledged","user_feedback",
        ])

    async def export_visits_csv(self, request: web.Request) -> web.Response:
        with get_connection(self._db) as conn:
            rows = conn.execute("""
                SELECT visit_id, entity_id, start_unix, end_unix, duration_sec,
                       observation_count, avg_rssi, max_rssi
                FROM entity_visits ORDER BY start_unix DESC
            """).fetchall()
        return self._csv_response(rows, [
            "visit_id","entity_id","start_unix","end_unix","duration_sec",
            "observation_count","avg_rssi","max_rssi",
        ])

    # ---- ADMIN ----

    async def admin_reset_entities(self, request: web.Request) -> web.Response:
        with get_connection(self._db) as conn:
            conn.execute("DELETE FROM entity_visits")
            conn.execute("DELETE FROM entities")
            conn.execute("DELETE FROM analytics_state WHERE key = 'rollup_last_event_id'")
        return web.json_response({"ok": True})

    async def admin_test_ntfy(self, request: web.Request) -> web.Response:
        """Send a synthetic high-severity alert through the dispatcher to verify ntfy + webhook + mqtt config."""
        from watchtower.analytics import _dispatch_external
        s = load_settings(self._db)
        await asyncio.get_event_loop().run_in_executor(
            None, _dispatch_external, s, {
                "alert_id": "test_" + str(int(time.time())),
                "ts_unix": int(time.time()),
                "rule_id": "test_notification",
                "severity": "high",
                "entity_id": None,
                "score": 1.0,
                "home_state": "test",
                "evidence": {"explanation": "This is a test alert from the Watchtower Settings tab."},
            },
        )
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

    # ---- RECAP ----

    async def recap(self, request: web.Request) -> web.Response:
        """Summary of activity over the last N hours (default 8h ≈ overnight).

        Returns:
        - new_entities: first-seen during the window
        - departed_entities: last-seen during the window but not after (left range)
        - alert_counts: alerts fired by severity
        - top_alerts: high/critical alerts to surface
        - busiest_hour: peak BLE rate hour
        - peak_count: peak unique-MAC count in any 5min bucket
        """
        hours = int(request.query.get("hours", "8"))
        window = max(1, min(168, hours)) * 3600
        now = int(time.time())
        since = now - window
        with get_connection(self._db) as conn:
            new_entities = conn.execute("""
                SELECT entity_id, kind, friendly_name, first_seen_unix, last_seen_unix,
                       avg_rssi, total_observations, anomaly_score
                FROM entities
                WHERE first_seen_unix >= ?
                ORDER BY total_observations DESC LIMIT 30
            """, (since,)).fetchall()
            departed_entities = conn.execute("""
                SELECT entity_id, kind, friendly_name, classification,
                       first_seen_unix, last_seen_unix, total_observations
                FROM entities
                WHERE last_seen_unix BETWEEN ? AND ?
                  AND last_seen_unix < ? - 600
                ORDER BY last_seen_unix DESC LIMIT 30
            """, (since, now, now)).fetchall()
            alert_counts = conn.execute("""
                SELECT severity, COUNT(*) FROM alerts WHERE ts_unix >= ? GROUP BY severity
            """, (since,)).fetchall()
            top_alerts = conn.execute("""
                SELECT a.alert_id, a.ts_unix, a.rule_id, a.severity, a.entity_id,
                       a.score, a.evidence_json, e.friendly_name, e.kind
                FROM alerts a
                LEFT JOIN entities e ON a.entity_id = e.entity_id
                WHERE a.ts_unix >= ? AND a.severity IN ('high', 'critical')
                ORDER BY a.ts_unix DESC LIMIT 20
            """, (since,)).fetchall()
            ble_per_5min = conn.execute("""
                SELECT (ts_unix / 300) * 300 AS bucket, COUNT(DISTINCT json_extract(features_json, '$.mac')) AS unique_macs
                FROM raw_events
                WHERE scanner = 'ble_scanner' AND ts_unix >= ?
                GROUP BY bucket
                ORDER BY unique_macs DESC LIMIT 1
            """, (since,)).fetchone()
            total_events = conn.execute("""
                SELECT COUNT(*) FROM raw_events WHERE ts_unix >= ?
            """, (since,)).fetchone()[0]
        new_dicts = [
            {"entity_id": e[0], "kind": e[1], "friendly_name": e[2],
             "first_seen_unix": e[3], "last_seen_unix": e[4],
             "avg_rssi": e[5], "total_observations": e[6], "anomaly_score": e[7]}
            for e in new_entities
        ]
        departed_dicts = [
            {"entity_id": e[0], "kind": e[1], "friendly_name": e[2],
             "classification": e[3],
             "first_seen_unix": e[4], "last_seen_unix": e[5],
             "total_observations": e[6]}
            for e in departed_entities
        ]
        alert_dicts = []
        for aid, ts, rid, sev, eid, score, ev_json, fname, kind in top_alerts:
            alert_dicts.append({
                "alert_id": aid, "ts_unix": ts, "rule_id": rid, "severity": sev,
                "entity_id": eid, "score": score,
                "evidence": json.loads(ev_json) if ev_json else {},
                "friendly_name": fname, "kind": kind,
            })
        return web.json_response({
            "window_hours": hours,
            "since_unix": since,
            "ts_unix": now,
            "new_entities_count": len(new_dicts),
            "new_entities": new_dicts,
            "departed_entities_count": len(departed_dicts),
            "departed_entities": departed_dicts,
            "alert_counts": {sev: c for sev, c in alert_counts},
            "alerts_total": sum(c for _, c in alert_counts),
            "top_alerts": alert_dicts,
            "peak_unique_macs_5min": ble_per_5min[1] if ble_per_5min else 0,
            "peak_unique_macs_at_unix": ble_per_5min[0] if ble_per_5min else 0,
            "total_events": total_events,
        })

    # ---- FIND-MY TRACKER ----

    async def findmy_observers(self, request: web.Request) -> web.Response:
        """Live snapshot of nearby Find-My broadcasts.

        For each rotating BLE address that emitted a Find-My advertisement in
        the configured window, returns the most-recent state, RSSI, sighting
        count, status nibble, and decoded ownership. Each *distinct* rotating
        address is approximately a distinct tracker (Apple keys rotate every
        ~15 min so a 5-min window mostly captures one slot per tracker).
        """
        from watchtower.apple_continuity import decode_continuity, short_state_summary
        window = max(10, min(900, int(request.query.get("window", "300"))))
        now = int(time.time())
        db_path = self._db

        def _query_observers():
            # Rotating-MAC aggregation over last `window` seconds. With ~3300
            # ble_scanner rows in a 5-min window and a json_extract per row,
            # this costs ~500 ms — too expensive to repeat on every dashboard
            # poll. Result only changes by a handful of MACs every 30 s, so
            # cache it briefly.
            rows_cache_key = f"findmy_observers_rows_{window}"
            def _compute_rows():
                with get_connection(db_path) as conn:
                    return conn.execute("""
                        SELECT lower(json_extract(features_json, '$.mac')) AS mac,
                               MAX(json_extract(features_json, '$.manufacturer_data_hex')) AS mfr,
                               MAX(CAST(json_extract(features_json, '$.rssi') AS INTEGER)) AS max_rssi,
                               AVG(CAST(json_extract(features_json, '$.rssi') AS INTEGER)) AS avg_rssi,
                               MIN(ts_unix) AS first_seen,
                               MAX(ts_unix) AS last_seen,
                               COUNT(*) AS sightings
                        FROM raw_events
                        WHERE scanner = 'ble_scanner'
                          AND ts_unix > ?
                          AND substr(json_extract(features_json, '$.manufacturer_data_hex'), 1, 6) = '4c0012'
                        GROUP BY mac
                        ORDER BY max_rssi DESC NULLS LAST
                        LIMIT 100
                    """, (now - window,)).fetchall()
            rows = _cached(rows_cache_key, 30.0, _compute_rows)
            with get_connection(db_path) as conn:
                # Daily-presence aggregate is the slow part — keep it cached.
                def _compute_daily_presence_inner():
                    day_rows = conn.execute("""
                        WITH minute_buckets AS (
                            SELECT date(ts_unix, 'unixepoch', 'localtime') AS day,
                                   CAST(ts_unix / 60 AS INTEGER) AS bucket
                            FROM raw_events
                            WHERE scanner = 'ble_scanner'
                              AND ts_unix > strftime('%s','now') - 7 * 86400
                              AND substr(json_extract(features_json, '$.manufacturer_data_hex'), 1, 6) = '4c0012'
                            GROUP BY day, bucket
                        )
                        SELECT day, COUNT(*) AS minutes_with_findmy
                        FROM minute_buckets GROUP BY day ORDER BY day DESC
                    """).fetchall()
                    return [{"day": d, "minutes_with_findmy": m} for d, m in day_rows]
                daily = _cached("findmy_daily_presence", 300.0, _compute_daily_presence_inner)
                return rows, daily

        rows, daily = await _offload(_query_observers)
        observers = []
        for mac, mfr, max_rssi, avg_rssi, first_seen, last_seen, sightings in rows:
            decoded = decode_continuity(mfr or "")
            observers.append({
                "rotating_mac": mac,
                "max_rssi": max_rssi,
                "avg_rssi": round(avg_rssi, 1) if avg_rssi is not None else None,
                "first_seen_unix": first_seen,
                "last_seen_unix": last_seen,
                "sightings": sightings,
                "status": (decoded or {}).get("status"),
                "maintained": (decoded or {}).get("maintained"),
                "summary": short_state_summary(decoded) if decoded else "",
            })

        # Group observers by status nibble for quick "owned vs unowned" counts.
        by_status: dict[str, int] = {}
        for o in observers:
            key = o.get("status") or "unknown"
            by_status[key] = by_status.get(key, 0) + 1

        return web.json_response({
            "ts_unix": now,
            "window_sec": window,
            "distinct_count": len(observers),
            "by_status": by_status,
            "observers": observers,
            "daily_presence": daily,
        })

    async def findmy_clusters_list(self, request: web.Request) -> web.Response:
        """Stable Find-My clusters joined across rotating MAC handoffs."""
        active_only = request.query.get("active_only", "1") == "1"
        now = int(time.time())
        cutoff = now - (3600 if active_only else 7 * 86400)
        db_path = self._db

        def _query():
            with get_connection(db_path) as conn:
                cursor = conn.execute("""
                    SELECT c.cluster_id, c.first_seen_unix, c.last_seen_unix,
                           c.sighting_count, c.rotation_count, c.last_rssi, c.avg_rssi,
                           c.last_status, c.last_mac, c.classification, c.user_label,
                           c.inferred_owner_anchor, c.inferred_owner_score, c.notes,
                           e.friendly_name AS owner_friendly_name
                    FROM findmy_clusters c
                    LEFT JOIN entities e ON e.entity_id = c.inferred_owner_anchor
                    WHERE c.last_seen_unix > ?
                    ORDER BY c.last_seen_unix DESC, c.sighting_count DESC
                    LIMIT 100
                """, (cutoff,))
                cols = [c[0] for c in cursor.description]
                return [dict(zip(cols, r)) for r in cursor.fetchall()]

        rows = await _offload(_query)
        # Add a derived best-guess label for each cluster.
        for r in rows:
            r["display_label"] = (
                r.get("user_label")
                or (f"AirTag (probably {r['owner_friendly_name'] or r['inferred_owner_anchor']}'s)"
                    if r.get("inferred_owner_anchor") else None)
                or f"unidentified tracker · {r['last_status'] or 'unknown'}"
            )
            r["seconds_since_seen"] = now - (r.get("last_seen_unix") or 0)
        return web.json_response({"ts_unix": now, "clusters": rows})

    async def findmy_clusters_label(self, request: web.Request) -> web.Response:
        cid = request.match_info["cid"]
        body = await request.json()
        label = (body.get("label") or "").strip() or None
        classification = body.get("classification")
        if classification not in (None, "known", "suspicious", "enrolled"):
            return web.json_response({"error": "invalid classification"}, status=400)
        with get_connection(self._db) as conn:
            cur = conn.execute(
                "UPDATE findmy_clusters SET user_label = ?, classification = COALESCE(?, classification) WHERE cluster_id = ?",
                (label, classification, cid),
            )
            if cur.rowcount == 0:
                return web.json_response({"error": "cluster not found"}, status=404)
        return web.json_response({"ok": True})

    # ---- OWNED TRACKER ENROLLMENT ----

    async def findmy_owned_list(self, request: web.Request) -> web.Response:
        from watchtower.findmy_owned import list_trackers
        trackers = await asyncio.get_event_loop().run_in_executor(
            None, list_trackers, self._db,
        )
        return web.json_response({"trackers": trackers})

    async def findmy_owned_add(self, request: web.Request) -> web.Response:
        body = await request.json()
        name = (body.get("name") or "").strip()
        priv = (body.get("master_priv_b64") or "").strip()
        sym = (body.get("master_sym_b64") or "").strip()
        if not (name and priv and sym):
            return web.json_response(
                {"error": "name, master_priv_b64, master_sym_b64 all required"},
                status=400,
            )
        try:
            from watchtower.findmy_owned import store_tracker, regenerate_catalog
            tid = await asyncio.get_event_loop().run_in_executor(
                None, store_tracker, self._db, name, priv, sym,
            )
            # Pre-populate the catalog immediately so first match is < 4 hr away.
            with get_connection(self._db) as conn:
                row = conn.execute(
                    "SELECT enrolled_unix FROM findmy_owned_trackers WHERE tracker_id = ?",
                    (tid,),
                ).fetchone()
                enrolled = row[0] if row else int(time.time())
            await asyncio.get_event_loop().run_in_executor(
                None, regenerate_catalog, self._db, tid, enrolled,
            )
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        except Exception as e:  # noqa: BLE001
            log.exception("findmy_owned_add failed")
            return web.json_response({"error": str(e)}, status=500)
        return web.json_response({"ok": True, "tracker_id": tid})

    async def findmy_owned_delete(self, request: web.Request) -> web.Response:
        from watchtower.findmy_owned import delete_tracker
        tid = request.match_info["tid"]
        ok = await asyncio.get_event_loop().run_in_executor(
            None, delete_tracker, self._db, tid,
        )
        return web.json_response({"ok": ok})

    async def findmy_owned_regen(self, request: web.Request) -> web.Response:
        from watchtower.findmy_owned import regenerate_catalog
        tid = request.match_info["tid"]
        with get_connection(self._db) as conn:
            row = conn.execute(
                "SELECT enrolled_unix FROM findmy_owned_trackers WHERE tracker_id = ?",
                (tid,),
            ).fetchone()
        if not row:
            return web.json_response({"error": "not found"}, status=404)
        n = await asyncio.get_event_loop().run_in_executor(
            None, regenerate_catalog, self._db, tid, row[0],
        )
        return web.json_response({"ok": True, "slots_inserted": n})

    async def findmy_tracker_status(self, request: web.Request) -> web.Response:
        if self._findmy_tracker is None:
            return web.json_response({"error": "tracker not initialized"}, status=503)
        status = self._findmy_tracker.get_status()
        # Suppress private key from default GET; require ?reveal=1 to include it.
        if request.query.get("reveal") != "1":
            status.pop("private_key_pem", None)
        return web.json_response(status)

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
                       avg_rssi, regularity, anomaly_score, is_random_mac
                FROM entities
                WHERE classification IS NULL
                  AND total_observations >= 50
                  AND last_seen_unix > ?
                ORDER BY total_observations DESC
                LIMIT 100
            """, (now - 7 * 86400,))
            candidates = [_row_to_dict(cursor, r) for r in cursor.fetchall()]

        lan_macs = _read_lan_macs()
        for c in candidates:
            score = c.get("total_observations", 0) / 100
            if c.get("friendly_name"):
                score += 5
            eid = c.get("entity_id", "")
            on_lan = False
            if eid.startswith("ble:mac:"):
                score += 3
                if eid[8:].lower() in lan_macs:
                    score += 20  # huge boost: this device is on your home WiFi
                    on_lan = True
            elif eid.startswith("ble:named:"):
                score += 4
            elif eid.startswith("ble:apple:"):
                score += 2
            elif eid.startswith("wifi:mac:"):
                if eid[9:].lower() in lan_macs:
                    score += 15
                    on_lan = True
            c["on_home_wifi"] = on_lan
            c["candidacy_score"] = score
        candidates.sort(key=lambda c: c["candidacy_score"], reverse=True)
        return web.json_response({"candidates": candidates[:30], "lan_macs": list(lan_macs)})
