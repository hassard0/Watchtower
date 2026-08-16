"""Active BLE GATT prober.

Briefly connects to BLE devices to read the standard "device info" GATT
characteristics that often reveal a much friendlier name than the advertising
local_name field:

    0x2A00  Generic Access → Device Name
    0x2A29  Device Information → Manufacturer Name String
    0x2A24  Device Information → Model Number String

Many devices reject unauthenticated connections (iPhones, AirTags, locks),
so we expect a 30-50% hit rate. That's still a lot of "phone (random MAC)"
turning into "Govee_H5151 — Smart Bulb v3" or "Beats Studio Pro — Apple, Inc.".

Operational guarantees:
- Rate-limited per entity: max one probe per 24h per entity.
- Concurrency-limited globally: max one probe in flight at a time
  (BlueZ + bleak don't always handle parallel connect+scan reliably on
  a single Pi adapter).
- Probe attempts are recorded as `probe_attempts.last_attempt_unix` /
  `probe_attempts.outcome` in analytics_state so re-probing is bounded.
- Toggle-able: settings.active_probing_enabled (default OFF for privacy).
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path

from bleak import BleakClient
from bleak.exc import BleakError

from watchtower.storage.db import get_connection
from watchtower.name_resolution import clean_name, record_name_candidate

log = logging.getLogger(__name__)

# Standard GATT characteristic UUIDs (full 128-bit form).
UUID_DEVICE_NAME = "00002a00-0000-1000-8000-00805f9b34fb"
UUID_MFR_NAME = "00002a29-0000-1000-8000-00805f9b34fb"
UUID_MODEL = "00002a24-0000-1000-8000-00805f9b34fb"
UUID_FW = "00002a26-0000-1000-8000-00805f9b34fb"

PROBE_TIMEOUT_SEC = 5.0
PER_CHAR_READ_TIMEOUT_SEC = 1.5
COOLDOWN_SUCCESS_SEC = 7 * 86400   # don't re-probe successful entities for a week
COOLDOWN_FAILURE_SEC = 24 * 3600   # don't re-probe failed entities for a day


def _mark_outgoing(mac: str) -> None:
    """Tell the Honeypot watcher we initiated this connect so it doesn't
    flag it as honeypot engagement."""
    try:
        from watchtower.honeypot import Honeypot
        Honeypot.mark_outgoing(mac)
    except Exception:  # noqa: BLE001
        pass


async def _connect_and_read(mac: str, adapter: str | None) -> dict:
    """Inner connect-and-read. Bails early once name + mfr are populated to
    avoid waiting on read timeouts for devices that don't expose model/fw."""
    out: dict = {"ok": False, "name": None, "mfr": None, "model": None,
                 "fw": None, "error": None}
    async with BleakClient(mac, timeout=PROBE_TIMEOUT_SEC, adapter=adapter) as client:
        for key, uuid in (
            ("name", UUID_DEVICE_NAME),
            ("mfr", UUID_MFR_NAME),
            ("model", UUID_MODEL),
            ("fw", UUID_FW),
        ):
            try:
                data = await asyncio.wait_for(
                    client.read_gatt_char(uuid),
                    timeout=PER_CHAR_READ_TIMEOUT_SEC,
                )
                out[key] = clean_name(data.decode("utf-8", errors="replace"))
            except (BleakError, asyncio.TimeoutError, OSError):
                pass
            except Exception:  # noqa: BLE001
                log.exception("probe: read failed for %s on %s", uuid, mac)
            # Fast bail: if we have name + manufacturer, that's plenty.
            if out["name"] and out["mfr"] and key in ("mfr", "model"):
                break
        out["ok"] = any(out[k] for k in ("name", "mfr", "model"))
    return out


async def probe_one(mac: str, adapter: str | None = "hci0", pause_scanner=None) -> dict:
    """Connect to MAC, read characteristics, return dict.

    Strategy: try connecting WITHOUT pausing the BLE scanner first (modern
    BlueZ + bleak usually handles concurrent scan+connect fine). If we hit
    "operation already in progress" or similar, retry once with the scanner
    paused via `pause_scanner` if provided.

    Returns: {"ok": bool, "name", "mfr", "model", "fw", "error"}
    """
    out: dict = {"ok": False, "name": None, "mfr": None, "model": None,
                 "fw": None, "error": None}
    _mark_outgoing(mac)
    # First attempt: no pause — much faster (avoids the ~3-5s scanner restart).
    try:
        return await _connect_and_read(mac, adapter)
    except (BleakError, asyncio.TimeoutError, OSError) as e:
        msg = str(e).lower()
        # Recognizable "scanner-conflict" errors — retry with pause.
        is_busy = ("already in progress" in msg or "busy" in msg or
                   "in-progress" in msg or "operation already" in msg)
        if not is_busy or pause_scanner is None:
            out["error"] = str(e)[:200]
            return out
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)[:200]
        log.exception("probe: unexpected error for %s", mac)
        return out
    # Retry path: pause the scanner and try once more.
    try:
        async with await pause_scanner():
            try:
                return await _connect_and_read(mac, adapter)
            except (BleakError, asyncio.TimeoutError, OSError) as e:
                out["error"] = str(e)[:200]
            except Exception as e:  # noqa: BLE001
                out["error"] = str(e)[:200]
                log.exception("probe: retry failed for %s", mac)
    except Exception as e:  # noqa: BLE001
        out["error"] = out.get("error") or str(e)[:200]
    return out


def _load_attempts(conn) -> dict:
    row = conn.execute(
        "SELECT value FROM analytics_state WHERE key = 'probe_attempts'"
    ).fetchone()
    if row and row[0]:
        try:
            return json.loads(row[0])
        except Exception:  # noqa: BLE001
            return {}
    return {}


def _save_attempts(conn, attempts: dict) -> None:
    conn.execute(
        "INSERT INTO analytics_state(key, value, updated_unix) VALUES('probe_attempts', ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_unix = excluded.updated_unix",
        (json.dumps(attempts), int(time.time())),
    )


def _entity_mac(entity_id: str) -> str | None:
    """Extract the MAC from a 'ble:mac:aa:bb:..' entity_id. None for non-MAC entities."""
    if entity_id.startswith("ble:mac:"):
        return entity_id[len("ble:mac:"):]
    return None


def _candidate_entities(conn, max_n: int = 10) -> list[tuple[str, str, str | None]]:
    """Pick entities worth probing right now.

    Returns list of (entity_id, mac, current_friendly_name).
    """
    now = int(time.time())
    attempts = _load_attempts(conn)
    rows = conn.execute(
        """SELECT entity_id, friendly_name, friendly_name_source,
                  total_observations, last_seen_unix
           FROM entities
           WHERE entity_id LIKE 'ble:mac:%'
             AND last_seen_unix > ?
             AND total_observations >= 5
           ORDER BY total_observations DESC
           LIMIT 100""",
        (now - 600,),
    ).fetchall()
    out: list[tuple[str, str, str | None]] = []
    for entity_id, friendly_name, friendly_name_source, total_obs, last_seen in rows:
        mac = _entity_mac(entity_id)
        if not mac:
            continue
        a = attempts.get(entity_id, {})
        last_attempt = a.get("ts", 0)
        outcome = a.get("outcome")
        cooldown = COOLDOWN_SUCCESS_SEC if outcome == "ok" else COOLDOWN_FAILURE_SEC
        if last_attempt and (now - last_attempt) < cooldown:
            continue
        # Skip entities that already have a user-set name.
        if friendly_name and friendly_name_source == "user":
            continue
        out.append((entity_id, mac, friendly_name))
        if len(out) >= max_n:
            break
    return out


def _apply_probe_result(conn, entity_id: str, result: dict) -> None:
    """Update entity row with probe result and persist attempt record."""
    now = int(time.time())
    attempts = _load_attempts(conn)
    if result["ok"]:
        evidence = {key: result.get(key) for key in ("mfr", "model", "fw") if result.get(key)}
        if result.get("mfr"):
            conn.execute(
                "UPDATE entities SET vendor = COALESCE(vendor, ?) WHERE entity_id = ?",
                (result["mfr"], entity_id),
            )
        if result.get("name"):
            record_name_candidate(
                conn, entity_id, result["name"], "ble_gatt_device_name",
                evidence=evidence, observed_unix=now,
            )
        if result.get("model"):
            model = result["model"]
            mfr = result.get("mfr")
            display = f"{mfr} {model}" if mfr and mfr.casefold() not in model.casefold() else model
            record_name_candidate(
                conn, entity_id, display, "ble_gatt_model",
                evidence=evidence, observed_unix=now,
            )
        attempts[entity_id] = {"ts": now, "outcome": "ok", "name_source": "active_gatt", "result": result}
    else:
        attempts[entity_id] = {"ts": now, "outcome": "fail", "error": result.get("error")}
    _save_attempts(conn, attempts)


class GattProber:
    """Background task that periodically probes BLE entities."""

    def __init__(self, db_path: Path | str, adapter: str | None = "hci0",
                 enabled_check=lambda: False,
                 pause_scanner_factory=None) -> None:
        self._db = Path(db_path)
        self._adapter = adapter
        self._enabled_check = enabled_check
        self._pause_factory = pause_scanner_factory
        self._stopping = False
        self._sema = asyncio.Semaphore(1)  # one probe in flight at a time

    async def run(self, stop: asyncio.Event) -> None:
        """Main loop. Wakes up every 60s; if enabled, picks next candidate and probes."""
        log.info("gatt_prober: started (initially %s)",
                 "enabled" if self._enabled_check() else "disabled")
        while not stop.is_set() and not self._stopping:
            try:
                if self._enabled_check():
                    await self._tick()
            except Exception:  # noqa: BLE001
                log.exception("gatt_prober: tick error")
            try:
                await asyncio.wait_for(stop.wait(), timeout=60.0)
            except asyncio.TimeoutError:
                pass

    async def _tick(self) -> None:
        with get_connection(self._db) as conn:
            candidates = _candidate_entities(conn, max_n=3)
        if not candidates:
            return
        for entity_id, mac, _ in candidates:
            if self._stopping:
                break
            async with self._sema:
                log.info("gatt_prober: probing %s (%s)", mac, entity_id)
                result = await probe_one(mac, adapter=self._adapter, pause_scanner=self._pause_factory)
                with get_connection(self._db) as conn:
                    _apply_probe_result(conn, entity_id, result)
                if result["ok"]:
                    log.info("gatt_prober: ✓ %s → %s", mac,
                             result.get("name") or result.get("model") or result.get("mfr"))
                else:
                    log.debug("gatt_prober: × %s (%s)", mac, result.get("error", "unknown"))
                # Small spacing to be polite to neighboring radios.
                await asyncio.sleep(1.5)
