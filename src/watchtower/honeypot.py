"""BLE lure honeypot.

Pi rotates through a curated list of *tantalizing* BLE advertising names
(Tesla key, smart lock, exposed IoT, etc.) on its built-in adapter. Anyone
scanning the area with a recon tool sees Pi as a high-value target. We
DON'T relay or interact with attacker traffic — this is purely a lure.

Optional Phase 2 (best-effort): if BlueZ emits an inbound connection event
on the adapter, we log it as a `honeypot_engaged` alert with the attacker's
RF fingerprint (MAC + RSSI) and the lure that was active at the time.
Phase 2 hooks into BlueZ via D-Bus signal subscription — best-effort only.

Toggle via settings.honeypot_enabled (default OFF). Rotation period via
settings.honeypot_rotate_minutes (default 30).
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
import shutil
import time
from pathlib import Path

from ulid import ULID

from watchtower.events import EventKind
from watchtower.storage.db import get_connection

log = logging.getLogger(__name__)

# Curated lure-name catalog. Names are *plausible everyday devices* — the
# point is to look indistinguishable from a real household so a recon-mode
# scanner sees nothing suspicious. A device labeled "FBI-Surveillance-Van"
# screams trap; "AirPods Pro" or "Tesla Model Y" reads as a normal home.
# Names don't match the user's actual property/devices.
LURE_CATALOG: list[tuple[str, str]] = [
    # (advertising name, category — used in dashboard labels)
    # Vehicles — common modern cars
    ("Tesla Model Y",          "vehicle"),
    ("Tesla Model 3",          "vehicle"),
    ("BMW iX1",                "vehicle"),
    ("Audi e-tron",            "vehicle"),
    ("Mercedes EQS",           "vehicle"),
    ("Honda CR-V",             "vehicle"),
    ("Toyota RAV4 Prime",      "vehicle"),
    # Smart locks — real product names
    ("Yale Assure",            "smart-lock"),
    ("August Lock",            "smart-lock"),
    ("Schlage Encode",         "smart-lock"),
    ("Level Lock",             "smart-lock"),
    # Audio — common headphones/speakers
    ("AirPods Pro",            "audio"),
    ("AirPods Max",            "audio"),
    ("Bose QC45",              "audio"),
    ("Sonos Move",             "audio"),
    ("JBL Flip 6",             "audio"),
    ("Beats Studio",           "audio"),
    ("Marshall Major",         "audio"),
    # IoT — common smart-home hubs
    ("Hue Bridge",             "smart-home"),
    ("Nest Mini",              "smart-home"),
    ("Echo Dot",               "smart-home"),
    ("Chromecast",             "smart-home"),
    # Wearables
    ("Apple Watch",            "wearable"),
    ("Garmin Fenix",           "wearable"),
    ("Fitbit Charge",          "wearable"),
    ("WHOOP 4.0",              "wearable"),
    # Phones / tablets / TVs
    ("iPhone 15 Pro",          "phone"),
    ("Galaxy S24",             "phone"),
    ("iPad Air",               "tablet"),
    ("LG OLED TV",             "tv"),
    ("Samsung Soundbar",       "tv"),
]


def _pick_lure(seed: float | None = None) -> tuple[str, str]:
    """Choose the next lure (deterministic if seeded, random otherwise)."""
    rng = random.Random(seed) if seed is not None else random
    return rng.choice(LURE_CATALOG)


async def _bluetoothctl(commands: list[str]) -> tuple[bool, str]:
    """Run a sequence of bluetoothctl commands; return (ok, combined_output)."""
    if not shutil.which("bluetoothctl"):
        return False, "bluetoothctl not installed"
    try:
        proc = await asyncio.create_subprocess_exec(
            "bluetoothctl",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        cmd_block = "\n".join(commands) + "\nquit\n"
        stdout, _ = await asyncio.wait_for(
            proc.communicate(cmd_block.encode("utf-8")),
            timeout=10.0,
        )
        return proc.returncode == 0, stdout.decode("utf-8", errors="replace")
    except asyncio.TimeoutError:
        return False, "timed out"
    except Exception as e:  # noqa: BLE001
        return False, str(e)


async def set_lure(name: str) -> bool:
    """Set the BLE adapter alias to a lure name and start advertising it."""
    # bluetoothctl supports `system-alias` to set the friendly name shown in
    # advertisements without modifying the underlying device name. We use that
    # so unsetting the lure (set-alias '') restores normal behavior.
    ok, out = await _bluetoothctl([
        f'system-alias "{name}"',
        "advertise on",
    ])
    if not ok:
        log.warning("honeypot: failed to set lure '%s': %s", name, out[:200])
    return ok


async def clear_lure() -> bool:
    """Reset the alias and stop advertising."""
    ok, _ = await _bluetoothctl([
        "advertise off",
        'system-alias ""',
    ])
    return ok


def _record_lure_change(db_path: Path | str, name: str, category: str) -> None:
    """Persist current lure state to analytics_state for cross-process visibility."""
    with get_connection(db_path) as conn:
        conn.execute(
            "INSERT INTO analytics_state(key, value, updated_unix) "
            "VALUES('honeypot_active_lure', ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_unix = excluded.updated_unix",
            (json.dumps({"name": name, "category": category, "set_at_unix": int(time.time())}),
             int(time.time())),
        )


def _record_engagement(db_path: Path | str, attacker_mac: str, rssi: int | None) -> None:
    """Persist a honeypot engagement (someone connected to our lure) and
    push it to external sinks (ntfy / webhook / MQTT)."""
    now = int(time.time())
    alert_id = str(ULID())
    entity_id = f"ble:mac:{attacker_mac.lower()}"
    with get_connection(db_path) as conn:
        active = conn.execute(
            "SELECT value FROM analytics_state WHERE key = 'honeypot_active_lure'"
        ).fetchone()
        active_lure = json.loads(active[0])["name"] if active and active[0] else "(unknown)"
        evidence = {
            "attacker_mac": attacker_mac,
            "rssi": rssi,
            "active_lure": active_lure,
            "explanation": (
                "A device connected to the BLE lure that the Pi was broadcasting. "
                "The Pi was advertising as a normal-looking household device — this "
                "device tried to interact, which legitimate users in their own home "
                "would not do. Their MAC is now logged."
            ),
        }
        conn.execute(
            """INSERT INTO alerts (alert_id, ts_unix, rule_id, severity, entity_id,
                                    score, home_state, evidence_json)
               VALUES (?, ?, 'honeypot_engaged', 'high', ?, 0.85, 'unknown', ?)""",
            (alert_id, now, entity_id, json.dumps(evidence)),
        )
    # Forward to external dispatchers.
    try:
        from watchtower.analytics import _dispatch_external, load_settings
        _dispatch_external(load_settings(db_path), {
            "alert_id": alert_id, "ts_unix": now, "rule_id": "honeypot_engaged",
            "severity": "high", "entity_id": entity_id, "score": 0.85,
            "home_state": "unknown", "evidence": evidence,
        })
    except Exception:  # noqa: BLE001
        log.exception("honeypot: external dispatch failed")


async def _connected_macs() -> set[str]:
    """Return MACs currently connected to the BlueZ adapter.

    Parses `bluetoothctl devices Connected` (BlueZ 5.65+).
    """
    if not shutil.which("bluetoothctl"):
        return set()
    try:
        proc = await asyncio.create_subprocess_exec(
            "bluetoothctl", "devices", "Connected",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5.0)
    except (asyncio.TimeoutError, Exception):  # noqa: BLE001
        return set()
    out: set[str] = set()
    for line in stdout.decode("utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "Device":
            out.add(parts[1].lower())
    return out


class Honeypot:
    """Background lure broadcaster + inbound-connection logger.

    Phase 1: rotate the BLE adapter alias through tantalizing-but-plausible
    everyday-device names so the Pi looks like a normal household.
    Phase 2: poll `bluetoothctl devices Connected` every 2 sec; new MACs not
    initiated by our own GATT prober → log `honeypot_engaged` alert with
    attacker's MAC + most-recent RSSI + currently active lure.
    """

    # Class-level set of MACs we initiated outbound connects to recently.
    # Updated by active_probe.GattProber via Honeypot.mark_outgoing().
    _our_outgoing: dict[str, float] = {}

    @classmethod
    def mark_outgoing(cls, mac: str) -> None:
        """Called when our prober initiates a connection so we don't flag it."""
        cls._our_outgoing[mac.lower()] = time.time()
        # GC anything older than 30s
        cutoff = time.time() - 30
        for k in [k for k, v in cls._our_outgoing.items() if v < cutoff]:
            cls._our_outgoing.pop(k, None)

    @classmethod
    def _was_our_outgoing(cls, mac: str) -> bool:
        return mac.lower() in cls._our_outgoing

    def __init__(self, db_path: Path | str, enabled_check=lambda: False,
                 rotate_minutes_check=lambda: 30) -> None:
        self._db = Path(db_path)
        self._enabled_check = enabled_check
        self._rotate_minutes_check = rotate_minutes_check
        self._stopping = False
        self._was_enabled = False
        self._current_lure: tuple[str, str] | None = None
        self._last_connected: set[str] = set()

    async def run(self, stop: asyncio.Event) -> None:
        log.info("honeypot: started (initially %s)",
                 "enabled" if self._enabled_check() else "disabled")
        last_rotate_at = 0.0
        last_conn_check = 0.0
        while not stop.is_set() and not self._stopping:
            try:
                enabled = self._enabled_check()
                if enabled and not self._was_enabled:
                    last_rotate_at = 0.0
                if (not enabled) and self._was_enabled:
                    await clear_lure()
                    self._current_lure = None
                    self._last_connected = set()
                self._was_enabled = enabled

                if enabled:
                    rotate_secs = max(60, int(self._rotate_minutes_check() * 60))
                    now = time.monotonic()
                    if (now - last_rotate_at) >= rotate_secs:
                        candidate = _pick_lure()
                        if self._current_lure is not None:
                            tries = 0
                            while candidate == self._current_lure and tries < 5:
                                candidate = _pick_lure()
                                tries += 1
                        name, category = candidate
                        if await set_lure(name):
                            self._current_lure = candidate
                            _record_lure_change(self._db, name, category)
                            log.info("honeypot: now broadcasting as '%s' (%s)", name, category)
                            last_rotate_at = now

                    # Phase 2: connection watcher.
                    if (now - last_conn_check) >= 2.0:
                        await self._check_connections()
                        last_conn_check = now
            except Exception:  # noqa: BLE001
                log.exception("honeypot: tick error")
            # Tighter loop when enabled (for connection polling); slower when not.
            timeout = 2.0 if self._enabled_check() else 30.0
            try:
                await asyncio.wait_for(stop.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                pass
        if self._current_lure is not None:
            await clear_lure()
            self._current_lure = None

    async def _check_connections(self) -> None:
        current = await _connected_macs()
        new_macs = current - self._last_connected
        for mac in new_macs:
            if self._was_our_outgoing(mac):
                continue  # We initiated; this is the GATT prober.
            # Look up most-recent RSSI from raw_events for this MAC.
            rssi = self._lookup_recent_rssi(mac)
            log.warning("honeypot: 🪤 ENGAGED — %s connected to lure (rssi=%s)", mac, rssi)
            _record_engagement(self._db, mac, rssi)
        self._last_connected = current

    def _lookup_recent_rssi(self, mac: str) -> int | None:
        try:
            with get_connection(self._db) as conn:
                row = conn.execute(
                    """SELECT CAST(json_extract(features_json,'$.rssi') AS INTEGER)
                       FROM raw_events
                       WHERE scanner='ble_scanner'
                         AND lower(json_extract(features_json,'$.mac')) = ?
                         AND ts_unix > strftime('%s','now') - 300
                       ORDER BY ts_unix DESC LIMIT 1""",
                    (mac.lower(),),
                ).fetchone()
                return int(row[0]) if row and row[0] is not None else None
        except Exception:  # noqa: BLE001
            return None
