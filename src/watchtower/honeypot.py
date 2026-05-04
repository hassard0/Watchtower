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

# Curated lure name catalog. Mix of vehicle / smart-lock / high-value-electronic
# / recon-tool / IoT-exposed / stolen-device patterns. Names DON'T match any
# specific user device or location to avoid creating an attractive nuisance
# pointing at the real property.
LURE_CATALOG: list[tuple[str, str]] = [
    # (advertising name, category — used in dashboard labels)
    ("Tesla-Model-S-RKE-7842",                     "vehicle"),
    ("BMW-ComfortAccess-9E2A",                     "vehicle"),
    ("MercedesMe-CONN-3F1B",                       "vehicle"),
    ("KIA-AccessKey-AC03",                         "vehicle"),
    ("Yale-AssureBT-1A8C",                         "smart-lock"),
    ("August-Smart-Lock-Pro-V4",                   "smart-lock"),
    ("Schlage-Encode-Plus",                        "smart-lock"),
    ("Igloohome-Padlock-92F0",                     "smart-lock"),
    ("Apple-Watch-Ultra-Susan",                    "high-value"),
    ("Beats-Studio-Pro",                           "high-value"),
    ("Sonos-Roam-Bedroom",                         "high-value"),
    ("DJI-Mavic-Pro-3",                            "high-value"),
    ("Nest-Cam-IQ-Indoor-2C8B",                    "iot-exposed"),
    ("Ring-Doorbell-Pro-90AF",                     "iot-exposed"),
    ("EZVIZ-Smart-Cam-Default",                    "iot-exposed"),
    ("EXPOSED-PROD-DEBUG-DO-NOT-USE",              "recon-bait"),
    ("FBI-SURVEILLANCE-VAN-5",                     "recon-bait"),
    ("pi-cam-streaming-default-pwd",               "recon-bait"),
    ("AirTag-Stolen-Bike",                         "recon-bait"),
    ("ChargePoint-EV-Station-7",                   "vehicle"),
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
    """Persist a honeypot engagement (someone tried to connect / read)."""
    now = int(time.time())
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
                "Someone scanned-or-connected to a honeypot lure that the Pi "
                "was broadcasting. The Pi is not a Tesla key / lock / etc. — "
                "this is a trap. Their device MAC is now known."
            ),
        }
        conn.execute(
            """INSERT INTO alerts (alert_id, ts_unix, rule_id, severity, entity_id,
                                    score, home_state, evidence_json)
               VALUES (?, ?, 'honeypot_engaged', 'high', ?, 0.85, 'unknown', ?)""",
            (str(ULID()), now, f"ble:mac:{attacker_mac.lower()}", json.dumps(evidence)),
        )


class Honeypot:
    """Background lure broadcaster. Phase 1: rotate alias periodically.

    Phase 2 (TODO): subscribe to BlueZ D-Bus connection events to log
    inbound engagement as honeypot_engaged alerts. Hook in via dbus-fast.
    """

    def __init__(self, db_path: Path | str, enabled_check=lambda: False,
                 rotate_minutes_check=lambda: 30) -> None:
        self._db = Path(db_path)
        self._enabled_check = enabled_check
        self._rotate_minutes_check = rotate_minutes_check
        self._stopping = False
        self._was_enabled = False
        self._current_lure: tuple[str, str] | None = None

    async def run(self, stop: asyncio.Event) -> None:
        log.info("honeypot: started (initially %s)",
                 "enabled" if self._enabled_check() else "disabled")
        last_rotate_at = 0.0
        while not stop.is_set() and not self._stopping:
            try:
                enabled = self._enabled_check()
                if enabled and not self._was_enabled:
                    # Just became enabled — set initial lure.
                    last_rotate_at = 0.0
                if (not enabled) and self._was_enabled:
                    # Just became disabled — clear.
                    await clear_lure()
                    self._current_lure = None
                self._was_enabled = enabled

                if enabled:
                    rotate_secs = max(60, int(self._rotate_minutes_check() * 60))
                    now = time.monotonic()
                    if (now - last_rotate_at) >= rotate_secs:
                        # Pick something different from the current lure.
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
            except Exception:  # noqa: BLE001
                log.exception("honeypot: tick error")
            try:
                await asyncio.wait_for(stop.wait(), timeout=30.0)
            except asyncio.TimeoutError:
                pass
        # On shutdown: clear lure if we set one.
        if self._current_lure is not None:
            await clear_lure()
            self._current_lure = None
