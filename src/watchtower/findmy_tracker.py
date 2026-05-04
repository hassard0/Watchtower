"""OpenHaystack-style Find-My tracker mode.

Broadcasts a Find-My-compatible BLE advertisement using a self-generated
EC P-224 key pair. Real Apple iPhones nearby will see the broadcast,
encrypt their current location with our public key, and upload that
encrypted location report to Apple's servers — exactly what they do for
genuine AirTags.

What this gives us:
- A way to verify "is my Pi visible to Apple's crowdsourced network"
- Demonstrates the Find-My protocol the Pi can already detect
- Provides a tracker key that the user can register in OpenHaystack tooling
  on macOS to actually retrieve the location reports (so the Pi works as a
  $0 anti-theft tracker for high-value items)

What this does NOT do:
- Identify the iPhones reporting our location (they're anonymous to Apple
  and to us)
- Retrieve location reports — needs Apple ID + Apple's anisette protocol;
  OpenHaystack on macOS handles this; we just provide the key.

Reference: https://github.com/seemoo-lab/openhaystack
The advertisement format below is the same one OpenHaystack uses.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import shutil
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from watchtower.storage.db import get_connection

log = logging.getLogger(__name__)


# ---- Key pair generation + persistence ------------------------------------

def _key_path(db_path: Path | str) -> Path:
    """Sit beside the SQLite DB so backup tooling sweeps it up too."""
    return Path(db_path).parent / "findmy_tracker.key.pem"


def _ensure_keypair(db_path: Path | str) -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    """Load the persistent EC P-224 key, generating one on first run.

    Returns (private_key, public_key_x_28_bytes).
    """
    p = _key_path(db_path)
    if p.exists():
        try:
            with open(p, "rb") as f:
                priv = serialization.load_pem_private_key(f.read(), password=None)
        except Exception:  # noqa: BLE001
            log.exception("findmy: failed to load existing key, generating new")
            priv = None  # type: ignore[assignment]
    else:
        priv = None  # type: ignore[assignment]
    if priv is None:
        priv = ec.generate_private_key(ec.SECP224R1())
        with open(p, "wb") as f:
            f.write(priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        try:
            p.chmod(0o600)
        except OSError:
            pass
        log.info("findmy: generated new EC P-224 tracker key at %s", p)

    pub_x = priv.public_key().public_numbers().x.to_bytes(28, "big")
    return priv, pub_x


# ---- Apple Find-My BLE advertisement encoding -----------------------------

def encode_findmy_advertisement(public_key_x_28: bytes,
                                 status_byte: int = 0x00) -> tuple[bytes, str]:
    """Build the 30-byte manufacturer-data payload (incl. 0x4C00 vendor prefix)
    and the derived BLE MAC address that Apple's spec requires.

    Returns (mfr_data_bytes, derived_mac_string).
    """
    if len(public_key_x_28) != 28:
        raise ValueError("public key x-coord must be 28 bytes")

    # Apple Find-My adv format (subtype 0x12 = Find-My, 0x19 = length 25 bytes payload):
    #   byte 0:    status flags (0x00 maintained, 0x04 separated, etc.)
    #   bytes 1-22: bytes 6..27 of public key (the lower 22 bytes of x)
    #   byte 23:    high 2 bits of pub-key byte 0 + padding
    #   byte 24:    hint (0x00 = unowned)
    payload = bytearray(25)
    payload[0] = status_byte
    payload[1:23] = public_key_x_28[6:28]  # bytes 6-27 → 22 bytes
    payload[23] = (public_key_x_28[0] >> 6) & 0x03  # top 2 bits of byte 0
    payload[24] = 0x00

    # Manufacturer data = vendor 0x004C (LE) + subtype 0x12 + length 0x19 + payload
    mfr_data = bytes([0x4C, 0x00, 0x12, 0x19]) + bytes(payload)

    # Derive BLE MAC from public key.
    # Top 2 bits of MAC byte 0 must be 0b11 (Apple "random static address").
    # Remaining 46 bits = bits 0..45 of public key x (top 6 bytes, top-aligned).
    mac_bytes = bytearray(public_key_x_28[:6])
    mac_bytes[0] = (mac_bytes[0] & 0x3F) | 0xC0
    mac = ":".join(f"{b:02X}" for b in mac_bytes)
    return mfr_data, mac


# ---- BlueZ broadcast plumbing --------------------------------------------

async def _bluetoothctl(commands: list[str], timeout: float = 8.0) -> tuple[bool, str]:
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
            timeout=timeout,
        )
        return proc.returncode == 0, stdout.decode("utf-8", errors="replace")
    except asyncio.TimeoutError:
        return False, "timed out"
    except Exception as e:  # noqa: BLE001
        return False, str(e)


async def start_findmy_broadcast(mfr_data: bytes) -> bool:
    """Start advertising the Find-My payload via bluetoothctl."""
    hex_str = mfr_data.hex()
    # Format expected by bluetoothctl: each byte a separate space-separated argument.
    spaced = " ".join(f"0x{hex_str[i:i+2]}" for i in range(0, len(hex_str), 2))
    ok, out = await _bluetoothctl([
        # Apple manufacturer data is the entire payload from byte 2 onward
        # (the vendor ID is set separately).
        # bluetoothctl expects: set-advertise-mfg-data <vendor-le-hex> <data...>
        f"set-advertise-mfg-data 0x004C {' '.join('0x'+hex_str[4:][i:i+2] for i in range(0, len(hex_str)-4, 2))}",
        "advertise on",
    ])
    if not ok:
        log.warning("findmy: failed to set up broadcast: %s", out[:300])
    return ok


async def stop_findmy_broadcast() -> bool:
    ok, _ = await _bluetoothctl([
        "set-advertise-mfg-data",
        "advertise off",
    ])
    return ok


# ---- Long-running broadcaster --------------------------------------------

class FindMyTracker:
    """Background task: when settings.findmy_tracker_enabled is True, broadcast
    the Find-My-compatible advertisement using our persistent key pair.

    Only one of {honeypot, findmy_tracker} can broadcast at a time on the same
    adapter — both use bluetoothctl's advertise channel. This class checks
    settings.honeypot_enabled and yields when the honeypot is active.
    """

    def __init__(self, db_path: Path | str, enabled_check, honeypot_check) -> None:
        self._db = Path(db_path)
        self._enabled_check = enabled_check
        self._honeypot_check = honeypot_check
        self._stopping = False
        self._was_active = False
        self._priv: ec.EllipticCurvePrivateKey | None = None
        self._pub_x: bytes | None = None
        self._mac: str | None = None

    def get_status(self) -> dict:
        """Snapshot for the API/dashboard."""
        if self._priv is None:
            return {"key_present": False}
        priv_pem = self._priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        pub_b64 = base64.b64encode(self._pub_x or b"").decode("ascii")
        return {
            "key_present": True,
            "ble_mac": self._mac,
            "public_key_b64": pub_b64,  # for OpenHaystack registration
            "private_key_pem": priv_pem,  # ⚠️ keep secret; user owns this
            "active": self._was_active,
        }

    async def run(self, stop: asyncio.Event) -> None:
        # Generate / load the key pair eagerly.
        try:
            self._priv, self._pub_x = _ensure_keypair(self._db)
            mfr_data, self._mac = encode_findmy_advertisement(self._pub_x)
        except Exception:  # noqa: BLE001
            log.exception("findmy: keypair init failed; tracker disabled")
            return
        log.info("findmy: tracker key loaded; BLE MAC = %s", self._mac)

        while not stop.is_set() and not self._stopping:
            try:
                want_active = self._enabled_check()
                # Yield to the honeypot if both enabled — they share the adapter.
                if self._honeypot_check():
                    want_active = False

                if want_active and not self._was_active:
                    if await start_findmy_broadcast(mfr_data):
                        log.info("findmy: broadcasting as Find-My tracker (mac=%s)", self._mac)
                        self._was_active = True
                if (not want_active) and self._was_active:
                    await stop_findmy_broadcast()
                    self._was_active = False

                # Persist current state for the API.
                with get_connection(self._db) as conn:
                    conn.execute(
                        "INSERT INTO analytics_state(key, value, updated_unix) "
                        "VALUES('findmy_tracker_state', ?, ?) "
                        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_unix = excluded.updated_unix",
                        (json.dumps({
                            "active": self._was_active,
                            "ble_mac": self._mac,
                            "set_at_unix": int(time.time()),
                        }), int(time.time())),
                    )
            except Exception:  # noqa: BLE001
                log.exception("findmy: tick error")
            try:
                await asyncio.wait_for(stop.wait(), timeout=30.0)
            except asyncio.TimeoutError:
                pass

        if self._was_active:
            await stop_findmy_broadcast()
            self._was_active = False
