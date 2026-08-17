"""BlueZ identity enrichment and authorized Fast Pair/EAD key retrieval."""
from __future__ import annotations

import asyncio
import logging
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from bleak import BleakClient
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from watchtower.name_crypto import VaultKey, decrypt_fast_pair_personalized_name
from watchtower.name_resolution import clean_name, record_name_candidate
from watchtower.storage.db import get_connection

UUID_FAST_PAIR_KEY_PAIRING = "fe2c1234-8366-4814-8eb0-01de32100beA"
UUID_FAST_PAIR_ADDITIONAL_DATA = "fe2c1237-8366-4814-8eb0-01de32100beA"
UUID_EAD_KEY_MATERIAL = "00002b88-0000-1000-8000-00805f9b34fb"
_MAC = re.compile(r"(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b")
log = logging.getLogger(__name__)


def _run_bluetoothctl(args: list[str], timeout: float = 20.0) -> str:
    try:
        cp = subprocess.run(["bluetoothctl", *args], capture_output=True, text=True,
                            timeout=timeout, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"BlueZ bluetoothctl unavailable: {exc}") from exc
    text = (cp.stdout or "") + "\n" + (cp.stderr or "")
    if cp.returncode and not text.strip():
        raise RuntimeError(f"bluetoothctl exited with status {cp.returncode}")
    return text


def parse_device_info(text: str, address: str | None = None) -> dict[str, Any]:
    """Parse stable, human-readable fields from bluetoothctl info output."""
    out: dict[str, Any] = {"address": (address or "").upper(), "uuids": []}
    for raw in text.splitlines():
        line = re.sub(r"\x1b\[[0-9;]*m", "", raw).strip()
        mac_match = _MAC.search(line)
        if line.startswith("Device ") and mac_match:
            out["address"] = mac_match.group(0).upper()
        if ": " not in line:
            continue
        key, value = line.split(": ", 1)
        normalized = key.strip().lower().replace(" ", "_")
        if normalized in {"name", "alias", "icon", "modalias"}:
            out[normalized] = value.strip()
        elif normalized in {"paired", "bonded", "trusted", "connected", "blocked"}:
            out[normalized] = value.strip().lower() == "yes"
        elif normalized == "rssi":
            try:
                out["rssi"] = int(value.split()[0])
            except ValueError:
                pass
        elif normalized == "uuid":
            found = re.search(r"\(([0-9a-f-]{4,36})\)", value, re.IGNORECASE)
            if found:
                out["uuids"].append(found.group(1).lower())
    return out


def list_bluez_devices() -> list[dict[str, Any]]:
    listing = _run_bluetoothctl(["devices"], timeout=5)
    addresses = []
    for line in listing.splitlines():
        match = _MAC.search(line)
        if match and match.group(0).upper() not in addresses:
            addresses.append(match.group(0).upper())
    devices = []
    for address in addresses[:100]:
        try:
            devices.append(parse_device_info(_run_bluetoothctl(["info", address], timeout=5), address))
        except RuntimeError:
            continue
    return devices


def scan_classic(timeout_sec: int = 10) -> list[dict[str, Any]]:
    """Run bounded BR/EDR inquiry; BlueZ performs Remote Name Requests."""
    timeout_sec = max(4, min(30, int(timeout_sec)))
    _run_bluetoothctl(["--timeout", str(timeout_sec), "scan", "bredr"], timeout=timeout_sec + 5)
    return list_bluez_devices()


def pair_device(address: str) -> dict[str, Any]:
    if not _MAC.fullmatch(address or ""):
        raise ValueError("A valid Bluetooth address is required")
    output = _run_bluetoothctl(["--timeout", "30", "pair", address], timeout=35)
    info = parse_device_info(_run_bluetoothctl(["info", address], timeout=5), address)
    if not info.get("paired"):
        tail = " ".join(output.split())[-240:]
        raise RuntimeError(tail or "Pairing failed; confirm pairing mode and try again")
    _run_bluetoothctl(["trust", address], timeout=5)
    return parse_device_info(_run_bluetoothctl(["info", address], timeout=5), address)


def ingest_bluez_devices(db_path: Path | str, devices: list[dict[str, Any]]) -> int:
    now = int(time.time())
    count = 0
    with get_connection(db_path) as conn:
        for device in devices:
            mac = str(device.get("address") or "").lower()
            if not _MAC.fullmatch(mac):
                continue
            eid = f"ble:mac:{mac}"
            conn.execute(
                """INSERT INTO entities
                   (entity_id,scanner,kind,first_seen_unix,last_seen_unix,visit_count,total_observations,is_random_mac,avg_rssi,min_rssi,max_rssi)
                   VALUES (?,'ble_scanner','bluetooth_classic',?,?,0,1,0,?,?,?)
                   ON CONFLICT(entity_id) DO UPDATE SET
                     last_seen_unix=MAX(entities.last_seen_unix,excluded.last_seen_unix),
                     total_observations=entities.total_observations+1,
                     avg_rssi=COALESCE(excluded.avg_rssi,entities.avg_rssi),
                     min_rssi=MIN(COALESCE(entities.min_rssi,excluded.min_rssi),COALESCE(excluded.min_rssi,entities.min_rssi)),
                     max_rssi=MAX(COALESCE(entities.max_rssi,excluded.max_rssi),COALESCE(excluded.max_rssi,entities.max_rssi))""",
                (eid, now, now, device.get("rssi"), device.get("rssi"), device.get("rssi")),
            )
            alias = clean_name(device.get("alias"))
            name = clean_name(device.get("name"))
            evidence = {"address": mac, "paired": bool(device.get("paired")),
                        "trusted": bool(device.get("trusted"))}
            if alias and device.get("paired"):
                record_name_candidate(conn, eid, alias, "bluez_paired_alias", evidence=evidence)
            if name:
                record_name_candidate(conn, eid, name, "bluetooth_remote_name", evidence=evidence)
            count += 1
    return count


async def read_ead_key_material(address: str, adapter: str | None = "hci0") -> bytes | None:
    """Read EAD session key+IV; BlueZ enforces characteristic authorization."""
    async with BleakClient(address, timeout=10, adapter=adapter) as client:
        try:
            value = bytes(await client.read_gatt_char(UUID_EAD_KEY_MATERIAL))
        except Exception as exc:  # noqa: BLE001 - backend errors vary by BlueZ version
            log.debug("EAD key material unavailable for %s: %s", address, exc)
            return None
    return value if len(value) == 24 else None


def _fast_pair_request(address: str, account_key: bytes) -> bytes:
    provider_address = bytes.fromhex(address.replace(":", ""))
    # Raw key-based pairing request: request type, request-existing-name flag,
    # current provider BLE address, and fresh salt.
    raw = b"\x00\x20" + provider_address + os.urandom(8)
    encryptor = Cipher(algorithms.AES(account_key), modes.ECB()).encryptor()
    return encryptor.update(raw) + encryptor.finalize()


async def fetch_fast_pair_name(address: str, keys: list[VaultKey],
                               adapter: str | None = "hci0") -> tuple[str, str]:
    """Ask an owned Fast Pair provider for its authenticated personalized name."""
    account_keys = [key for key in keys if key.key_type == "fast_pair_account"]
    if not account_keys:
        raise ValueError("No enabled Fast Pair account keys are available")
    if not _MAC.fullmatch(address or ""):
        raise ValueError("A valid Bluetooth address is required")
    loop = asyncio.get_running_loop()
    result: asyncio.Future[tuple[str, str]] = loop.create_future()

    def on_name(_sender, data: bytearray) -> None:
        if result.done():
            return
        for key in account_keys:
            try:
                name = clean_name(decrypt_fast_pair_personalized_name(bytes(data), key.secret), max_length=48)
            except (ValueError, UnicodeDecodeError):
                continue
            if name:
                result.set_result((name, key.key_id))
                return

    async with BleakClient(address, timeout=12, adapter=adapter) as client:
        await client.start_notify(UUID_FAST_PAIR_ADDITIONAL_DATA, on_name)
        for key in account_keys:
            try:
                await client.write_gatt_char(UUID_FAST_PAIR_KEY_PAIRING,
                                             _fast_pair_request(address, key.secret), response=True)
                return await asyncio.wait_for(asyncio.shield(result), timeout=7)
            except TimeoutError:
                continue
            except Exception as exc:  # noqa: BLE001 - backend errors vary by BlueZ version
                log.debug("Fast Pair request failed for key %s: %s", key.key_id, exc)
                continue
        if result.done():
            return result.result()
    raise RuntimeError("The device did not return a name for any imported account key")
