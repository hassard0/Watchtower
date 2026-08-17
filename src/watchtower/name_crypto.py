"""Authorized, local-only device-name decryption and key storage.

Only keys explicitly imported by the user or obtained from a device they
pair are accepted.  There is deliberately no key guessing or brute force.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from ulid import ULID

from watchtower.storage.db import get_connection

KEY_LENGTHS = {"ble_ead": 24, "fast_pair_account": 16, "ble_irk": 16}
_HEX = re.compile(r"^[0-9a-fA-F]+$")


class KeyVaultError(ValueError):
    pass


def parse_secret(value: str, key_type: str) -> bytes:
    """Validate a hex key without silently padding, truncating, or guessing."""
    expected = KEY_LENGTHS.get(key_type)
    if expected is None:
        raise KeyVaultError("Unsupported key type")
    compact = re.sub(r"[\s:-]", "", str(value or ""))
    if len(compact) != expected * 2 or not _HEX.fullmatch(compact):
        raise KeyVaultError(f"{key_type} requires exactly {expected} bytes of hexadecimal data")
    return bytes.fromhex(compact)


def parse_ad_structures(payload: bytes) -> list[tuple[int, bytes]]:
    """Parse the standard length/type/value structures inside advertising data."""
    out: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(payload):
        length = payload[offset]
        offset += 1
        if length == 0:
            break
        end = offset + length
        if end > len(payload) or length < 1:
            raise ValueError("Malformed advertising-data structure")
        out.append((payload[offset], payload[offset + 1:end]))
        offset = end
    return out


def local_name_from_ad(payload: bytes) -> str | None:
    """Return Complete Local Name (preferred) or Shortened Local Name."""
    names: dict[int, str] = {}
    for ad_type, value in parse_ad_structures(payload):
        if ad_type in (0x08, 0x09):
            try:
                names[ad_type] = value.decode("utf-8", "strict")
            except UnicodeDecodeError:
                continue
    return names.get(0x09) or names.get(0x08)


def decrypt_ead(encrypted_ad_data: bytes, session_key: bytes, iv: bytes) -> bytes:
    """Decrypt Bluetooth Encrypted Advertising Data (AD type 0x31)."""
    if len(session_key) != 16 or len(iv) != 8:
        raise ValueError("EAD key material must contain a 16-byte session key and 8-byte IV")
    if len(encrypted_ad_data) < 10:  # randomizer(5), >=1 encrypted byte, MIC(4)
        raise ValueError("Encrypted Advertising Data is too short")
    randomizer, ciphertext_and_mic = encrypted_ad_data[:5], encrypted_ad_data[5:]
    nonce = randomizer + iv[::-1]
    return AESCCM(session_key, tag_length=4).decrypt(nonce, ciphertext_and_mic, b"\xea")


def decrypt_fast_pair_personalized_name(packet: bytes, account_key: bytes) -> str:
    """Authenticate and decrypt a Fast Pair Personalized Name packet."""
    if len(account_key) != 16:
        raise ValueError("Fast Pair account key must be 16 bytes")
    if len(packet) < 17:
        raise ValueError("Fast Pair name packet is too short")
    signature, nonce, ciphertext = packet[:8], packet[8:16], packet[16:]
    expected = hmac.new(account_key, nonce + ciphertext, hashlib.sha256).digest()[:8]
    if not hmac.compare_digest(signature, expected):
        raise ValueError("Fast Pair name authentication failed")
    encryptor = Cipher(algorithms.AES(account_key), modes.ECB()).encryptor()
    plain = bytearray()
    for block_index, start in enumerate(range(0, len(ciphertext), 16)):
        if block_index > 255:
            raise ValueError("Fast Pair name packet is too long")
        stream = encryptor.update(bytes([block_index]) + (b"\0" * 7) + nonce)
        block = ciphertext[start:start + 16]
        plain.extend(a ^ b for a, b in zip(block, stream))
    encryptor.finalize()
    return bytes(plain).decode("utf-8", "strict")


def resolve_rpa(address: str, irk: bytes) -> bool:
    """Resolve a Bluetooth Resolvable Private Address with its peer IRK."""
    if len(irk) != 16:
        raise ValueError("IRK must be 16 bytes")
    try:
        raw = bytes.fromhex(address.replace(":", ""))
    except ValueError:
        return False
    if len(raw) != 6:
        return False
    # Bluetooth renders the 48-bit random address as prand || hash.
    prand, address_hash = raw[:3], raw[3:]
    # RPA prand has its two most-significant bits set to 0b01.
    if (prand[0] & 0xC0) != 0x40:
        return False
    encryptor = Cipher(algorithms.AES(irk), modes.ECB()).encryptor()
    encrypted = encryptor.update((b"\0" * 13) + prand) + encryptor.finalize()
    return hmac.compare_digest(encrypted[-3:], address_hash)


@dataclass(frozen=True)
class VaultKey:
    key_id: str
    label: str
    key_type: str
    scope: str
    secret: bytes
    metadata: dict[str, Any]


class NameKeyVault:
    """Fernet-encrypted key records backed by Watchtower's SQLite database."""

    def __init__(self, db_path: Path | str, master_key_path: Path | str | None = None) -> None:
        self.db_path = Path(db_path)
        self.master_key_path = Path(master_key_path or self.db_path.with_name("name-vault.key"))

    def _fernet(self, *, create: bool) -> Fernet:
        if not self.master_key_path.exists():
            if not create:
                raise KeyVaultError("Name-decryption vault has not been initialized")
            self.master_key_path.parent.mkdir(parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            fd = os.open(self.master_key_path, flags, 0o600)
            try:
                os.write(fd, Fernet.generate_key() + b"\n")
            finally:
                os.close(fd)
        try:
            key = self.master_key_path.read_bytes().strip()
            if os.name != "nt":
                os.chmod(self.master_key_path, 0o600)
            return Fernet(key)
        except (OSError, ValueError) as exc:
            raise KeyVaultError("Unable to open the local name-decryption vault") from exc

    def add(self, *, label: str, key_type: str, secret_hex: str, scope: str = "*",
            metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        secret = parse_secret(secret_hex, key_type)
        label = " ".join(str(label or "").split())[:80]
        scope = str(scope or "*").strip()[:160]
        if not label:
            raise KeyVaultError("A key label is required")
        metadata_json = json.dumps(metadata or {}, separators=(",", ":"), sort_keys=True)[:2000]
        key_id = str(ULID())
        token = self._fernet(create=True).encrypt(secret).decode("ascii")
        now = int(time.time())
        with get_connection(self.db_path) as conn:
            conn.execute(
                """INSERT INTO name_decryption_keys
                   (key_id,label,key_type,scope,secret_ciphertext,metadata_json,created_unix,enabled)
                   VALUES (?,?,?,?,?,?,?,1)""",
                (key_id, label, key_type, scope, token, metadata_json, now),
            )
        return {"key_id": key_id, "label": label, "key_type": key_type,
                "scope": scope, "metadata": metadata or {}, "created_unix": now,
                "last_used_unix": None, "enabled": True}

    def list_public(self) -> list[dict[str, Any]]:
        with get_connection(self.db_path) as conn:
            rows = conn.execute(
                """SELECT key_id,label,key_type,scope,metadata_json,created_unix,last_used_unix,enabled
                   FROM name_decryption_keys ORDER BY created_unix DESC"""
            ).fetchall()
        out = []
        for key_id, label, key_type, scope, metadata_json, created, used, enabled in rows:
            try:
                metadata = json.loads(metadata_json or "{}")
            except (TypeError, ValueError):
                metadata = {}
            out.append({"key_id": key_id, "label": label, "key_type": key_type,
                        "scope": scope, "metadata": metadata, "created_unix": created,
                        "last_used_unix": used, "enabled": bool(enabled)})
        return out

    def enabled(self, key_type: str | None = None) -> list[VaultKey]:
        sql = "SELECT key_id,label,key_type,scope,secret_ciphertext,metadata_json FROM name_decryption_keys WHERE enabled=1"
        params: tuple[Any, ...] = ()
        if key_type:
            sql += " AND key_type=?"
            params = (key_type,)
        with get_connection(self.db_path) as conn:
            rows = conn.execute(sql, params).fetchall()
        if not rows:
            return []
        fernet = self._fernet(create=False)
        out = []
        for key_id, label, kind, scope, token, metadata_json in rows:
            try:
                secret = fernet.decrypt(token.encode("ascii"))
                metadata = json.loads(metadata_json or "{}")
            except (InvalidToken, ValueError, TypeError, json.JSONDecodeError):
                continue
            out.append(VaultKey(key_id, label, kind, scope, secret, metadata))
        return out

    def mark_used(self, key_id: str) -> None:
        with get_connection(self.db_path) as conn:
            conn.execute("UPDATE name_decryption_keys SET last_used_unix=? WHERE key_id=?",
                         (int(time.time()), key_id))

    def delete(self, key_id: str) -> bool:
        with get_connection(self.db_path) as conn:
            cur = conn.execute("DELETE FROM name_decryption_keys WHERE key_id=?", (key_id,))
            return cur.rowcount > 0
