from __future__ import annotations

import hashlib
import hmac
import json
import os
import time

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from ulid import ULID

from watchtower.analytics import Analytics
from watchtower.name_crypto import (
    KeyVaultError,
    NameKeyVault,
    decrypt_ead,
    decrypt_fast_pair_personalized_name,
    local_name_from_ad,
    parse_secret,
    resolve_rpa,
)
from watchtower.storage.db import get_connection, init_db


def test_bluetooth_ead_official_vector_extracts_local_name():
    key = bytes.fromhex("57A9DA12D12E6E131E20612AD10A6A19")
    iv = bytes.fromhex("46E77AB1EF007A9E")
    encrypted = bytes.fromhex(
        "8D1C976E7A35444076125788C238A58E8BD9CFF0DEFE251A8E7275454C"
    )
    plain = decrypt_ead(encrypted, key, iv)
    assert plain.hex().upper() == "0F0953686F7274204D696E692D42757303190A8C"
    assert local_name_from_ad(plain) == "Short Mini-Bus"


def _fast_pair_packet(name: str, key: bytes, nonce: bytes) -> bytes:
    data = name.encode()
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    cipher = bytearray()
    for index, start in enumerate(range(0, len(data), 16)):
        stream = encryptor.update(bytes([index]) + b"\0" * 7 + nonce)
        cipher.extend(a ^ b for a, b in zip(data[start:start + 16], stream))
    encryptor.finalize()
    signature = hmac.new(key, nonce + cipher, hashlib.sha256).digest()[:8]
    return signature + nonce + cipher


def test_fast_pair_personalized_name_is_authenticated_and_decrypted():
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    packet = _fast_pair_packet("Mara's Pixel Buds", key, bytes.fromhex("0102030405060708"))
    assert decrypt_fast_pair_personalized_name(packet, key) == "Mara's Pixel Buds"
    damaged = packet[:-1] + bytes([packet[-1] ^ 1])
    with pytest.raises(ValueError, match="authentication"):
        decrypt_fast_pair_personalized_name(damaged, key)


def test_vault_encrypts_and_never_lists_secret(tmp_path):
    db = tmp_path / "watchtower.db"
    master = tmp_path / "vault.key"
    init_db(db)
    vault = NameKeyVault(db, master)
    public = vault.add(label="Owned beacon", key_type="ble_ead",
                       secret_hex="11" * 24, scope="AA:BB:CC:DD:EE:FF")
    assert "secret" not in public
    assert "secret" not in vault.list_public()[0]
    with get_connection(db) as conn:
        token = conn.execute("SELECT secret_ciphertext FROM name_decryption_keys").fetchone()[0]
    assert "11" * 24 not in token
    assert vault.enabled("ble_ead")[0].secret == b"\x11" * 24
    if os.name != "nt":
        assert master.stat().st_mode & 0o777 == 0o600


def test_key_lengths_are_strict():
    assert parse_secret("aa:" * 15 + "aa", "fast_pair_account") == b"\xaa" * 16
    with pytest.raises(KeyVaultError):
        parse_secret("aa" * 15, "fast_pair_account")


def test_bluetooth_irk_official_ah_vector_resolves_rpa():
    irk = bytes.fromhex("ec0234a357c8ad05341010a60a397d9b")
    assert resolve_rpa("70:81:94:0d:fb:aa", irk)
    assert not resolve_rpa("70:81:94:0d:fb:ab", irk)


def _insert_ble_event(db, features):
    now = int(time.time())
    with get_connection(db) as conn:
        conn.execute(
            """INSERT INTO raw_events(event_id,ts,ts_unix,scanner,kind,features_json,raw_json)
               VALUES (?,datetime('now'),?,'ble_scanner','ble_adv',?,'{}')""",
            (str(ULID()), now, json.dumps(features)),
        )


def test_analytics_promotes_only_authenticated_ead_name(tmp_path):
    db = tmp_path / "watchtower.db"
    init_db(db)
    vault = NameKeyVault(db, tmp_path / "vault.key")
    vault.add(label="Owned EAD", key_type="ble_ead",
              secret_hex="57A9DA12D12E6E131E20612AD10A6A1946E77AB1EF007A9E")
    _insert_ble_event(db, {
        "mac": "00:11:22:33:44:55", "is_random_mac": False,
        "encrypted_ad_data_hex": ["8D1C976E7A35444076125788C238A58E8BD9CFF0DEFE251A8E7275454C"],
    })
    analytics = Analytics(db)
    analytics._name_vault = vault
    assert analytics.step()["processed"] == 1
    with get_connection(db) as conn:
        row = conn.execute("SELECT friendly_name,friendly_name_source FROM entities").fetchone()
    assert row == ("Short Mini-Bus", "ble_ead_local_name")


def test_analytics_resolves_owned_rpa_to_stable_irk_entity(tmp_path):
    db = tmp_path / "watchtower.db"
    init_db(db)
    vault = NameKeyVault(db, tmp_path / "vault.key")
    public = vault.add(label="My Sensor", key_type="ble_irk",
                       secret_hex="ec0234a357c8ad05341010a60a397d9b")
    _insert_ble_event(db, {"mac": "70:81:94:0d:fb:aa", "is_random_mac": True})
    analytics = Analytics(db)
    analytics._name_vault = vault
    analytics.step()
    with get_connection(db) as conn:
        row = conn.execute("SELECT entity_id,friendly_name,friendly_name_source FROM entities").fetchone()
    assert row == (f"ble:irk:{public['key_id']}", "My Sensor", "ble_irk_identity")
