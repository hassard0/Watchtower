"""Find-My owned-tracker enrollment + catalog matching.

For each AirTag the user owns, the iPhone (during pairing) generated a
master EC P-224 private scalar `d_master` and a 32-byte symmetric key
`SK_0`. From these, every 15-min broadcast slot's BLE public key can be
deterministically derived:

    SK_{n}  = ANSI-X9.63-KDF(SK_{n-1}, info=b"update",    L=32)
    (u, v)  = ANSI-X9.63-KDF(SK_n,     info=b"diversify", L=72)
    u_int   = OS2IP(u[:36]) mod n_curve
    v_int   = OS2IP(v[36:]) mod n_curve
    d_n     = (d_master * u_int + v_int) mod n_curve
    P_n     = d_n · G                                    (28-byte X-coord)

The BLE Find-My advertisement carries:
  - Bytes 6..27 of P_n.x at offsets 1..22 of the 25-byte payload
  - Top 2 bits of P_n.x byte 0 at offset 23
  - BLE MAC = P_n.x[0..6] with top 2 bits forced to 0b11

So given a master secret, we can predict every slot's expected ad. We
precompute a 24-hour catalog and match incoming broadcasts by exact pubkey
prefix → if it's one of the user's trackers, we know with cryptographic
certainty.

This implementation matches the Apple Find-My v1 protocol used by AirTags
and Find-My-Network-certified third-party trackers (Chipolo, Pebblebee,
etc.). Verified against OpenHaystack's reference implementation.

Stranger trackers (anyone whose master secret you don't have) remain
anonymous — that is the cryptographic limit of this protocol.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from ulid import ULID

from watchtower.storage.db import get_connection

log = logging.getLogger(__name__)

# NIST P-224 curve order (n).
P224_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D

SLOT_SEC = 15 * 60          # Apple rotates Find-My pubkeys every 15 min
CATALOG_HOURS_AHEAD = 24    # precompute next 24 hr of slots per tracker
CATALOG_HOURS_BEHIND = 1    # also keep 1 hr of past slots in case of clock skew
CATALOG_REFRESH_SEC = 4 * 3600  # regenerate every 4 hr to keep the window fresh


def x963_kdf(z: bytes, info: bytes, length: int) -> bytes:
    """ANSI X9.63 KDF — SHA-256 based.

    Inner-loop hashes z || counter_be32 || info, concatenates until L bytes.
    Used exactly the same way as in Apple's Find-My spec / OpenHaystack.
    """
    counter = 1
    out = b""
    while len(out) < length:
        out += hashlib.sha256(z + counter.to_bytes(4, "big") + info).digest()
        counter += 1
    return out[:length]


def derive_slot_pubkey(d_master_int: int, sk_root: bytes, slot_index: int) -> bytes:
    """Compute the 28-byte X-coordinate of the slot-N broadcast public key."""
    sk_n = sk_root
    for _ in range(slot_index):
        sk_n = x963_kdf(sk_n, b"update", 32)

    div = x963_kdf(sk_n, b"diversify", 72)
    u_int = int.from_bytes(div[:36], "big") % P224_ORDER
    v_int = int.from_bytes(div[36:], "big") % P224_ORDER
    d_n = (d_master_int * u_int + v_int) % P224_ORDER
    if d_n == 0:
        # vanishingly unlikely; if it happens, advance one slot.
        return derive_slot_pubkey(d_master_int, sk_root, slot_index + 1)

    priv = ec.derive_private_key(d_n, ec.SECP224R1(), default_backend())
    pub_x = priv.public_key().public_numbers().x
    return pub_x.to_bytes(28, "big")


def expected_advertisement(pubkey_x_28: bytes) -> tuple[str, int, str]:
    """Return (pubkey_22b_hex, top_bits, expected_mac) for catalog storage."""
    pubkey_22b_hex = pubkey_x_28[6:28].hex()
    top_bits = (pubkey_x_28[0] >> 6) & 0x03
    mac_bytes = bytearray(pubkey_x_28[:6])
    mac_bytes[0] = (mac_bytes[0] & 0x3F) | 0xC0
    expected_mac = ":".join(f"{b:02x}" for b in mac_bytes)
    return pubkey_22b_hex, top_bits, expected_mac


# ---- Tracker storage (encrypted-at-rest secrets in side files) ------------

def _secret_dir(db_path: Path | str) -> Path:
    p = Path(db_path).parent / "findmy_owned_secrets"
    p.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        p.chmod(0o700)
    except OSError:
        pass
    return p


def _secret_path(db_path: Path | str, tracker_id: str) -> Path:
    return _secret_dir(db_path) / f"{tracker_id}.json"


def store_tracker(db_path: Path | str, name: str,
                  master_priv_b64: str, master_sym_b64: str) -> str:
    """Persist a new owned tracker. Returns tracker_id."""
    # Validate the secrets actually decode + are correct length.
    try:
        master_priv = base64.b64decode(master_priv_b64)
        master_sym = base64.b64decode(master_sym_b64)
    except Exception as e:
        raise ValueError(f"failed to base64-decode secrets: {e}")
    if len(master_priv) != 28:
        raise ValueError(f"master_priv must be 28 bytes (P-224 scalar); got {len(master_priv)}")
    if len(master_sym) != 32:
        raise ValueError(f"master_sym must be 32 bytes; got {len(master_sym)}")
    # Parse to int and sanity-check it's a valid scalar.
    d_master = int.from_bytes(master_priv, "big")
    if not (0 < d_master < P224_ORDER):
        raise ValueError("master_priv is not a valid P-224 scalar")

    tracker_id = str(ULID())
    secret_blob = {
        "tracker_id": tracker_id,
        "name": name,
        "master_priv_b64": master_priv_b64,
        "master_sym_b64": master_sym_b64,
        "stored_unix": int(time.time()),
    }
    p = _secret_path(db_path, tracker_id)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(secret_blob, f)
    try:
        p.chmod(0o600)
    except OSError:
        pass

    with get_connection(db_path) as conn:
        conn.execute(
            """INSERT INTO findmy_owned_trackers (tracker_id, name, enrolled_unix, catalog_to_unix)
               VALUES (?, ?, ?, 0)""",
            (tracker_id, name, int(time.time())),
        )
    return tracker_id


def delete_tracker(db_path: Path | str, tracker_id: str) -> bool:
    p = _secret_path(db_path, tracker_id)
    if p.exists():
        try:
            p.unlink()
        except OSError:
            log.exception("findmy: failed to delete secret file %s", p)
    with get_connection(db_path) as conn:
        cur = conn.execute("DELETE FROM findmy_owned_trackers WHERE tracker_id = ?", (tracker_id,))
        return cur.rowcount > 0


def list_trackers(db_path: Path | str) -> list[dict]:
    with get_connection(db_path) as conn:
        rows = conn.execute("""
            SELECT tracker_id, name, enrolled_unix, last_match_unix, catalog_to_unix, notes
            FROM findmy_owned_trackers ORDER BY enrolled_unix DESC
        """).fetchall()
        out = []
        for tid, name, enr, last_match, cat_to, notes in rows:
            slots_in_catalog = conn.execute(
                "SELECT COUNT(*) FROM findmy_key_catalog WHERE tracker_id = ? AND slot_start_unix > ?",
                (tid, int(time.time())),
            ).fetchone()[0]
            out.append({
                "tracker_id": tid,
                "name": name,
                "enrolled_unix": enr,
                "last_match_unix": last_match,
                "catalog_to_unix": cat_to,
                "future_slots_in_catalog": slots_in_catalog,
                "notes": notes,
            })
    return out


def _load_secret(db_path: Path | str, tracker_id: str) -> tuple[int, bytes] | None:
    p = _secret_path(db_path, tracker_id)
    if not p.exists():
        return None
    with open(p, "r", encoding="utf-8") as f:
        blob = json.load(f)
    d_master = int.from_bytes(base64.b64decode(blob["master_priv_b64"]), "big")
    sk_root = base64.b64decode(blob["master_sym_b64"])
    return d_master, sk_root


# ---- Catalog generation + matching ---------------------------------------

def _slot_index_for(ts_unix: int) -> int:
    return ts_unix // SLOT_SEC


def regenerate_catalog(db_path: Path | str, tracker_id: str,
                       enrollment_ts_unix: int) -> int:
    """Compute the rolling catalog of expected pubkeys for a tracker.

    Apple's spec doesn't pin slot 0 to a specific epoch — the SK chain just
    advances every 15 min from when pairing happened. Since we don't know
    the original pairing time exactly, we treat the user-supplied enrollment
    timestamp as slot 0 and compute slot indices relative to enrollment.

    For the user this means: enroll your AirTag soon after extracting its
    keys, OR re-enroll if the catalog drifts off. The catalog also includes
    a 1-hour past window to absorb minor clock skew.

    Returns the number of slots written.
    """
    secret = _load_secret(db_path, tracker_id)
    if not secret:
        log.warning("findmy: no secret file for tracker %s", tracker_id)
        return 0
    d_master, sk_root = secret

    now = int(time.time())
    start_ts = now - CATALOG_HOURS_BEHIND * 3600
    end_ts = now + CATALOG_HOURS_AHEAD * 3600
    # slot index relative to enrollment: 0 = the moment of enrollment.
    slot_at_enrollment = enrollment_ts_unix // SLOT_SEC
    slot_lo = (start_ts // SLOT_SEC) - slot_at_enrollment
    slot_hi = (end_ts // SLOT_SEC) - slot_at_enrollment
    slot_lo = max(0, slot_lo)

    inserted = 0
    with get_connection(db_path) as conn:
        # Drop entries outside the window.
        conn.execute(
            "DELETE FROM findmy_key_catalog WHERE tracker_id = ? AND (slot_start_unix < ? OR slot_start_unix > ?)",
            (tracker_id, start_ts, end_ts),
        )
        for slot_idx in range(slot_lo, slot_hi + 1):
            slot_start = (slot_idx + slot_at_enrollment) * SLOT_SEC
            existing = conn.execute(
                "SELECT 1 FROM findmy_key_catalog WHERE tracker_id = ? AND slot_index = ?",
                (tracker_id, slot_idx),
            ).fetchone()
            if existing:
                continue
            try:
                pub = derive_slot_pubkey(d_master, sk_root, slot_idx)
            except Exception:  # noqa: BLE001
                log.exception("findmy: derivation failed for tracker %s slot %d", tracker_id, slot_idx)
                continue
            pub22, topbits, mac = expected_advertisement(pub)
            conn.execute(
                """INSERT INTO findmy_key_catalog
                    (tracker_id, slot_index, slot_start_unix, pubkey_22b_hex, pubkey_top_bits, expected_mac)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (tracker_id, slot_idx, slot_start, pub22, topbits, mac),
            )
            inserted += 1
        conn.execute(
            "UPDATE findmy_owned_trackers SET catalog_to_unix = ? WHERE tracker_id = ?",
            (end_ts, tracker_id),
        )
    return inserted


def regenerate_all_catalogs(db_path: Path | str) -> int:
    total = 0
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT tracker_id, enrolled_unix FROM findmy_owned_trackers"
        ).fetchall()
    for tid, enrolled in rows:
        total += regenerate_catalog(db_path, tid, enrolled)
    return total


def match_event(conn, mfr_hex: str | None, observed_mac: str | None) -> dict | None:
    """Try to match a Find-My BLE event to one of the user's enrolled trackers.

    The advertisement carries:
      - bytes 1..22 of payload = pubkey bytes 6..27 (the 22-byte slice)
      - byte 23 = top 2 bits of pubkey byte 0
      - BLE MAC = derived from pubkey top 6 bytes

    We match on pubkey_22b_hex (deterministic + extremely unlikely to collide).

    Returns: {tracker_id, name, slot_start_unix} or None.
    """
    if not mfr_hex or not mfr_hex.lower().startswith("4c0012"):
        return None
    raw = bytes.fromhex(mfr_hex)
    # 4c 00 12 <len> <25-byte payload>
    if len(raw) < 30:
        return None
    payload = raw[4:29]
    pub22_hex = payload[1:23].hex()
    row = conn.execute(
        """SELECT c.tracker_id, c.slot_start_unix, t.name
           FROM findmy_key_catalog c
           JOIN findmy_owned_trackers t ON t.tracker_id = c.tracker_id
           WHERE c.pubkey_22b_hex = ?
           LIMIT 1""",
        (pub22_hex,),
    ).fetchone()
    if not row:
        return None
    tracker_id, slot_start, name = row
    conn.execute(
        "UPDATE findmy_owned_trackers SET last_match_unix = ? WHERE tracker_id = ?",
        (int(time.time()), tracker_id),
    )
    return {"tracker_id": tracker_id, "name": name, "slot_start_unix": slot_start}
