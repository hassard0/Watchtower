"""Tests for local, provenance-preserving friendly-name resolution."""
from pathlib import Path

from watchtower.name_resolution import (
    candidates_for_entity,
    candidates_from_features,
    clean_name,
    record_name_candidate,
    revalidate_name_candidates,
    set_user_name,
)
from watchtower.storage.db import get_connection, init_db


def _entity(conn, entity_id: str = "ble:mac:aa:bb:cc:dd:ee:ff") -> str:
    conn.execute(
        """INSERT INTO entities
               (entity_id, scanner, kind, first_seen_unix, last_seen_unix)
           VALUES (?, 'ble_scanner', 'ble_unknown', 100, 100)""",
        (entity_id,),
    )
    return entity_id


def test_clean_name_normalizes_and_rejects_opaque_identifiers():
    assert clean_name("  Kitchen\x00   Speaker  ") == "Kitchen Speaker"
    assert clean_name("Unknown") is None
    assert clean_name("aa:bb:cc:dd:ee:ff") is None
    assert clean_name("0x0123456789abcdef") is None
    assert clean_name("112637_8940") is None
    assert clean_name("AL0012A1GP5V04308A") is None
    assert clean_name("SamsungTV2024") == "SamsungTV2024"


def test_stronger_local_evidence_wins(tmp_path: Path):
    db = tmp_path / "names.db"
    init_db(db)
    with get_connection(db) as conn:
        eid = _entity(conn)
        assert record_name_candidate(conn, eid, "HomeNet", "wifi_ssid", observed_unix=100)
        assert record_name_candidate(conn, eid, "Kitchen Speaker", "ble_gatt_device_name",
                                     observed_unix=110)
        row = conn.execute(
            """SELECT friendly_name, friendly_name_source, friendly_name_confidence
               FROM entities WHERE entity_id = ?""", (eid,),
        ).fetchone()
    assert row == ("Kitchen Speaker", "ble_gatt_device_name", 0.96)


def test_user_name_is_never_overwritten_and_can_be_cleared(tmp_path: Path):
    db = tmp_path / "names.db"
    init_db(db)
    with get_connection(db) as conn:
        eid = _entity(conn)
        record_name_candidate(conn, eid, "Advertised speaker", "ble_advertised_name")
        assert set_user_name(conn, eid, "My desk speaker") == "My desk speaker"
        record_name_candidate(conn, eid, "Factory Device Name", "ble_gatt_device_name")
        selected = conn.execute(
            "SELECT friendly_name, friendly_name_source FROM entities WHERE entity_id = ?", (eid,),
        ).fetchone()
        assert selected == ("My desk speaker", "user")

        assert set_user_name(conn, eid, "") is None
        selected = conn.execute(
            "SELECT friendly_name, friendly_name_source FROM entities WHERE entity_id = ?", (eid,),
        ).fetchone()
        assert selected == ("Factory Device Name", "ble_gatt_device_name")


def test_candidate_provenance_is_retained(tmp_path: Path):
    db = tmp_path / "names.db"
    init_db(db)
    with get_connection(db) as conn:
        eid = _entity(conn)
        record_name_candidate(conn, eid, "Lamp", "ble_advertised_name", evidence={"uuid": "fff0"})
        record_name_candidate(conn, eid, "Acme L100", "ble_gatt_model")
        candidates = candidates_for_entity(conn, eid)
    assert [c["source"] for c in candidates] == ["ble_gatt_model", "ble_advertised_name"]
    assert candidates[1]["evidence"] == {"uuid": "fff0"}


def test_feature_extraction_covers_ble_wifi_and_public_signatures():
    ble = candidates_from_features("ble_scanner", {
        "local_name": "Flipper Ian",
        "decoded": {"device_detection": {"device_signature": "flipper_zero"}},
    })
    assert ("Flipper Zero", "signature", {"detector": "ble_signature"}) in ble
    assert any(source == "ble_advertised_name" for _, source, _ in ble)

    wifi = candidates_from_features("wifi_scanner", {
        "local_name": "HomeNet",
        "decoded": {
            "ssid": "HomeNet", "wps_device_name": "Living Room AP",
            "wps_manufacturer": "Acme", "wps_model": "AX10",
        },
    })
    assert ("Living Room AP", "wifi_wps_device_name", {}) in wifi
    assert ("Acme AX10", "wifi_wps_model", {}) in wifi


def test_schema_has_name_provenance(tmp_path: Path):
    db = tmp_path / "names.db"
    init_db(db)
    with get_connection(db) as conn:
        entity_columns = {row[1] for row in conn.execute("PRAGMA table_info(entities)")}
        candidate_columns = {row[1] for row in conn.execute("PRAGMA table_info(entity_name_candidates)")}
    assert {"friendly_name_source", "friendly_name_confidence",
            "friendly_name_updated_unix"}.issubset(entity_columns)
    assert {"entity_id", "name", "source", "confidence", "evidence_json"}.issubset(candidate_columns)


def test_revalidation_removes_old_factory_identifiers(tmp_path: Path):
    db = tmp_path / "names.db"
    init_db(db)
    with get_connection(db) as conn:
        eid = _entity(conn)
        conn.execute(
            """INSERT INTO entity_name_candidates
                   (entity_id, name, source, confidence, first_seen_unix, last_seen_unix)
               VALUES (?, 'AL0012A1GP5V04308A', 'legacy', 0.6, 100, 100)""", (eid,),
        )
        conn.execute(
            """UPDATE entities SET friendly_name='AL0012A1GP5V04308A',
                   friendly_name_source='legacy', friendly_name_confidence=0.6
               WHERE entity_id=?""", (eid,),
        )
        assert revalidate_name_candidates(conn) == 1
        selected = conn.execute(
            "SELECT friendly_name, friendly_name_source FROM entities WHERE entity_id=?", (eid,),
        ).fetchone()
    assert selected == (None, None)
