import json
from pathlib import Path

from watchtower.intrusion import ble_presence_signature, process_signal_batch
from watchtower.storage.db import get_connection, init_db


def _row(event_id: str, ts: int, scanner: str, kind: str, features: dict) -> tuple:
    return (
        event_id, "2026-08-16T00:00:00Z", ts, scanner, kind,
        json.dumps(features), "{}",
    )


def _apple(mac: str, rssi: int = -60, payload: str = "4c00160400112233") -> dict:
    return {
        "mac": mac, "address_type": "random", "is_random_mac": True,
        "rssi": rssi, "tx_power": -8, "service_uuids": [],
        "service_data_hex": {}, "manufacturer_data_hex": payload,
        "decoded": {"apple_continuity": {"subtype": "airpods-connected"}},
    }


def test_signature_ignores_rotating_apple_payload_bytes():
    left = ble_presence_signature(_apple("40:00:00:00:00:01", payload="4c00160400112233"))
    right = ble_presence_signature(_apple("70:00:00:00:00:02", payload="4c001604ffeeddcc"))
    assert left and right
    assert left[0] == right[0]
    assert "not a permanent device identity" in left[2]["limitation"]


def test_signature_rejects_public_and_featureless_random_packets():
    public = _apple("d0:03:4b:00:00:01")
    public["address_type"] = "public"
    assert ble_presence_signature(public) is None
    assert ble_presence_signature({
        "mac": "40:00:00:00:00:01", "address_type": "random",
    }) is None


def test_rotated_addresses_join_one_short_lived_tracklet(tmp_path: Path):
    db = tmp_path / "watchtower.db"
    init_db(db)
    first = [_row(f"a-{i}", 100 + i, "ble_scanner", "ble_adv",
                  _apple("40:00:00:00:00:01", -62 + i)) for i in range(3)]
    second = [_row(f"b-{i}", 125 + i, "ble_scanner", "ble_adv",
                   _apple("70:00:00:00:00:02", -59 + i)) for i in range(3)]
    with get_connection(db) as conn:
        process_signal_batch(conn, first, now=103)
        process_signal_batch(conn, second, now=128)
        tracks = conn.execute(
            "SELECT observation_count,address_count,state FROM presence_tracklets"
        ).fetchall()
    assert tracks == [(6, 2, "active")]


def test_overlapping_addresses_do_not_merge(tmp_path: Path):
    db = tmp_path / "watchtower.db"
    init_db(db)
    with get_connection(db) as conn:
        process_signal_batch(conn, [
            _row("a", 100, "ble_scanner", "ble_adv", _apple("40:00:00:00:00:01")),
            _row("a2", 106, "ble_scanner", "ble_adv", _apple("40:00:00:00:00:01")),
            _row("b", 105, "ble_scanner", "ble_adv", _apple("70:00:00:00:00:02")),
        ], now=106)
        count = conn.execute("SELECT COUNT(*) FROM presence_tracklets").fetchone()[0]
    assert count == 2


def test_two_independent_signal_families_create_explainable_away_alert(tmp_path: Path):
    db = tmp_path / "watchtower.db"
    init_db(db)
    with get_connection(db) as conn:
        conn.execute(
            """INSERT INTO entities
                   (entity_id,scanner,kind,first_seen_unix,last_seen_unix,classification)
               VALUES ('ble:mac:00:11:22:33:44:55','ble_scanner','ble_device',1,1,'anchor')"""
        )
        base = 43200
        rows = [
            _row(f"ble-{i}", base + i * 5, "ble_scanner", "ble_adv",
                 _apple("40:00:00:00:00:01", -58 + i))
            for i in range(3)
        ]
        rows.append(_row(
            "rf-1", base + 12, "subghz_scanner", "keyfob_emission",
            {"protocol": "Honda-CarRemote", "decoded": {"id": "0x123"}},
        ))
        alerts = process_signal_batch(conn, rows, now=base + 15)
        stored = conn.execute(
            "SELECT rule_id,severity,home_state,evidence_json FROM alerts"
        ).fetchone()
        episode = conn.execute(
            "SELECT status,score FROM intrusion_episodes"
        ).fetchone()
    assert len(alerts) == 1
    assert stored[:3] == ("multi_signal_intrusion", "high", "away")
    evidence = json.loads(stored[3])
    assert evidence["independent_families"] == ["ble", "subghz"]
    assert episode == ("alerted", 70)


def test_same_signals_only_observe_while_anchor_is_home(tmp_path: Path):
    db = tmp_path / "watchtower.db"
    init_db(db)
    with get_connection(db) as conn:
        conn.execute(
            """INSERT INTO entities
                   (entity_id,scanner,kind,first_seen_unix,last_seen_unix,classification)
               VALUES ('ble:mac:00:11:22:33:44:55','ble_scanner','ble_device',1,43210,'anchor')"""
        )
        base = 43200
        rows = [
            _row(f"ble-{i}", base + i * 5, "ble_scanner", "ble_adv",
                 _apple("40:00:00:00:00:01", -58 + i))
            for i in range(3)
        ]
        rows.append(_row(
            "rf-1", base + 12, "subghz_scanner", "garage_emission",
            {"protocol": "Genie-OverheadDoor", "decoded": {"id": "55"}},
        ))
        alerts = process_signal_batch(conn, rows, now=base + 15)
        episode = conn.execute(
            "SELECT status,score,home_state FROM intrusion_episodes"
        ).fetchone()
    assert alerts == []
    assert episode == ("observing", 55, "home")


def test_ble_symptoms_do_not_stack_or_alert_with_hotspot_alone(tmp_path: Path):
    db = tmp_path / "watchtower.db"
    init_db(db)
    base = 43200
    with get_connection(db) as conn:
        conn.execute(
            """INSERT INTO entities
                   (entity_id,scanner,kind,first_seen_unix,last_seen_unix,classification)
               VALUES ('ble:mac:00:11:22:33:44:55','ble_scanner','ble_device',1,1,'anchor')"""
        )
        ble_rows = [
            _row(f"ble-{i}", base + i * 5, "ble_scanner", "ble_adv",
                 _apple("40:00:00:00:00:01", -72 + i * 5))
            for i in range(4)
        ]
        wifi = {
            "mac": "a6:6a:bb:e6:9f:f5", "local_name": "Visitor hotspot",
            "rssi": -45, "is_random_mac": True,
            "decoded": {"ssid": "Visitor hotspot"},
        }
        wifi_row = _row("wifi-1", base + 16, "wifi_scanner", "wifi_beacon", wifi)
        # The local sink stores raw events before deriving signals.
        conn.execute(
            """INSERT INTO raw_events
                   (event_id,ts,ts_unix,scanner,kind,features_json,raw_json)
               VALUES (?,?,?,?,?,?,?)""",
            wifi_row,
        )
        alerts = process_signal_batch(conn, [*ble_rows, wifi_row], now=base + 20)
        episode = conn.execute(
            "SELECT status,score,evidence_json FROM intrusion_episodes"
        ).fetchone()
    evidence = json.loads(episode[2])
    assert alerts == []
    assert episode[:2] == ("observing", 65)
    assert evidence["family_scores"] == {"ble": 30.0, "wifi": 20.0}
    assert evidence["decisive_signal_types"] == []


def test_repeated_randomized_hotspot_is_not_intrusion_evidence(tmp_path: Path):
    db = tmp_path / "watchtower.db"
    init_db(db)
    base = 43200
    wifi = {
        "mac": "a6:6a:bb:e6:9f:f5", "local_name": "Known local hotspot",
        "rssi": -40, "is_random_mac": True,
        "decoded": {"ssid": "Known local hotspot"},
    }
    old_row = _row("wifi-old", base - 3600, "wifi_scanner", "wifi_beacon", wifi)
    new_row = _row("wifi-new", base, "wifi_scanner", "wifi_beacon", wifi)
    with get_connection(db) as conn:
        conn.executemany(
            """INSERT INTO raw_events
                   (event_id,ts,ts_unix,scanner,kind,features_json,raw_json)
               VALUES (?,?,?,?,?,?,?)""",
            [old_row, new_row],
        )
        process_signal_batch(conn, [new_row], now=base)
        count = conn.execute(
            "SELECT COUNT(*) FROM intrusion_signals WHERE family='wifi'"
        ).fetchone()[0]
    assert count == 0
