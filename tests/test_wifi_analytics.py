import time
from pathlib import Path

from watchtower.analytics import Analytics, _entity_id_for
from watchtower.storage.db import get_connection, init_db


def _wifi_features(ssid: str, *, random: bool = True) -> dict:
    return {
        "mac": "a6:6a:bb:e6:9f:f5",
        "local_name": ssid,
        "rssi": -43,
        "is_random_mac": random,
        "decoded": {"ssid": ssid, "encryption": "WPA2"},
    }


def test_wifi_beacon_uses_bssid_even_when_locally_administered():
    assert _entity_id_for(
        _wifi_features("Visitor hotspot"), "wifi_scanner", "wifi_beacon_seen"
    ) == "wifi:mac:a6:6a:bb:e6:9f:f5"


def test_random_client_probe_uses_scanner_normalized_ssid():
    assert _entity_id_for(
        _wifi_features("Visitor hotspot"), "wifi_scanner", "wifi_probe_request"
    ) == "wifi:ssid:Visitor hotspot"


def test_new_repeated_close_random_hotspot_alerts(tmp_path: Path):
    db = tmp_path / "watchtower.db"
    init_db(db)
    now = int(time.time())
    with get_connection(db) as conn:
        conn.execute(
            """INSERT INTO entities
                   (entity_id,scanner,kind,first_seen_unix,last_seen_unix,
                    total_observations,is_random_mac,avg_rssi,friendly_name)
               VALUES ('wifi:mac:a6:6a:bb:e6:9f:f5','wifi_scanner','wifi_random',
                       ?,?,3,1,-43,'Visitor hotspot')""",
            (now - 45, now - 2),
        )
        Analytics(db)._evaluate_rules(conn)
        alert = conn.execute(
            """SELECT rule_id,severity,entity_id,evidence_json FROM alerts
               WHERE rule_id='rogue_hotspot'"""
        ).fetchone()
    assert alert is not None
    assert alert[:3] == (
        "rogue_hotspot", "medium", "wifi:mac:a6:6a:bb:e6:9f:f5",
    )
    assert '"observation_count": 3' in alert[3]


def test_established_or_recovery_wifi_does_not_alert(tmp_path: Path):
    db = tmp_path / "watchtower.db"
    init_db(db)
    now = int(time.time())
    with get_connection(db) as conn:
        conn.executemany(
            """INSERT INTO entities
                   (entity_id,scanner,kind,first_seen_unix,last_seen_unix,
                    total_observations,is_random_mac,avg_rssi,friendly_name)
               VALUES (?, 'wifi_scanner','wifi_random',?,?,?,1,-40,?)""",
            [
                ("wifi:mac:a6:6a:bb:e6:9f:f5", now - 3600, now - 2, 80, "Established AP"),
                ("wifi:mac:02:11:22:33:44:55", now - 20, now - 1, 3, "Watchtower"),
            ],
        )
        Analytics(db)._evaluate_rules(conn)
        count = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE rule_id='rogue_hotspot'"
        ).fetchone()[0]
    assert count == 0
