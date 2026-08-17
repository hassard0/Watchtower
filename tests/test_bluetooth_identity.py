from watchtower.bluetooth_identity import ingest_bluez_devices, parse_device_info
from watchtower.storage.db import get_connection, init_db


def test_parse_and_ingest_bluez_paired_alias(tmp_path):
    text = """
Device AA:BB:CC:DD:EE:FF (public)
        Name: QuietComfort 45
        Alias: Sam's Headphones
        Paired: yes
        Bonded: yes
        Trusted: yes
        RSSI: -41
        UUID: Audio Sink (0000110b-0000-1000-8000-00805f9b34fb)
"""
    device = parse_device_info(text)
    assert device["paired"] is True
    assert device["name"] == "QuietComfort 45"
    db = tmp_path / "watchtower.db"
    init_db(db)
    assert ingest_bluez_devices(db, [device]) == 1
    with get_connection(db) as conn:
        row = conn.execute("SELECT friendly_name,friendly_name_source FROM entities").fetchone()
    assert row == ("Sam's Headphones", "bluez_paired_alias")
