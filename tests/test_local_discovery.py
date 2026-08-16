from watchtower.local_discovery import ingest_lan_names, normalize_mdns_instance
from watchtower.storage.db import get_connection, init_db


def test_lan_name_sources_are_scored_and_provenanced(tmp_path):
    db = tmp_path / "watchtower.db"
    init_db(db)
    observations = [
        {"ip": "192.168.1.4", "name": "printer", "source": "reverse_dns"},
        {"ip": "192.168.1.4", "name": "Office LaserJet", "source": "mdns_service_name",
         "service": "_ipp._tcp.local."},
    ]
    assert ingest_lan_names(db, observations, {"192.168.1.4": "aa:bb:cc:dd:ee:ff"}) == 2
    with get_connection(db) as conn:
        row = conn.execute("SELECT friendly_name,friendly_name_source FROM entities").fetchone()
    assert row == ("Office LaserJet", "mdns_service_name")


def test_mdns_host_unifies_addresses_and_removes_serial_prefixes(tmp_path):
    assert normalize_mdns_instance("EA7851293739@Gym") == "Gym"
    assert normalize_mdns_instance("70-35-60-63.1 Gym") == "Gym"
    db = tmp_path / "watchtower.db"
    init_db(db)
    observations = [
        {"ip": "192.168.1.8", "host": "speaker.local", "name": "AABBCCDDEEFF@Kitchen",
         "source": "mdns_service_name"},
        {"ip": "fe80::12", "host": "speaker.local", "name": "Kitchen",
         "source": "mdns_service_name"},
    ]
    ingest_lan_names(db, observations, {})
    with get_connection(db) as conn:
        rows = conn.execute("SELECT entity_id,friendly_name FROM entities").fetchall()
    assert rows == [("lan:host:speaker.local", "Kitchen")]


def test_mdns_host_uses_one_known_mac_for_ipv4_and_ipv6(tmp_path):
    db = tmp_path / "watchtower.db"
    init_db(db)
    observations = [
        {"ip": "192.168.1.8", "host": "speaker.local", "name": "Kitchen",
         "source": "mdns_service_name"},
        {"ip": "fe80::12", "host": "speaker.local", "name": "Kitchen AirPlay",
         "source": "mdns_service_name"},
    ]
    ingest_lan_names(db, observations, {"192.168.1.8": "aa:bb:cc:dd:ee:ff"})
    with get_connection(db) as conn:
        entities = conn.execute("SELECT entity_id FROM entities").fetchall()
    assert entities == [("lan:mac:aa:bb:cc:dd:ee:ff",)]


def test_arp_mac_outranks_airplay_logical_mac_for_same_host(tmp_path):
    db = tmp_path / "watchtower.db"
    init_db(db)
    observations = [
        {"ip": "fe80::12", "host": "studio.local", "name": "Studio",
         "service_mac": "11:22:33:44:55:66", "source": "airplay_display_name"},
        {"ip": "192.168.1.8", "host": "studio.local", "name": "Studio",
         "service_mac": "11:22:33:44:55:66", "source": "airplay_display_name"},
    ]
    ingest_lan_names(db, observations, {"192.168.1.8": "aa:bb:cc:dd:ee:ff"})
    with get_connection(db) as conn:
        entities = conn.execute("SELECT entity_id FROM entities").fetchall()
    assert entities == [("lan:mac:aa:bb:cc:dd:ee:ff",)]


def test_apple_bonjour_name_cross_links_only_an_existing_exact_ble_mac(tmp_path):
    db = tmp_path / "watchtower.db"
    init_db(db)
    with get_connection(db) as conn:
        conn.execute(
            """INSERT INTO entities
                   (entity_id,scanner,kind,first_seen_unix,last_seen_unix)
               VALUES ('ble:mac:7c:3f:93:e7:01:ab','ble_scanner','ble_device',1,1)"""
        )
    observations = [{
        "ip": "192.168.1.20", "host": "Gym.local", "name": "Gym",
        "source": "airplay_display_name", "service": "_airplay._tcp.local.",
        "model": "Apple TV HD", "bluetooth_mac": "7c:3f:93:e7:01:ab",
        "evidence": {"apple_hardware": True},
    }]
    ingest_lan_names(db, observations, {"192.168.1.20": "00:11:22:33:44:55"})
    with get_connection(db) as conn:
        ble = conn.execute(
            "SELECT friendly_name,friendly_name_source FROM entities WHERE entity_id LIKE 'ble:mac:%'"
        ).fetchone()
        lan = conn.execute(
            "SELECT friendly_name,friendly_name_source FROM entities WHERE entity_id LIKE 'lan:mac:%'"
        ).fetchone()
    assert ble == ("Gym", "apple_bonjour_bluetooth_link")
    assert lan == ("Gym", "airplay_display_name")
