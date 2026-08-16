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
