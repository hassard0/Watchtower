from pathlib import Path

from watchtower.findmy_clusters import process_location_tracker_event
from watchtower.storage.db import get_connection, init_db


def test_tracker_clusters_keep_protocol_families_separate(tmp_path: Path):
    db = tmp_path / "trackers.db"
    init_db(db)
    apple = {
        "family": "apple_findmy", "provider": "apple", "status": "separated",
        "near_owner": False, "alert_eligible": True,
    }
    tile = {
        "family": "tile", "provider": "tile", "status": "state-unavailable",
        "near_owner": None, "alert_eligible": True,
    }
    with get_connection(db) as conn:
        apple_id = process_location_tracker_event(conn, "aa:00:00:00:00:01", apple, -55, 1000)
        tile_id = process_location_tracker_event(conn, "aa:00:00:00:00:02", tile, -56, 1001)
        assert apple_id != tile_id
        rows = conn.execute(
            "SELECT tracker_family, network_provider, near_owner FROM findmy_clusters ORDER BY tracker_family"
        ).fetchall()
    assert rows == [("apple_findmy", "apple", 0), ("tile", "tile", None)]


def test_same_family_rotation_handoff_joins_cluster(tmp_path: Path):
    db = tmp_path / "rotation.db"
    init_db(db)
    detection = {
        "family": "dult", "provider": "google", "status": "separated",
        "near_owner": False, "alert_eligible": True,
    }
    with get_connection(db) as conn:
        first = process_location_tracker_event(conn, "aa:00:00:00:00:01", detection, -60, 1000)
        second = process_location_tracker_event(conn, "aa:00:00:00:00:02", detection, -62, 1004)
        rotations = conn.execute(
            "SELECT rotation_count FROM findmy_clusters WHERE cluster_id = ?", (first,)
        ).fetchone()[0]
    assert second == first
    assert rotations == 2
