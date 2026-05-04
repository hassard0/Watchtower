"""Tests for Event envelope."""
from datetime import datetime, timezone

from watchtower.events import Event, EventKind, Features, Scanner


def test_event_has_ulid_id():
    e = Event(
        scanner=Scanner.BLE,
        kind=EventKind.BLE_ADV,
        features=Features(rssi=-67, mac="aa:bb:cc:dd:ee:ff"),
    )
    assert len(e.event_id) == 26  # ULID canonical length


def test_event_id_is_time_sortable():
    e1 = Event(scanner=Scanner.BLE, kind=EventKind.BLE_ADV, features=Features())
    e2 = Event(scanner=Scanner.BLE, kind=EventKind.BLE_ADV, features=Features())
    assert e1.event_id < e2.event_id


def test_event_to_dict_round_trips():
    e = Event(
        scanner=Scanner.BLE,
        kind=EventKind.BLE_ADV,
        features=Features(rssi=-67, mac="aa:bb:cc:dd:ee:ff", vendor_oui="Apple"),
        raw={"k": "v"},
    )
    d = e.to_dict()
    e2 = Event.from_dict(d)
    assert e2.event_id == e.event_id
    assert e2.scanner == Scanner.BLE
    assert e2.kind == EventKind.BLE_ADV
    assert e2.features.rssi == -67
    assert e2.features.vendor_oui == "Apple"
    assert e2.raw == {"k": "v"}


def test_event_ts_is_utc_iso():
    e = Event(scanner=Scanner.BLE, kind=EventKind.BLE_ADV, features=Features())
    parsed = datetime.fromisoformat(e.ts)
    assert parsed.tzinfo is not None
    assert parsed.tzinfo.utcoffset(None).total_seconds() == 0


def test_event_explicit_ts():
    fixed = datetime(2026, 5, 3, 22, 41, 13, tzinfo=timezone.utc)
    e = Event(scanner=Scanner.BLE, kind=EventKind.BLE_ADV, features=Features(), ts=fixed.isoformat())
    assert e.ts == "2026-05-03T22:41:13+00:00"
