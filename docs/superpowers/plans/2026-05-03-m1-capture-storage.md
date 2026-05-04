# Watchtower M1 — Foundation + Capture + Storage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the Pi-side capture and storage foundation: 4 RF scanners (BLE, WiFi-stub, sub-GHz, mid-band) emit normalized events through a local message bus into a SQLite store with 7-day retention. No detection logic yet — that's M3.

**Architecture:** Python 3.13 service on Debian 13. `uv` for dependency management. Single long-lived process supervised by systemd. In-process `multiprocessing.Queue` message bus. Each scanner is a coroutine producing `Event` envelopes. A `LocalSink` consumer batches inserts into SQLite. A `Pruner` runs hourly and deletes events older than 7 days. Code is developed on the Windows host and deployed to the Pi via `rsync` over SSH.

**Tech Stack:**
- Python 3.13, `uv` for env/deps
- `bleak` for BLE scanning
- `pyrtlsdr` for RTL-SDR control
- `rtl_433` system tool (subprocess) for sub-GHz protocol decoding
- `python-ulid` for time-sortable event IDs
- `structlog` for JSON logging
- `pytest` for tests
- SQLite via stdlib `sqlite3`
- systemd for service supervision

**Hardware (already present):**
- Pi 5 16GB, Debian 13.4 trixie, kernel 6.12.75 ARM64
- 2× RTL-SDR USB dongles (RTL2832U, USB ID `0bda:2838`)
- Built-in BLE 5.0
- Reachable at `watchtower.local` (192.168.4.180), keyless SSH as `admin`

**Hardware NOT yet present (M1 scopes around this):** USB WiFi adapter (Alfa AWUS036ACS or equiv), Hailo-8L AI HAT, antennas, enclosure. The `wifi` scanner ships as a graceful stub in M1 — emits no events but logs that adapter is absent. It activates automatically when the adapter appears.

---

## File Structure

```
watchtower/
├── pyproject.toml                       # uv project, deps, scripts
├── README.md                            # quickstart
├── .gitignore
├── docs/superpowers/{specs,plans}/      # already exists
├── deploy/
│   ├── pi-setup.sh                      # idempotent Pi system-package install
│   ├── watchtower.service               # systemd unit
│   └── deploy.sh                        # rsync from Windows host to Pi
├── src/watchtower/
│   ├── __init__.py                      # version
│   ├── cli.py                           # `watchtower run`, `watchtower db init`
│   ├── config.py                        # TOML config loader
│   ├── logging_setup.py                 # structlog JSON logging
│   ├── events.py                        # Event/Features dataclasses, ULID, ser/deser
│   ├── bus.py                           # multiprocessing.Queue pub/sub wrapper
│   ├── scanners/
│   │   ├── __init__.py
│   │   ├── base.py                      # Scanner ABC, ScannerError
│   │   ├── ble.py                       # BleakScanner wrapper
│   │   ├── wifi.py                      # scapy stub (graceful when no adapter)
│   │   ├── subghz.py                    # rtl_433 subprocess parser
│   │   └── midband.py                   # pyrtlsdr energy detector
│   ├── sinks/
│   │   ├── __init__.py
│   │   ├── base.py                      # Sink ABC
│   │   └── local.py                     # SQLite batch writer
│   └── storage/
│       ├── __init__.py
│       ├── schema.sql                   # raw_events table
│       ├── db.py                        # connection helper, migrations
│       └── pruner.py                    # 7-day retention
├── tests/
│   ├── conftest.py
│   ├── test_events.py
│   ├── test_bus.py
│   ├── test_storage_db.py
│   ├── test_storage_pruner.py
│   ├── test_sinks_local.py
│   ├── test_scanners_base.py
│   ├── test_scanners_ble.py
│   ├── test_scanners_subghz.py
│   ├── test_scanners_midband.py
│   ├── test_scanners_wifi.py
│   └── integration/
│       ├── conftest.py
│       └── test_pi_smoke.py             # runs over SSH, requires Pi
└── config/
    └── watchtower.example.toml          # default config
```

**Decomposition principle:** files split by domain (events, bus, scanners, sinks, storage), not by layer. Each scanner is its own file because they don't share code beyond the `Scanner` ABC. Each sink the same. Tests mirror source layout.

---

## Task 1: Project scaffolding + uv setup

**Files:**
- Create: `C:\Users\ihass\watchtower\pyproject.toml`
- Create: `C:\Users\ihass\watchtower\.gitignore`
- Create: `C:\Users\ihass\watchtower\src\watchtower\__init__.py`
- Create: `C:\Users\ihass\watchtower\tests\conftest.py`
- Create: `C:\Users\ihass\watchtower\config\watchtower.example.toml`
- Create: `C:\Users\ihass\watchtower\README.md`

- [ ] **Step 1.1: Verify uv is installed (or install it)**

Run on Windows:
```bash
uv --version
```
Expected: prints version, e.g. `uv 0.4.x`. If not installed:
```bash
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

- [ ] **Step 1.2: Write pyproject.toml**

`C:\Users\ihass\watchtower\pyproject.toml`:
```toml
[project]
name = "watchtower"
version = "0.1.0"
description = "Perimeter RF awareness layer"
readme = "README.md"
requires-python = ">=3.11"
dependencies = [
    "bleak>=0.22",
    "pyrtlsdr>=0.3.0",
    "python-ulid>=2.7",
    "structlog>=24.4",
    "tomli>=2.0; python_version<'3.11'",
    "click>=8.1",
]

[project.scripts]
watchtower = "watchtower.cli:main"

[tool.uv]
dev-dependencies = [
    "pytest>=8.3",
    "pytest-asyncio>=0.24",
    "pytest-mock>=3.14",
]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
addopts = "-q -ra"
markers = [
    "integration: tests that require the live Pi over SSH",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/watchtower"]
```

- [ ] **Step 1.3: Write .gitignore**

`C:\Users\ihass\watchtower\.gitignore`:
```
__pycache__/
*.pyc
.venv/
.uv/
.pytest_cache/
*.db
*.db-journal
*.db-wal
*.db-shm
.coverage
dist/
build/
*.egg-info/
config/watchtower.toml
```

- [ ] **Step 1.4: Write src/watchtower/__init__.py**

`C:\Users\ihass\watchtower\src\watchtower\__init__.py`:
```python
"""Watchtower — perimeter RF awareness layer."""

__version__ = "0.1.0"
```

- [ ] **Step 1.5: Write tests/conftest.py (placeholder for now)**

`C:\Users\ihass\watchtower\tests\conftest.py`:
```python
"""Shared pytest fixtures."""
```

- [ ] **Step 1.6: Write config/watchtower.example.toml**

`C:\Users\ihass\watchtower\config\watchtower.example.toml`:
```toml
# Watchtower configuration.
# Copy to /etc/watchtower/watchtower.toml on the Pi and edit.

[storage]
db_path = "/var/lib/watchtower/watchtower.db"
retention_days = 7

[bus]
queue_size = 10000

[logging]
level = "INFO"
format = "json"

[scanners.ble]
enabled = true
adapter = "hci0"

[scanners.wifi]
enabled = true
interface = "wlan1"  # USB monitor-mode adapter; gracefully stubs if absent

[scanners.subghz]
enabled = true
device_index = 0          # which RTL-SDR (0 or 1)
center_freq_hz = 433920000
sample_rate_hz = 2048000
rtl_433_args = ["-F", "json", "-d", "0", "-G", "5"]

[scanners.midband]
enabled = true
device_index = 1          # the other RTL-SDR
sweep_freqs_hz = [
    734000000,    # LTE Band 12 lower
    881000000,    # LTE Band 5 lower
    944000000,    # GSM 900
    1575420000,   # GPS L1 (energy reference, never has user signal)
]
dwell_seconds = 5
sample_rate_hz = 2048000
```

- [ ] **Step 1.7: Write README.md (one-paragraph)**

`C:\Users\ihass\watchtower\README.md`:
```markdown
# Watchtower

Perimeter RF awareness layer for residential pre-intrusion casing detection
and 7-day forensic timeline. Single-Pi deployment, fully passive.

See `docs/superpowers/specs/2026-05-03-watchtower-design.md` for design.
See `docs/superpowers/plans/` for milestone implementation plans.

## Quickstart

```bash
uv sync
uv run pytest
```

Deployment to Pi: see `deploy/deploy.sh`.
```

- [ ] **Step 1.8: Initialize uv environment and verify**

Run on Windows:
```bash
cd /c/Users/ihass/watchtower
uv sync
uv run python -c "import watchtower; print(watchtower.__version__)"
```
Expected: `0.1.0`

- [ ] **Step 1.9: Commit**

```bash
cd /c/Users/ihass/watchtower
git add pyproject.toml .gitignore src/watchtower/__init__.py tests/conftest.py config/watchtower.example.toml README.md
git commit -m "M1.1: project scaffolding, uv deps, config template"
```

---

## Task 2: Pi system-package setup script

**Files:**
- Create: `C:\Users\ihass\watchtower\deploy\pi-setup.sh`

- [ ] **Step 2.1: Write deploy/pi-setup.sh**

`C:\Users\ihass\watchtower\deploy\pi-setup.sh`:
```bash
#!/usr/bin/env bash
# Idempotent Pi-side system setup. Safe to re-run.
set -euo pipefail

echo "[+] Updating apt index..."
sudo apt-get update -qq

echo "[+] Installing system packages..."
sudo apt-get install -y --no-install-recommends \
  python3-pip python3-venv python3-dev \
  bluez bluez-tools libbluetooth-dev \
  rtl-sdr librtlsdr-dev rtl-433 \
  sqlite3 \
  build-essential pkg-config \
  rsync git curl

echo "[+] Adding 'admin' to bluetooth group (requires re-login to take effect)..."
sudo usermod -aG bluetooth admin || true

echo "[+] Blacklisting kernel DVB driver (else rtl-sdr can't claim USB)..."
sudo tee /etc/modprobe.d/blacklist-rtl.conf >/dev/null <<'EOF'
blacklist dvb_usb_rtl28xxu
blacklist rtl2832
blacklist rtl2830
EOF

echo "[+] Installing rtl-sdr udev rules so non-root users can use the dongles..."
sudo tee /etc/udev/rules.d/20-rtlsdr.rules >/dev/null <<'EOF'
SUBSYSTEM=="usb", ATTRS{idVendor}=="0bda", ATTRS{idProduct}=="2838", GROUP="plugdev", MODE="0666"
EOF
sudo udevadm control --reload-rules
sudo udevadm trigger

echo "[+] Creating /var/lib/watchtower and /etc/watchtower owned by admin..."
sudo install -d -o admin -g admin -m 0755 /var/lib/watchtower
sudo install -d -o admin -g admin -m 0755 /etc/watchtower
sudo install -d -o admin -g admin -m 0755 /var/log/watchtower

echo "[+] Done. Verify with: rtl_test -t (must reload modules / reboot if blacklist was new)"
```

- [ ] **Step 2.2: Copy to Pi and run**

Run on Windows:
```bash
scp /c/Users/ihass/watchtower/deploy/pi-setup.sh admin@watchtower.local:/tmp/pi-setup.sh
ssh admin@watchtower.local "chmod +x /tmp/pi-setup.sh && sudo /tmp/pi-setup.sh"
```
Note: `sudo` on the Pi will prompt for the admin password the first time (until passwordless sudo is configured separately). Have user enter it.

- [ ] **Step 2.3: Reboot Pi to load fresh module blacklist**

```bash
ssh admin@watchtower.local "sudo reboot"
sleep 60
ssh -o BatchMode=yes admin@watchtower.local "uptime"
```
Expected: Pi boots back, uptime under 2 min.

- [ ] **Step 2.4: Verify RTL-SDR dongles enumerate**

```bash
ssh admin@watchtower.local "rtl_test -t 2>&1 | head -25"
```
Expected: `Found 2 device(s)` followed by tuner info per device, then "PASS" or band-stops list.

- [ ] **Step 2.5: Verify rtl_433 runs**

```bash
ssh admin@watchtower.local "timeout 5 rtl_433 -F json -d 0 -G 5 2>&1 | head -20"
```
Expected: rtl_433 starts, prints config JSON, may or may not decode signals (depends on environment), exits cleanly after timeout.

- [ ] **Step 2.6: Commit setup script**

```bash
cd /c/Users/ihass/watchtower
git add deploy/pi-setup.sh
git commit -m "M1.2: Pi system-package setup script"
```

---

## Task 3: Event envelope + ULID

**Files:**
- Create: `src/watchtower/events.py`
- Create: `tests/test_events.py`

- [ ] **Step 3.1: Write the failing test**

`tests/test_events.py`:
```python
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
```

- [ ] **Step 3.2: Run test, verify it fails**

```bash
cd /c/Users/ihass/watchtower
uv run pytest tests/test_events.py -v
```
Expected: FAIL — `ImportError: No module named 'watchtower.events'`

- [ ] **Step 3.3: Implement events.py**

`src/watchtower/events.py`:
```python
"""Event envelope shared across all scanners and sinks."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from ulid import ULID


class Scanner(str, Enum):
    BLE = "ble_scanner"
    WIFI = "wifi_scanner"
    SUBGHZ = "subghz_scanner"
    MIDBAND = "midband_scanner"


class EventKind(str, Enum):
    BLE_ADV = "ble_adv"
    BLE_SCAN_RESPONSE = "ble_scan_response"
    WIFI_PROBE_REQUEST = "wifi_probe_request"
    WIFI_ASSOC_REQUEST = "wifi_assoc_request"
    WIFI_BEACON_SEEN = "wifi_beacon_seen"
    KEYFOB_EMISSION = "keyfob_emission"
    GARAGE_EMISSION = "garage_emission"
    UNKNOWN_SUBGHZ_BURST = "unknown_subghz_burst"
    WALKIETALKIE_EMISSION = "walkietalkie_emission"
    SUBGHZ_PROTOCOL_DECODED = "subghz_protocol_decoded"
    CELLULAR_BAND_ENERGY = "cellular_band_energy"
    LORA_EMISSION = "lora_emission"
    AVIATION_BAND_ENERGY = "aviation_band_energy"


@dataclass
class Features:
    rssi: int | None = None
    mac: str | None = None
    vendor_oui: str | None = None
    service_uuids: list[str] = field(default_factory=list)
    manufacturer_data_hex: str | None = None
    is_random_mac: bool | None = None
    tx_power: int | None = None
    local_name: str | None = None
    # sub-GHz
    frequency_hz: int | None = None
    protocol: str | None = None
    decoded: dict[str, Any] = field(default_factory=dict)
    # midband / spectrum
    band_name: str | None = None
    energy_dbm: float | None = None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Event:
    scanner: Scanner
    kind: EventKind
    features: Features
    raw: dict[str, Any] = field(default_factory=dict)
    ts: str = field(default_factory=_now_iso)
    event_id: str = field(default_factory=lambda: str(ULID()))
    channel_hint: int | None = None
    mesh_node_id: str | None = None  # v2

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["scanner"] = self.scanner.value
        d["kind"] = self.kind.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Event":
        return cls(
            event_id=d["event_id"],
            ts=d["ts"],
            scanner=Scanner(d["scanner"]),
            kind=EventKind(d["kind"]),
            features=Features(**d.get("features", {})),
            raw=d.get("raw", {}),
            channel_hint=d.get("channel_hint"),
            mesh_node_id=d.get("mesh_node_id"),
        )
```

- [ ] **Step 3.4: Run test, verify it passes**

```bash
uv run pytest tests/test_events.py -v
```
Expected: 5 passed.

- [ ] **Step 3.5: Commit**

```bash
git add src/watchtower/events.py tests/test_events.py
git commit -m "M1.3: Event envelope with ULID, dataclass round-trip"
```

---

## Task 4: SQLite schema + db helper

**Files:**
- Create: `src/watchtower/storage/__init__.py`
- Create: `src/watchtower/storage/schema.sql`
- Create: `src/watchtower/storage/db.py`
- Create: `tests/test_storage_db.py`

- [ ] **Step 4.1: Write the failing test**

`tests/test_storage_db.py`:
```python
"""Tests for storage/db.py — schema setup and connection helper."""
import sqlite3
from pathlib import Path

import pytest

from watchtower.storage.db import init_db, get_connection, schema_version


def test_init_db_creates_raw_events_table(tmp_path: Path):
    db = tmp_path / "test.db"
    init_db(db)
    with get_connection(db) as conn:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
    names = [r[0] for r in rows]
    assert "raw_events" in names
    assert "schema_meta" in names


def test_init_db_is_idempotent(tmp_path: Path):
    db = tmp_path / "test.db"
    init_db(db)
    init_db(db)  # second call must not fail
    with get_connection(db) as conn:
        v = conn.execute("SELECT version FROM schema_meta").fetchone()
    assert v[0] == 1


def test_raw_events_columns(tmp_path: Path):
    db = tmp_path / "test.db"
    init_db(db)
    with get_connection(db) as conn:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(raw_events)")}
    expected = {"event_id", "ts", "ts_unix", "scanner", "kind", "features_json", "raw_json"}
    assert expected.issubset(cols)


def test_get_connection_enables_foreign_keys(tmp_path: Path):
    db = tmp_path / "test.db"
    init_db(db)
    with get_connection(db) as conn:
        v = conn.execute("PRAGMA foreign_keys").fetchone()[0]
    assert v == 1


def test_schema_version_returns_int(tmp_path: Path):
    db = tmp_path / "test.db"
    init_db(db)
    assert schema_version(db) == 1
```

- [ ] **Step 4.2: Run test, verify it fails**

```bash
uv run pytest tests/test_storage_db.py -v
```
Expected: FAIL — `ImportError`.

- [ ] **Step 4.3: Write storage/__init__.py and schema.sql**

`src/watchtower/storage/__init__.py`:
```python
"""SQLite storage."""
```

`src/watchtower/storage/schema.sql`:
```sql
-- Watchtower schema v1.
-- raw_events stores every scan event for the retention window (default 7d).

CREATE TABLE IF NOT EXISTS schema_meta (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS raw_events (
    event_id      TEXT PRIMARY KEY,            -- ULID, time-sortable
    ts            TEXT NOT NULL,               -- ISO-8601 UTC
    ts_unix       INTEGER NOT NULL,            -- epoch seconds, indexed for prune
    scanner       TEXT NOT NULL,               -- e.g. "ble_scanner"
    kind          TEXT NOT NULL,               -- e.g. "ble_adv"
    features_json TEXT NOT NULL,               -- JSON-encoded Features dict
    raw_json      TEXT NOT NULL                -- JSON-encoded raw scanner output
);

CREATE INDEX IF NOT EXISTS idx_raw_events_ts_unix ON raw_events(ts_unix);
CREATE INDEX IF NOT EXISTS idx_raw_events_scanner_kind ON raw_events(scanner, kind);
CREATE INDEX IF NOT EXISTS idx_raw_events_mac ON raw_events(json_extract(features_json, '$.mac'));

-- Initial version row inserted only if absent.
INSERT OR IGNORE INTO schema_meta(version) VALUES (1);
```

- [ ] **Step 4.4: Write db.py**

`src/watchtower/storage/db.py`:
```python
"""SQLite connection helper and schema bootstrap."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from importlib import resources
from pathlib import Path
from typing import Iterator


def _load_schema_sql() -> str:
    return resources.files("watchtower.storage").joinpath("schema.sql").read_text(encoding="utf-8")


@contextmanager
def get_connection(db_path: Path | str) -> Iterator[sqlite3.Connection]:
    """Yield a SQLite connection with PRAGMAs set sensibly for the daemon."""
    conn = sqlite3.connect(str(db_path), isolation_level=None)  # autocommit
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA busy_timeout = 5000")
        yield conn
    finally:
        conn.close()


def init_db(db_path: Path | str) -> None:
    """Create the database file and apply the schema if not already present."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with get_connection(db_path) as conn:
        conn.executescript(_load_schema_sql())


def schema_version(db_path: Path | str) -> int:
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT version FROM schema_meta").fetchone()
    return int(row[0]) if row else 0
```

- [ ] **Step 4.5: Update pyproject.toml to package schema.sql**

Edit `pyproject.toml`, ensure the `[tool.hatch.build.targets.wheel]` section includes:
```toml
[tool.hatch.build.targets.wheel]
packages = ["src/watchtower"]

[tool.hatch.build.targets.wheel.force-include]
"src/watchtower/storage/schema.sql" = "watchtower/storage/schema.sql"
```

- [ ] **Step 4.6: Run test, verify it passes**

```bash
uv run pytest tests/test_storage_db.py -v
```
Expected: 5 passed.

- [ ] **Step 4.7: Commit**

```bash
git add src/watchtower/storage tests/test_storage_db.py pyproject.toml
git commit -m "M1.4: SQLite schema + connection helper, schema v1"
```

---

## Task 5: Local message bus

**Files:**
- Create: `src/watchtower/bus.py`
- Create: `tests/test_bus.py`

- [ ] **Step 5.1: Write the failing test**

`tests/test_bus.py`:
```python
"""Tests for the local message bus."""
import asyncio

import pytest

from watchtower.bus import Bus
from watchtower.events import Event, EventKind, Features, Scanner


def _ev() -> Event:
    return Event(scanner=Scanner.BLE, kind=EventKind.BLE_ADV, features=Features(rssi=-50))


async def test_bus_delivers_to_one_subscriber():
    bus = Bus()
    received: list[Event] = []

    async def consumer(ev):
        received.append(ev)

    bus.subscribe(consumer)
    await bus.publish(_ev())
    await bus.drain(timeout=1.0)
    assert len(received) == 1
    assert received[0].kind == EventKind.BLE_ADV


async def test_bus_delivers_to_multiple_subscribers():
    bus = Bus()
    a, b = [], []
    bus.subscribe(lambda ev: a.append(ev))
    bus.subscribe(lambda ev: b.append(ev))
    await bus.publish(_ev())
    await bus.drain(timeout=1.0)
    assert len(a) == 1
    assert len(b) == 1


async def test_bus_isolates_failing_subscriber():
    bus = Bus()
    received_b: list[Event] = []

    def bad(ev):
        raise RuntimeError("boom")

    async def good(ev):
        received_b.append(ev)

    bus.subscribe(bad)
    bus.subscribe(good)
    await bus.publish(_ev())
    await bus.drain(timeout=1.0)
    # good subscriber still received despite bad raising
    assert len(received_b) == 1


async def test_bus_supports_sync_and_async_subscribers():
    bus = Bus()
    sync_recv, async_recv = [], []
    bus.subscribe(lambda ev: sync_recv.append(ev))

    async def a(ev):
        async_recv.append(ev)

    bus.subscribe(a)
    await bus.publish(_ev())
    await bus.drain(timeout=1.0)
    assert sync_recv and async_recv
```

- [ ] **Step 5.2: Run test, verify it fails**

```bash
uv run pytest tests/test_bus.py -v
```
Expected: FAIL — `ImportError`.

- [ ] **Step 5.3: Implement bus.py**

`src/watchtower/bus.py`:
```python
"""In-process pub/sub bus for Event objects.

Implementation note: M1 uses asyncio for simplicity since all scanners are
already coroutine-friendly (bleak is async, pyrtlsdr can be wrapped, rtl_433
output is read line-by-line). multiprocessing.Queue is reserved for cross-process
fan-out which is not needed in M1. Swap is local to this module.
"""
from __future__ import annotations

import asyncio
import inspect
import logging
from typing import Awaitable, Callable, Union

from watchtower.events import Event

log = logging.getLogger(__name__)

Subscriber = Union[Callable[[Event], None], Callable[[Event], Awaitable[None]]]


class Bus:
    def __init__(self, queue_size: int = 10000) -> None:
        self._subs: list[Subscriber] = []
        self._queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=queue_size)
        self._dispatcher_task: asyncio.Task | None = None

    def subscribe(self, fn: Subscriber) -> None:
        self._subs.append(fn)

    async def publish(self, ev: Event) -> None:
        if self._dispatcher_task is None:
            self._dispatcher_task = asyncio.create_task(self._dispatch())
        await self._queue.put(ev)

    async def _dispatch(self) -> None:
        while True:
            ev = await self._queue.get()
            for sub in self._subs:
                try:
                    res = sub(ev)
                    if inspect.isawaitable(res):
                        await res
                except Exception:  # noqa: BLE001
                    log.exception("subscriber raised; isolated")

    async def drain(self, timeout: float = 5.0) -> None:
        """Wait for the queue to empty and dispatcher to settle. For tests."""
        deadline = asyncio.get_event_loop().time() + timeout
        while not self._queue.empty():
            if asyncio.get_event_loop().time() > deadline:
                raise TimeoutError("bus drain timeout")
            await asyncio.sleep(0.01)
        # one more tick so the last in-flight handler can finish
        await asyncio.sleep(0.05)

    async def shutdown(self) -> None:
        if self._dispatcher_task and not self._dispatcher_task.done():
            self._dispatcher_task.cancel()
            try:
                await self._dispatcher_task
            except asyncio.CancelledError:
                pass
```

- [ ] **Step 5.4: Run test, verify it passes**

```bash
uv run pytest tests/test_bus.py -v
```
Expected: 4 passed.

- [ ] **Step 5.5: Commit**

```bash
git add src/watchtower/bus.py tests/test_bus.py
git commit -m "M1.5: asyncio bus with sync+async subscribers and failure isolation"
```

---

## Task 6: LocalSink (SQLite batch writer)

**Files:**
- Create: `src/watchtower/sinks/__init__.py`
- Create: `src/watchtower/sinks/base.py`
- Create: `src/watchtower/sinks/local.py`
- Create: `tests/test_sinks_local.py`

- [ ] **Step 6.1: Write the failing test**

`tests/test_sinks_local.py`:
```python
"""Tests for the SQLite local sink."""
import asyncio
import json
import sqlite3
from pathlib import Path

import pytest

from watchtower.events import Event, EventKind, Features, Scanner
from watchtower.sinks.local import LocalSink
from watchtower.storage.db import init_db


def _ev(rssi: int = -50) -> Event:
    return Event(
        scanner=Scanner.BLE,
        kind=EventKind.BLE_ADV,
        features=Features(rssi=rssi, mac="aa:bb:cc:dd:ee:ff"),
        raw={"k": "v"},
    )


async def test_sink_writes_single_event(tmp_path: Path):
    db = tmp_path / "t.db"
    init_db(db)
    sink = LocalSink(db, batch_size=1, flush_interval=0.1)
    await sink.start()
    await sink.write(_ev())
    await sink.flush()
    await sink.stop()
    with sqlite3.connect(db) as conn:
        n = conn.execute("SELECT COUNT(*) FROM raw_events").fetchone()[0]
    assert n == 1


async def test_sink_batches_then_flushes(tmp_path: Path):
    db = tmp_path / "t.db"
    init_db(db)
    sink = LocalSink(db, batch_size=10, flush_interval=10.0)
    await sink.start()
    for i in range(5):
        await sink.write(_ev(rssi=-50 - i))
    # batch_size not yet reached, but explicit flush forces write
    await sink.flush()
    await sink.stop()
    with sqlite3.connect(db) as conn:
        n = conn.execute("SELECT COUNT(*) FROM raw_events").fetchone()[0]
    assert n == 5


async def test_sink_persists_features_and_raw(tmp_path: Path):
    db = tmp_path / "t.db"
    init_db(db)
    sink = LocalSink(db, batch_size=1, flush_interval=0.1)
    await sink.start()
    e = _ev()
    await sink.write(e)
    await sink.flush()
    await sink.stop()
    with sqlite3.connect(db) as conn:
        row = conn.execute(
            "SELECT event_id, scanner, kind, features_json, raw_json FROM raw_events"
        ).fetchone()
    assert row[0] == e.event_id
    assert row[1] == "ble_scanner"
    assert row[2] == "ble_adv"
    feats = json.loads(row[3])
    assert feats["rssi"] == -50
    assert feats["mac"] == "aa:bb:cc:dd:ee:ff"
    assert json.loads(row[4]) == {"k": "v"}
```

- [ ] **Step 6.2: Run test, verify it fails**

```bash
uv run pytest tests/test_sinks_local.py -v
```
Expected: FAIL — `ImportError`.

- [ ] **Step 6.3: Write sinks/base.py and sinks/__init__.py**

`src/watchtower/sinks/__init__.py`:
```python
"""Event sinks."""
```

`src/watchtower/sinks/base.py`:
```python
"""Sink abstract interface."""
from __future__ import annotations

from abc import ABC, abstractmethod

from watchtower.events import Event


class Sink(ABC):
    @abstractmethod
    async def start(self) -> None: ...
    @abstractmethod
    async def stop(self) -> None: ...
    @abstractmethod
    async def write(self, ev: Event) -> None: ...
    @abstractmethod
    async def flush(self) -> None: ...
```

- [ ] **Step 6.4: Write sinks/local.py**

`src/watchtower/sinks/local.py`:
```python
"""SQLite-backed sink. Batches writes for throughput."""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path

from watchtower.events import Event
from watchtower.sinks.base import Sink
from watchtower.storage.db import get_connection

log = logging.getLogger(__name__)

_INSERT_SQL = """
INSERT INTO raw_events (event_id, ts, ts_unix, scanner, kind, features_json, raw_json)
VALUES (?, ?, ?, ?, ?, ?, ?)
"""


class LocalSink(Sink):
    def __init__(
        self,
        db_path: Path | str,
        batch_size: int = 100,
        flush_interval: float = 1.0,
    ) -> None:
        self._db = Path(db_path)
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._buf: list[tuple] = []
        self._lock = asyncio.Lock()
        self._flusher: asyncio.Task | None = None
        self._stopping = False

    async def start(self) -> None:
        self._stopping = False
        self._flusher = asyncio.create_task(self._periodic_flush())

    async def stop(self) -> None:
        self._stopping = True
        if self._flusher:
            self._flusher.cancel()
            try:
                await self._flusher
            except asyncio.CancelledError:
                pass
        await self.flush()

    async def write(self, ev: Event) -> None:
        async with self._lock:
            self._buf.append(self._to_row(ev))
            if len(self._buf) >= self._batch_size:
                await self._flush_locked()

    async def flush(self) -> None:
        async with self._lock:
            await self._flush_locked()

    async def _flush_locked(self) -> None:
        if not self._buf:
            return
        rows, self._buf = self._buf, []
        try:
            with get_connection(self._db) as conn:
                conn.executemany(_INSERT_SQL, rows)
        except Exception:  # noqa: BLE001
            log.exception("local sink flush failed; %d events lost", len(rows))

    async def _periodic_flush(self) -> None:
        try:
            while not self._stopping:
                await asyncio.sleep(self._flush_interval)
                await self.flush()
        except asyncio.CancelledError:
            pass

    @staticmethod
    def _to_row(ev: Event) -> tuple:
        ts_unix = int(datetime.fromisoformat(ev.ts).timestamp())
        # Features is a dataclass; asdict via to_dict pulls already-serialized form
        d = ev.to_dict()
        return (
            ev.event_id,
            ev.ts,
            ts_unix,
            d["scanner"],
            d["kind"],
            json.dumps(d["features"], default=str),
            json.dumps(d["raw"], default=str),
        )
```

- [ ] **Step 6.5: Run test, verify it passes**

```bash
uv run pytest tests/test_sinks_local.py -v
```
Expected: 3 passed.

- [ ] **Step 6.6: Commit**

```bash
git add src/watchtower/sinks tests/test_sinks_local.py
git commit -m "M1.6: LocalSink batched SQLite writer"
```

---

## Task 7: Retention pruner

**Files:**
- Create: `src/watchtower/storage/pruner.py`
- Create: `tests/test_storage_pruner.py`

- [ ] **Step 7.1: Write the failing test**

`tests/test_storage_pruner.py`:
```python
"""Tests for retention pruner."""
import time
from pathlib import Path

import pytest

from watchtower.events import Event, EventKind, Features, Scanner
from watchtower.sinks.local import LocalSink
from watchtower.storage.db import get_connection, init_db
from watchtower.storage.pruner import prune_older_than


def _seed_events(db: Path, count: int, ts_unix: int) -> None:
    """Seed `count` raw_events at the given epoch ts."""
    rows = []
    for i in range(count):
        rows.append((
            f"01HF{i:020d}",                                # fake ULID-shaped id
            "2026-05-03T22:41:13+00:00",
            ts_unix,
            "ble_scanner", "ble_adv", "{}", "{}",
        ))
    with get_connection(db) as conn:
        conn.executemany(
            "INSERT INTO raw_events VALUES (?, ?, ?, ?, ?, ?, ?)", rows
        )


def test_prune_deletes_old_events(tmp_path: Path):
    db = tmp_path / "t.db"
    init_db(db)
    now = int(time.time())
    _seed_events(db, 5, now - 8 * 86400)   # 8 days old, should be pruned
    _seed_events(db, 3, now - 1 * 86400)   # 1 day old, kept
    n_pruned = prune_older_than(db, retention_seconds=7 * 86400)
    assert n_pruned == 5
    with get_connection(db) as conn:
        remaining = conn.execute("SELECT COUNT(*) FROM raw_events").fetchone()[0]
    assert remaining == 3


def test_prune_noop_when_nothing_old(tmp_path: Path):
    db = tmp_path / "t.db"
    init_db(db)
    now = int(time.time())
    _seed_events(db, 3, now - 86400)
    assert prune_older_than(db, retention_seconds=7 * 86400) == 0


def test_prune_returns_zero_on_empty_db(tmp_path: Path):
    db = tmp_path / "t.db"
    init_db(db)
    assert prune_older_than(db, retention_seconds=7 * 86400) == 0
```

- [ ] **Step 7.2: Run test, verify it fails**

```bash
uv run pytest tests/test_storage_pruner.py -v
```
Expected: FAIL — `ImportError`.

- [ ] **Step 7.3: Implement pruner.py**

`src/watchtower/storage/pruner.py`:
```python
"""Retention pruner. Deletes raw_events older than retention window."""
from __future__ import annotations

import logging
import time
from pathlib import Path

from watchtower.storage.db import get_connection

log = logging.getLogger(__name__)


def prune_older_than(db_path: Path | str, retention_seconds: int) -> int:
    """Delete raw_events with ts_unix older than `now - retention_seconds`.

    Returns the count of deleted rows.
    """
    cutoff = int(time.time()) - retention_seconds
    with get_connection(db_path) as conn:
        cur = conn.execute("DELETE FROM raw_events WHERE ts_unix < ?", (cutoff,))
        deleted = cur.rowcount or 0
        # M1 does not VACUUM — pages are reused over the steady-state 7-day window
        # so file size stabilizes naturally. Periodic vacuum is M5 ops cleanup.
    if deleted:
        log.info("pruner: deleted %d rows older than %d (cutoff=%d)", deleted, retention_seconds, cutoff)
    return deleted
```

- [ ] **Step 7.4: Run test, verify it passes**

```bash
uv run pytest tests/test_storage_pruner.py -v
```
Expected: 3 passed.

- [ ] **Step 7.5: Commit**

```bash
git add src/watchtower/storage/pruner.py tests/test_storage_pruner.py
git commit -m "M1.7: retention pruner deletes events past 7-day window"
```

---

## Task 8: Scanner ABC

**Files:**
- Create: `src/watchtower/scanners/__init__.py`
- Create: `src/watchtower/scanners/base.py`
- Create: `tests/test_scanners_base.py`

- [ ] **Step 8.1: Write the failing test**

`tests/test_scanners_base.py`:
```python
"""Tests for Scanner ABC contract."""
import asyncio

import pytest

from watchtower.events import Event, EventKind, Features, Scanner as ScannerName
from watchtower.scanners.base import Scanner, ScannerError


class FakeScanner(Scanner):
    """In-test scanner that emits one event then stops."""

    name = ScannerName.BLE

    async def run(self) -> None:
        ev = Event(scanner=ScannerName.BLE, kind=EventKind.BLE_ADV, features=Features(rssi=-1))
        await self._emit(ev)
        # stay alive until cancelled
        await asyncio.Event().wait()


async def test_scanner_emits_event():
    received = []
    s = FakeScanner()
    s.on_event(lambda ev: received.append(ev))
    task = asyncio.create_task(s.start())
    await asyncio.sleep(0.05)
    await s.stop()
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    assert len(received) == 1
    assert received[0].kind == EventKind.BLE_ADV


async def test_scanner_supports_async_callbacks():
    received = []

    async def consume(ev):
        received.append(ev)

    s = FakeScanner()
    s.on_event(consume)
    task = asyncio.create_task(s.start())
    await asyncio.sleep(0.05)
    await s.stop()
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    assert len(received) == 1


def test_scanner_error_is_exception():
    assert issubclass(ScannerError, Exception)
```

- [ ] **Step 8.2: Run test, verify it fails**

```bash
uv run pytest tests/test_scanners_base.py -v
```
Expected: FAIL — `ImportError`.

- [ ] **Step 8.3: Implement scanners/base.py and scanners/__init__.py**

`src/watchtower/scanners/__init__.py`:
```python
"""Scanners — RF capture front-ends emitting normalized Events."""
```

`src/watchtower/scanners/base.py`:
```python
"""Scanner abstract base.

A Scanner runs as an awaitable `start()` task and emits `Event`s to all
registered callbacks via `_emit(ev)`. Callbacks may be sync or async.
"""
from __future__ import annotations

import asyncio
import inspect
import logging
from abc import ABC, abstractmethod
from typing import Awaitable, Callable, Union

from watchtower.events import Event, Scanner as ScannerName

log = logging.getLogger(__name__)


class ScannerError(Exception):
    pass


Listener = Union[Callable[[Event], None], Callable[[Event], Awaitable[None]]]


class Scanner(ABC):
    """Long-lived event-producing scanner."""

    name: ScannerName  # subclass sets this

    def __init__(self) -> None:
        self._listeners: list[Listener] = []
        self._stop_event = asyncio.Event()

    def on_event(self, fn: Listener) -> None:
        self._listeners.append(fn)

    async def start(self) -> None:
        self._stop_event.clear()
        runner = asyncio.create_task(self.run())
        stopper = asyncio.create_task(self._stop_event.wait())
        done, pending = await asyncio.wait(
            {runner, stopper},
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass
        if runner in done and runner.exception():
            raise runner.exception()  # type: ignore[misc]

    async def stop(self) -> None:
        self._stop_event.set()

    @abstractmethod
    async def run(self) -> None:
        """Subclass implements the long-lived capture loop."""

    async def _emit(self, ev: Event) -> None:
        for fn in self._listeners:
            try:
                res = fn(ev)
                if inspect.isawaitable(res):
                    await res
            except Exception:  # noqa: BLE001
                log.exception("scanner listener raised; isolated")
```

- [ ] **Step 8.4: Run test, verify it passes**

```bash
uv run pytest tests/test_scanners_base.py -v
```
Expected: 3 passed.

- [ ] **Step 8.5: Commit**

```bash
git add src/watchtower/scanners/__init__.py src/watchtower/scanners/base.py tests/test_scanners_base.py
git commit -m "M1.8: Scanner ABC with start/stop/emit and listener fan-out"
```

---

## Task 9: BLE scanner

**Files:**
- Create: `src/watchtower/scanners/ble.py`
- Create: `tests/test_scanners_ble.py`

- [ ] **Step 9.1: Write the failing test**

`tests/test_scanners_ble.py`:
```python
"""Tests for BLE scanner — uses bleak mocks."""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from watchtower.events import EventKind, Scanner as ScannerName
from watchtower.scanners.ble import BleScanner


def _fake_device(address: str = "aa:bb:cc:dd:ee:ff", name: str | None = "iPhone"):
    d = MagicMock()
    d.address = address
    d.name = name
    return d


def _fake_advertisement(rssi: int = -55, tx_power: int | None = -8,
                        service_uuids: list[str] | None = None,
                        manufacturer_data: dict[int, bytes] | None = None,
                        local_name: str | None = "iPhone"):
    a = MagicMock()
    a.rssi = rssi
    a.tx_power = tx_power
    a.service_uuids = service_uuids or ["fd6f"]
    a.manufacturer_data = manufacturer_data or {0x004C: bytes.fromhex("1005")}
    a.local_name = local_name
    return a


async def test_ble_scanner_emits_on_advertisement():
    received = []

    with patch("watchtower.scanners.ble.BleakScanner") as MockScanner:
        instance = MockScanner.return_value
        instance.start = AsyncMock()
        instance.stop = AsyncMock()
        # capture the detection callback
        captured: dict[str, callable] = {}
        def _ctor(*args, **kwargs):
            captured["cb"] = kwargs.get("detection_callback") or (args[0] if args else None)
            return instance
        MockScanner.side_effect = _ctor

        s = BleScanner()
        s.on_event(lambda ev: received.append(ev))
        runner = asyncio.create_task(s.start())
        await asyncio.sleep(0.05)
        # invoke the captured detection callback as bleak would
        cb = captured["cb"]
        cb(_fake_device(), _fake_advertisement())
        await asyncio.sleep(0.05)
        await s.stop()
        runner.cancel()
        try:
            await runner
        except asyncio.CancelledError:
            pass

    assert len(received) == 1
    e = received[0]
    assert e.scanner == ScannerName.BLE
    assert e.kind == EventKind.BLE_ADV
    assert e.features.mac == "aa:bb:cc:dd:ee:ff"
    assert e.features.rssi == -55
    assert e.features.tx_power == -8
    assert e.features.service_uuids == ["fd6f"]
    assert e.features.manufacturer_data_hex.lower().startswith("4c00") or \
           e.features.manufacturer_data_hex.lower().startswith("004c")
    assert e.features.local_name == "iPhone"


def test_ble_is_random_mac_detection():
    from watchtower.scanners.ble import _is_random_mac
    # locally-administered bit (bit 1 of first byte) set => random
    assert _is_random_mac("ca:bb:cc:dd:ee:ff") is True   # first byte 0xCA, bit1=1
    assert _is_random_mac("aa:bb:cc:dd:ee:ff") is True   # 0xAA bit1=1
    assert _is_random_mac("a8:bb:cc:dd:ee:ff") is False  # 0xA8 bit1=0
    assert _is_random_mac("00:1A:11:22:33:44") is False  # 0x00 bit1=0


def test_ble_vendor_oui_lookup():
    from watchtower.scanners.ble import _vendor_for_oui
    # OUI list is small and we don't depend on it being exhaustive in M1;
    # just confirm the function returns None for unknown without raising.
    assert _vendor_for_oui("00:00:00") in (None, "Xerox")  # 00:00:00 historically Xerox
    assert _vendor_for_oui("zz:zz:zz") is None
```

- [ ] **Step 9.2: Run test, verify it fails**

```bash
uv run pytest tests/test_scanners_ble.py -v
```
Expected: FAIL — `ImportError`.

- [ ] **Step 9.3: Implement scanners/ble.py**

`src/watchtower/scanners/ble.py`:
```python
"""BLE scanner using bleak.

Subscribes to all BLE advertisements within range and emits one Event per
advertisement seen. Does not actively connect to devices (passive only).
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from bleak import BleakScanner

from watchtower.events import Event, EventKind, Features, Scanner as ScannerName
from watchtower.scanners.base import Scanner

log = logging.getLogger(__name__)


def _is_random_mac(mac: str) -> bool:
    """The locally-administered bit (bit 1 of MSB) flags random/non-OUI MACs."""
    try:
        first = int(mac.split(":")[0], 16)
    except (IndexError, ValueError):
        return False
    return bool(first & 0x02)


# Minimal vendor OUI table for v1 (top consumer brands).
# Full IEEE OUI registry will be downloaded at install time in a future task.
_OUI: dict[str, str] = {
    "00:00:00": "Xerox",
    "ac:de:48": "Apple",
    "f4:5c:89": "Apple",
    "fc:fc:48": "Apple",
    "00:18:b4": "Samsung",
    "08:08:c2": "Samsung",
    "94:eb:cd": "Google",
    "7c:9d:f0": "Google",
}


def _vendor_for_oui(mac: str) -> str | None:
    if not mac or len(mac) < 8:
        return None
    return _OUI.get(mac[:8].lower())


def _mfr_data_to_hex(data: dict[int, bytes]) -> str | None:
    if not data:
        return None
    # Concatenate vendor_id (LE 16-bit) + payload for each entry.
    parts = []
    for vid, payload in data.items():
        parts.append(vid.to_bytes(2, "little").hex() + payload.hex())
    return "".join(parts)


class BleScanner(Scanner):
    name = ScannerName.BLE

    def __init__(self, adapter: str | None = "hci0") -> None:
        super().__init__()
        self._adapter = adapter

    async def run(self) -> None:
        loop = asyncio.get_running_loop()

        def cb(device: Any, adv: Any) -> None:
            try:
                feats = Features(
                    mac=device.address,
                    rssi=int(adv.rssi) if adv.rssi is not None else None,
                    tx_power=int(adv.tx_power) if adv.tx_power is not None else None,
                    vendor_oui=_vendor_for_oui(device.address),
                    is_random_mac=_is_random_mac(device.address),
                    service_uuids=list(adv.service_uuids or []),
                    manufacturer_data_hex=_mfr_data_to_hex(adv.manufacturer_data or {}),
                    local_name=adv.local_name or device.name,
                )
                ev = Event(
                    scanner=ScannerName.BLE,
                    kind=EventKind.BLE_ADV,
                    features=feats,
                    raw={
                        "address": device.address,
                        "name": device.name,
                        "rssi": adv.rssi,
                        "tx_power": adv.tx_power,
                        "service_uuids": list(adv.service_uuids or []),
                        "manufacturer_data": {
                            str(k): v.hex() for k, v in (adv.manufacturer_data or {}).items()
                        },
                    },
                )
                # Schedule async emit from sync callback context.
                asyncio.run_coroutine_threadsafe(self._emit(ev), loop)
            except Exception:  # noqa: BLE001
                log.exception("ble cb failed")

        scanner = BleakScanner(detection_callback=cb, adapter=self._adapter)
        await scanner.start()
        try:
            # Stay alive until stopped.
            await self._stop_event.wait()
        finally:
            try:
                await scanner.stop()
            except Exception:  # noqa: BLE001
                log.exception("BleakScanner.stop failed")
```

- [ ] **Step 9.4: Run test, verify it passes**

```bash
uv run pytest tests/test_scanners_ble.py -v
```
Expected: 3 passed.

- [ ] **Step 9.5: Commit**

```bash
git add src/watchtower/scanners/ble.py tests/test_scanners_ble.py
git commit -m "M1.9: BLE scanner — passive advertisement capture via bleak"
```

---

## Task 10: Sub-GHz scanner (rtl_433 subprocess)

**Files:**
- Create: `src/watchtower/scanners/subghz.py`
- Create: `tests/test_scanners_subghz.py`

- [ ] **Step 10.1: Write the failing test**

`tests/test_scanners_subghz.py`:
```python
"""Tests for SubGhzScanner — parses rtl_433 JSON output via mock subprocess."""
import asyncio
import json

import pytest

from watchtower.events import EventKind, Scanner as ScannerName
from watchtower.scanners.subghz import SubGhzScanner, _line_to_event


def test_keyfob_line_to_event():
    line = json.dumps({
        "time": "2026-05-03 22:41:13",
        "model": "Honda-CarRemote",
        "id": "0x123ABC",
        "rolling_code": "0xDEADBEEF",
        "freq": 433.92,
    })
    ev = _line_to_event(line)
    assert ev is not None
    assert ev.scanner == ScannerName.SUBGHZ
    assert ev.kind == EventKind.KEYFOB_EMISSION
    assert ev.features.frequency_hz == 433_920_000
    assert ev.features.protocol == "Honda-CarRemote"
    assert ev.features.decoded["id"] == "0x123ABC"


def test_garage_line_to_event():
    line = json.dumps({
        "time": "2026-05-03 22:41:13",
        "model": "Genie-OverheadDoor",
        "id": "12345",
        "freq": 390.0,
    })
    ev = _line_to_event(line)
    assert ev is not None
    assert ev.kind == EventKind.GARAGE_EMISSION
    assert ev.features.frequency_hz == 390_000_000


def test_unknown_protocol_line_to_event():
    line = json.dumps({
        "time": "2026-05-03 22:41:13",
        "model": "WeatherStationXYZ",
        "freq": 433.92,
    })
    ev = _line_to_event(line)
    assert ev is not None
    assert ev.kind == EventKind.SUBGHZ_PROTOCOL_DECODED


def test_invalid_json_line_returns_none():
    assert _line_to_event("not json at all") is None


def test_non_decoded_status_line_returns_none():
    # rtl_433 sometimes emits status messages — ignore them.
    line = json.dumps({"app": "rtl_433", "version": "23.11"})
    assert _line_to_event(line) is None


async def test_subghz_scanner_consumes_subprocess_lines(monkeypatch):
    """Patch the subprocess to feed canned lines."""
    received = []
    line1 = json.dumps({"model": "Honda-CarRemote", "id": "0xABC", "freq": 433.92})
    line2 = json.dumps({"model": "Genie-OverheadDoor", "id": "55", "freq": 390.0})
    canned = [line1.encode() + b"\n", line2.encode() + b"\n"]

    class FakeStream:
        def __init__(self, lines):
            self._lines = list(lines)

        async def readline(self):
            if self._lines:
                return self._lines.pop(0)
            return b""

    class FakeProc:
        def __init__(self):
            self.stdout = FakeStream(canned)
            self.stderr = FakeStream([])
            self.returncode = None
            self._terminated = False

        def terminate(self):
            self._terminated = True
            self.returncode = 0

        async def wait(self):
            return 0

    async def fake_create_subprocess_exec(*args, **kwargs):
        return FakeProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    s = SubGhzScanner(rtl_433_args=["-F", "json"])
    s.on_event(lambda ev: received.append(ev))
    runner = asyncio.create_task(s.start())
    await asyncio.sleep(0.1)
    await s.stop()
    try:
        await asyncio.wait_for(runner, timeout=1.0)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        runner.cancel()

    assert len(received) == 2
    assert received[0].kind == EventKind.KEYFOB_EMISSION
    assert received[1].kind == EventKind.GARAGE_EMISSION
```

- [ ] **Step 10.2: Run test, verify it fails**

```bash
uv run pytest tests/test_scanners_subghz.py -v
```
Expected: FAIL — `ImportError`.

- [ ] **Step 10.3: Implement scanners/subghz.py**

`src/watchtower/scanners/subghz.py`:
```python
"""Sub-GHz scanner: spawns rtl_433 as a subprocess and parses each JSON line.

Why subprocess: rtl_433 is a mature C implementation with a huge protocol
library. Re-implementing protocol decoders in Python would be wasteful.
We parse its JSON-line output and convert each decode to an Event.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from watchtower.events import Event, EventKind, Features, Scanner as ScannerName
from watchtower.scanners.base import Scanner

log = logging.getLogger(__name__)

# Minimal model->kind classifier. Anything not matched goes to SUBGHZ_PROTOCOL_DECODED.
_KEYFOB_MODELS = (
    "CarRemote", "KeyFob", "Toyota-CarRemote", "Honda-CarRemote",
    "Hyundai-CarRemote", "Renault-CarRemote", "Subaru", "Hyundai",
)
_GARAGE_MODELS = (
    "OverheadDoor", "Genie-OverheadDoor", "GarageDoor", "Liftmaster",
    "Chamberlain", "Marantec", "Stanley",
)


def _classify_kind(model: str) -> EventKind:
    if any(s.lower() in model.lower() for s in _KEYFOB_MODELS):
        return EventKind.KEYFOB_EMISSION
    if any(s.lower() in model.lower() for s in _GARAGE_MODELS):
        return EventKind.GARAGE_EMISSION
    return EventKind.SUBGHZ_PROTOCOL_DECODED


def _line_to_event(line: str) -> Event | None:
    try:
        d: dict[str, Any] = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    model = d.get("model")
    if not isinstance(model, str):
        # rtl_433 emits status/version lines without a model field; ignore.
        return None
    freq_mhz = d.get("freq")
    freq_hz = int(round(freq_mhz * 1_000_000)) if isinstance(freq_mhz, (int, float)) else None
    kind = _classify_kind(model)
    decoded = {k: v for k, v in d.items() if k not in ("time", "freq", "model")}
    feats = Features(
        protocol=model,
        frequency_hz=freq_hz,
        decoded=decoded,
    )
    return Event(scanner=ScannerName.SUBGHZ, kind=kind, features=feats, raw=d)


class SubGhzScanner(Scanner):
    name = ScannerName.SUBGHZ

    def __init__(
        self,
        rtl_433_args: list[str] | None = None,
        device_index: int = 0,
    ) -> None:
        super().__init__()
        self._args = rtl_433_args or ["-F", "json", "-d", str(device_index), "-G", "5"]

    async def run(self) -> None:
        cmd = ["rtl_433", *self._args]
        log.info("subghz: starting rtl_433: %s", " ".join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            assert proc.stdout is not None
            while not self._stop_event.is_set():
                line_bytes = await proc.stdout.readline()
                if not line_bytes:
                    log.warning("subghz: rtl_433 stdout closed")
                    break
                line = line_bytes.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                ev = _line_to_event(line)
                if ev is not None:
                    await self._emit(ev)
        finally:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except (ProcessLookupError, asyncio.TimeoutError):
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
```

- [ ] **Step 10.4: Run test, verify it passes**

```bash
uv run pytest tests/test_scanners_subghz.py -v
```
Expected: 6 passed.

- [ ] **Step 10.5: Commit**

```bash
git add src/watchtower/scanners/subghz.py tests/test_scanners_subghz.py
git commit -m "M1.10: SubGhzScanner — rtl_433 subprocess + JSON line parsing"
```

---

## Task 11: Mid-band scanner (RTL-SDR energy detector)

**Files:**
- Create: `src/watchtower/scanners/midband.py`
- Create: `tests/test_scanners_midband.py`

- [ ] **Step 11.1: Write the failing test**

`tests/test_scanners_midband.py`:
```python
"""Tests for MidbandScanner — RTL-SDR energy sweeper."""
import asyncio

import numpy as np
import pytest

from watchtower.events import EventKind, Scanner as ScannerName
from watchtower.scanners.midband import MidbandScanner, _energy_dbm


def test_energy_dbm_scales_with_amplitude():
    weak = np.full(1024, 0.01 + 0.0j, dtype=np.complex64)
    strong = np.full(1024, 1.0 + 0.0j, dtype=np.complex64)
    assert _energy_dbm(strong) > _energy_dbm(weak)


def test_energy_dbm_returns_finite_for_zero_input():
    z = np.zeros(1024, dtype=np.complex64)
    e = _energy_dbm(z)
    # Zero input: clamp to a safe floor (-200 dBm) instead of -inf.
    assert e == pytest.approx(-200.0, abs=1.0)


async def test_midband_scanner_emits_per_frequency(monkeypatch):
    """Patch RtlSdr to feed canned IQ samples; verify one event per freq."""
    received = []

    class FakeRtlSdr:
        def __init__(self, device_index=0):
            self.device_index = device_index
            self.center_freq = 0
            self.sample_rate = 0
            self.gain = 0

        def read_samples(self, n):
            return np.full(n, 0.5 + 0.0j, dtype=np.complex64)

        def close(self):
            pass

    monkeypatch.setattr("watchtower.scanners.midband.RtlSdr", FakeRtlSdr)

    s = MidbandScanner(
        device_index=1,
        sweep_freqs_hz=[700_000_000, 900_000_000],
        dwell_seconds=0.05,
        sample_rate_hz=2_048_000,
    )
    s.on_event(lambda ev: received.append(ev))
    runner = asyncio.create_task(s.start())
    await asyncio.sleep(0.3)  # enough time for at least one full sweep
    await s.stop()
    runner.cancel()
    try:
        await runner
    except asyncio.CancelledError:
        pass

    # We should have at least one event per configured frequency.
    band_names = {ev.features.band_name for ev in received}
    assert "700MHz" in band_names
    assert "900MHz" in band_names
    for ev in received:
        assert ev.scanner == ScannerName.MIDBAND
        assert ev.kind in (EventKind.CELLULAR_BAND_ENERGY, EventKind.LORA_EMISSION, EventKind.AVIATION_BAND_ENERGY)
        assert ev.features.energy_dbm is not None
```

- [ ] **Step 11.2: Run test, verify it fails**

```bash
uv run pytest tests/test_scanners_midband.py -v
```
Expected: FAIL — `ImportError`. (Also expect `numpy` to be missing; we add it in implementation.)

- [ ] **Step 11.3: Add numpy to deps**

Edit `pyproject.toml`, add to `dependencies`:
```toml
    "numpy>=1.26",
```
Then:
```bash
uv sync
```

- [ ] **Step 11.4: Implement scanners/midband.py**

`src/watchtower/scanners/midband.py`:
```python
"""Mid-band scanner: sweeps a list of frequencies on RTL-SDR and emits energy events.

The point isn't decoding — that's the BLE/WiFi/sub-GHz scanners' job. The
midband scanner produces a quantitative "is there RF activity in this band
right now" signal that the detection layer baselines for anomaly detection.
"""
from __future__ import annotations

import asyncio
import logging
import math

import numpy as np
from rtlsdr import RtlSdr

from watchtower.events import Event, EventKind, Features, Scanner as ScannerName
from watchtower.scanners.base import Scanner

log = logging.getLogger(__name__)

# Map a center freq (Hz) to a friendly band label and event kind.
_BAND_LABELS: list[tuple[int, int, str, EventKind]] = [
    # (low_hz, high_hz, label, kind)
    (108_000_000,  138_000_000, "AviationBand", EventKind.AVIATION_BAND_ENERGY),
    (700_000_000,  799_000_000, "700MHz",       EventKind.CELLULAR_BAND_ENERGY),
    (824_000_000,  894_000_000, "850MHz",       EventKind.CELLULAR_BAND_ENERGY),
    (902_000_000,  928_000_000, "900MHz",       EventKind.LORA_EMISSION),
    (929_000_000,  960_000_000, "GSM900",       EventKind.CELLULAR_BAND_ENERGY),
    (1_563_000_000, 1_587_000_000, "GPS-L1",    EventKind.AVIATION_BAND_ENERGY),
]


def _label_for_freq(freq_hz: int) -> tuple[str, EventKind]:
    for low, high, label, kind in _BAND_LABELS:
        if low <= freq_hz <= high:
            return label, kind
    return "OutOfBand", EventKind.CELLULAR_BAND_ENERGY


def _energy_dbm(iq: np.ndarray) -> float:
    """Mean power of complex IQ samples in dBm (relative; calibration offsets later)."""
    if iq.size == 0:
        return -200.0
    p = float(np.mean(np.abs(iq) ** 2))
    if p <= 0:
        return -200.0
    # 10*log10(p), then arbitrary -30 dB offset to keep typical values negative-dBm-shaped.
    return 10.0 * math.log10(p) - 30.0


class MidbandScanner(Scanner):
    name = ScannerName.MIDBAND

    def __init__(
        self,
        device_index: int = 1,
        sweep_freqs_hz: list[int] | None = None,
        dwell_seconds: float = 5.0,
        sample_rate_hz: int = 2_048_000,
        sample_count: int = 256 * 1024,
    ) -> None:
        super().__init__()
        self._device_index = device_index
        self._freqs = sweep_freqs_hz or [
            734_000_000, 881_000_000, 944_000_000, 1_575_420_000,
        ]
        self._dwell = dwell_seconds
        self._sample_rate = sample_rate_hz
        self._n = sample_count

    async def run(self) -> None:
        try:
            sdr = RtlSdr(device_index=self._device_index)
        except Exception as ex:  # noqa: BLE001
            log.exception("midband: failed to open RTL-SDR device %d", self._device_index)
            raise
        try:
            sdr.sample_rate = self._sample_rate
            sdr.gain = "auto"
            while not self._stop_event.is_set():
                for freq in self._freqs:
                    if self._stop_event.is_set():
                        break
                    sdr.center_freq = freq
                    # Reading samples is a blocking call — run in default executor.
                    iq = await asyncio.get_event_loop().run_in_executor(
                        None, sdr.read_samples, self._n
                    )
                    iq = np.asarray(iq, dtype=np.complex64)
                    e_dbm = _energy_dbm(iq)
                    label, kind = _label_for_freq(freq)
                    ev = Event(
                        scanner=ScannerName.MIDBAND,
                        kind=kind,
                        features=Features(
                            band_name=label,
                            frequency_hz=freq,
                            energy_dbm=e_dbm,
                        ),
                        raw={"sample_rate_hz": self._sample_rate, "n": self._n},
                    )
                    await self._emit(ev)
                    try:
                        await asyncio.wait_for(self._stop_event.wait(), timeout=self._dwell)
                    except asyncio.TimeoutError:
                        pass
        finally:
            try:
                sdr.close()
            except Exception:  # noqa: BLE001
                log.exception("midband: sdr.close failed")
```

- [ ] **Step 11.5: Run test, verify it passes**

```bash
uv run pytest tests/test_scanners_midband.py -v
```
Expected: 3 passed.

- [ ] **Step 11.6: Commit**

```bash
git add src/watchtower/scanners/midband.py tests/test_scanners_midband.py pyproject.toml
git commit -m "M1.11: Midband RTL-SDR energy sweeper across cellular bands"
```

---

## Task 12: WiFi scanner stub (gracefully absent adapter)

**Files:**
- Create: `src/watchtower/scanners/wifi.py`
- Create: `tests/test_scanners_wifi.py`

- [ ] **Step 12.1: Write the failing test**

`tests/test_scanners_wifi.py`:
```python
"""Tests for WiFi scanner — stub mode when no adapter is present."""
import asyncio
from pathlib import Path

import pytest

from watchtower.scanners.wifi import WifiScanner, _adapter_present


def test_adapter_present_returns_false_for_missing_iface(tmp_path: Path):
    # /sys/class/net/<iface> doesn't exist -> False
    assert _adapter_present("zzznonexistent_iface_12345") is False


async def test_wifi_scanner_runs_in_stub_mode_when_iface_missing():
    """If the configured interface doesn't exist, the scanner should
    log a warning and idle without emitting events or crashing."""
    received = []
    s = WifiScanner(interface="zzznonexistent_iface_12345")
    s.on_event(lambda ev: received.append(ev))
    runner = asyncio.create_task(s.start())
    await asyncio.sleep(0.2)
    await s.stop()
    runner.cancel()
    try:
        await runner
    except asyncio.CancelledError:
        pass
    assert received == []  # stub mode emits nothing
```

- [ ] **Step 12.2: Run test, verify it fails**

```bash
uv run pytest tests/test_scanners_wifi.py -v
```
Expected: FAIL — `ImportError`.

- [ ] **Step 12.3: Implement scanners/wifi.py**

`src/watchtower/scanners/wifi.py`:
```python
"""WiFi scanner.

In M1, the USB monitor-mode adapter is not yet on hand. This scanner ships
in stub mode: if `/sys/class/net/<interface>` does not exist, the scanner
logs a warning and idles. Once the adapter is plugged in (and the interface
appears), the next service restart picks up the live capture path.

The live capture path is intentionally minimal in M1 — it records probe
requests and beacons via `scapy`. Deeper protocol features (association
attempts, action frames) are deferred to M2 when there's hardware to test
against.
"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from watchtower.events import Event, EventKind, Features, Scanner as ScannerName
from watchtower.scanners.base import Scanner

log = logging.getLogger(__name__)


def _adapter_present(iface: str) -> bool:
    return Path(f"/sys/class/net/{iface}").exists()


class WifiScanner(Scanner):
    name = ScannerName.WIFI

    def __init__(self, interface: str = "wlan1") -> None:
        super().__init__()
        self._iface = interface

    async def run(self) -> None:
        if not _adapter_present(self._iface):
            log.warning(
                "wifi: interface '%s' not present — running in stub mode "
                "(plug in USB monitor-mode adapter and restart to enable)",
                self._iface,
            )
            await self._stop_event.wait()
            return
        # Live mode is wired up in M2. For now, log and idle.
        log.info(
            "wifi: interface '%s' present but live capture is M2 work — idling",
            self._iface,
        )
        await self._stop_event.wait()
```

- [ ] **Step 12.4: Run test, verify it passes**

```bash
uv run pytest tests/test_scanners_wifi.py -v
```
Expected: 2 passed.

- [ ] **Step 12.5: Commit**

```bash
git add src/watchtower/scanners/wifi.py tests/test_scanners_wifi.py
git commit -m "M1.12: WiFi scanner stub (adapter-absent graceful idle)"
```

---

## Task 13: Config loader + logging setup

**Files:**
- Create: `src/watchtower/config.py`
- Create: `src/watchtower/logging_setup.py`
- Create: `tests/test_config.py`

- [ ] **Step 13.1: Write the failing test**

`tests/test_config.py`:
```python
"""Tests for config loader."""
from pathlib import Path

import pytest

from watchtower.config import Config, load_config


def test_load_config_reads_toml(tmp_path: Path):
    p = tmp_path / "wt.toml"
    p.write_text("""
[storage]
db_path = "/tmp/x.db"
retention_days = 14

[bus]
queue_size = 5000

[logging]
level = "DEBUG"
format = "json"

[scanners.ble]
enabled = false
adapter = "hci1"

[scanners.wifi]
enabled = true
interface = "wlan2"

[scanners.subghz]
enabled = true
device_index = 0
center_freq_hz = 433920000
sample_rate_hz = 2048000
rtl_433_args = ["-F", "json", "-d", "0"]

[scanners.midband]
enabled = true
device_index = 1
sweep_freqs_hz = [700000000, 900000000]
dwell_seconds = 5
sample_rate_hz = 2048000
""", encoding="utf-8")
    cfg = load_config(p)
    assert isinstance(cfg, Config)
    assert cfg.storage.db_path == "/tmp/x.db"
    assert cfg.storage.retention_days == 14
    assert cfg.bus.queue_size == 5000
    assert cfg.logging.level == "DEBUG"
    assert cfg.scanners.ble.enabled is False
    assert cfg.scanners.ble.adapter == "hci1"
    assert cfg.scanners.wifi.interface == "wlan2"
    assert cfg.scanners.subghz.device_index == 0
    assert cfg.scanners.midband.sweep_freqs_hz == [700000000, 900000000]


def test_missing_section_uses_defaults(tmp_path: Path):
    p = tmp_path / "wt.toml"
    p.write_text("[storage]\ndb_path='/tmp/x.db'\n", encoding="utf-8")
    cfg = load_config(p)
    assert cfg.storage.retention_days == 7   # default
    assert cfg.scanners.ble.enabled is True  # default


def test_load_config_missing_file_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "no.toml")
```

- [ ] **Step 13.2: Run test, verify it fails**

```bash
uv run pytest tests/test_config.py -v
```
Expected: FAIL — `ImportError`.

- [ ] **Step 13.3: Implement config.py**

`src/watchtower/config.py`:
```python
"""TOML config loader."""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[no-redef]


@dataclass
class StorageCfg:
    db_path: str = "/var/lib/watchtower/watchtower.db"
    retention_days: int = 7


@dataclass
class BusCfg:
    queue_size: int = 10000


@dataclass
class LoggingCfg:
    level: str = "INFO"
    format: str = "json"


@dataclass
class BleCfg:
    enabled: bool = True
    adapter: str = "hci0"


@dataclass
class WifiCfg:
    enabled: bool = True
    interface: str = "wlan1"


@dataclass
class SubGhzCfg:
    enabled: bool = True
    device_index: int = 0
    center_freq_hz: int = 433_920_000
    sample_rate_hz: int = 2_048_000
    rtl_433_args: list[str] = field(default_factory=lambda: ["-F", "json", "-d", "0", "-G", "5"])


@dataclass
class MidbandCfg:
    enabled: bool = True
    device_index: int = 1
    sweep_freqs_hz: list[int] = field(default_factory=lambda: [
        734_000_000, 881_000_000, 944_000_000, 1_575_420_000,
    ])
    dwell_seconds: float = 5.0
    sample_rate_hz: int = 2_048_000


@dataclass
class ScannersCfg:
    ble: BleCfg = field(default_factory=BleCfg)
    wifi: WifiCfg = field(default_factory=WifiCfg)
    subghz: SubGhzCfg = field(default_factory=SubGhzCfg)
    midband: MidbandCfg = field(default_factory=MidbandCfg)


@dataclass
class Config:
    storage: StorageCfg = field(default_factory=StorageCfg)
    bus: BusCfg = field(default_factory=BusCfg)
    logging: LoggingCfg = field(default_factory=LoggingCfg)
    scanners: ScannersCfg = field(default_factory=ScannersCfg)


def _merge(dataclass_default: Any, raw: dict | None) -> Any:
    if raw is None:
        return dataclass_default
    fields_present = {f for f in raw.keys() if f in dataclass_default.__dataclass_fields__}
    kwargs = {}
    for f in dataclass_default.__dataclass_fields__:
        if f in fields_present:
            kwargs[f] = raw[f]
        else:
            kwargs[f] = getattr(dataclass_default, f)
    return type(dataclass_default)(**kwargs)


def load_config(path: Path | str) -> Config:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"config not found: {p}")
    with p.open("rb") as f:
        raw = tomllib.load(f)
    sc_raw = raw.get("scanners", {})
    return Config(
        storage=_merge(StorageCfg(), raw.get("storage")),
        bus=_merge(BusCfg(), raw.get("bus")),
        logging=_merge(LoggingCfg(), raw.get("logging")),
        scanners=ScannersCfg(
            ble=_merge(BleCfg(), sc_raw.get("ble")),
            wifi=_merge(WifiCfg(), sc_raw.get("wifi")),
            subghz=_merge(SubGhzCfg(), sc_raw.get("subghz")),
            midband=_merge(MidbandCfg(), sc_raw.get("midband")),
        ),
    )
```

- [ ] **Step 13.4: Implement logging_setup.py**

`src/watchtower/logging_setup.py`:
```python
"""structlog-based JSON logging setup."""
from __future__ import annotations

import logging
import sys

import structlog


def setup_logging(level: str = "INFO", fmt: str = "json") -> None:
    log_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )
    processors: list = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    if fmt == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        cache_logger_on_first_use=True,
    )
```

- [ ] **Step 13.5: Run test, verify it passes**

```bash
uv run pytest tests/test_config.py -v
```
Expected: 3 passed.

- [ ] **Step 13.6: Commit**

```bash
git add src/watchtower/config.py src/watchtower/logging_setup.py tests/test_config.py
git commit -m "M1.13: TOML config loader + structlog setup"
```

---

## Task 14: CLI runner + supervisor

**Files:**
- Create: `src/watchtower/cli.py`
- Create: `tests/test_cli.py`

- [ ] **Step 14.1: Write the failing test**

`tests/test_cli.py`:
```python
"""Tests for CLI: db init and run subcommands."""
import sqlite3
from pathlib import Path

from click.testing import CliRunner

from watchtower.cli import main


def test_cli_db_init_creates_schema(tmp_path: Path):
    db = tmp_path / "wt.db"
    runner = CliRunner()
    result = runner.invoke(main, ["db", "init", "--db", str(db)])
    assert result.exit_code == 0, result.output
    assert db.exists()
    with sqlite3.connect(db) as conn:
        v = conn.execute("SELECT version FROM schema_meta").fetchone()
    assert v[0] == 1


def test_cli_help_lists_run_subcommand():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert "run" in result.output
    assert "db" in result.output
```

- [ ] **Step 14.2: Run test, verify it fails**

```bash
uv run pytest tests/test_cli.py -v
```
Expected: FAIL — `ImportError`.

- [ ] **Step 14.3: Implement cli.py**

`src/watchtower/cli.py`:
```python
"""Watchtower CLI entrypoint."""
from __future__ import annotations

import asyncio
import logging
import signal
from pathlib import Path

import click

from watchtower.bus import Bus
from watchtower.config import load_config
from watchtower.logging_setup import setup_logging
from watchtower.scanners.ble import BleScanner
from watchtower.scanners.midband import MidbandScanner
from watchtower.scanners.subghz import SubGhzScanner
from watchtower.scanners.wifi import WifiScanner
from watchtower.sinks.local import LocalSink
from watchtower.storage.db import init_db
from watchtower.storage.pruner import prune_older_than

log = logging.getLogger(__name__)


@click.group()
def main() -> None:
    """Watchtower — perimeter RF awareness daemon."""


@main.group()
def db() -> None:
    """Database operations."""


@db.command("init")
@click.option("--db", "db_path", type=click.Path(), required=True, help="SQLite path")
def db_init(db_path: str) -> None:
    """Create the watchtower SQLite schema (idempotent)."""
    init_db(Path(db_path))
    click.echo(f"OK: {db_path}")


@main.command("run")
@click.option("--config", "config_path", type=click.Path(exists=True), required=True)
def run(config_path: str) -> None:
    """Start scanners and sink as a long-lived service."""
    asyncio.run(_run_async(Path(config_path)))


async def _run_async(config_path: Path) -> None:
    cfg = load_config(config_path)
    setup_logging(level=cfg.logging.level, fmt=cfg.logging.format)
    log.info("watchtower starting; config=%s", config_path)

    init_db(cfg.storage.db_path)

    bus = Bus(queue_size=cfg.bus.queue_size)
    sink = LocalSink(cfg.storage.db_path, batch_size=100, flush_interval=1.0)
    bus.subscribe(lambda ev: asyncio.ensure_future(sink.write(ev)))
    await sink.start()

    scanners = []
    if cfg.scanners.ble.enabled:
        scanners.append(BleScanner(adapter=cfg.scanners.ble.adapter))
    if cfg.scanners.wifi.enabled:
        scanners.append(WifiScanner(interface=cfg.scanners.wifi.interface))
    if cfg.scanners.subghz.enabled:
        scanners.append(SubGhzScanner(
            rtl_433_args=cfg.scanners.subghz.rtl_433_args,
            device_index=cfg.scanners.subghz.device_index,
        ))
    if cfg.scanners.midband.enabled:
        scanners.append(MidbandScanner(
            device_index=cfg.scanners.midband.device_index,
            sweep_freqs_hz=cfg.scanners.midband.sweep_freqs_hz,
            dwell_seconds=cfg.scanners.midband.dwell_seconds,
            sample_rate_hz=cfg.scanners.midband.sample_rate_hz,
        ))

    for s in scanners:
        s.on_event(lambda ev: asyncio.ensure_future(bus.publish(ev)))

    stop = asyncio.Event()

    def _signal_handler(signum: int) -> None:
        log.info("received signal %d, shutting down", signum)
        stop.set()

    loop = asyncio.get_running_loop()
    for s in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(s, _signal_handler, int(s))
        except NotImplementedError:
            # Windows
            signal.signal(s, lambda *a: stop.set())

    pruner_task = asyncio.create_task(_pruner_loop(stop, cfg.storage.db_path, cfg.storage.retention_days))
    scanner_tasks = [asyncio.create_task(s.start()) for s in scanners]

    await stop.wait()
    log.info("watchtower stopping scanners…")
    for s in scanners:
        await s.stop()
    for t in scanner_tasks:
        t.cancel()
    pruner_task.cancel()
    try:
        await pruner_task
    except asyncio.CancelledError:
        pass
    await sink.stop()
    await bus.shutdown()
    log.info("watchtower stopped")


async def _pruner_loop(stop: asyncio.Event, db_path: str, retention_days: int) -> None:
    """Run the retention pruner once an hour."""
    interval = 3600
    while not stop.is_set():
        try:
            n = await asyncio.get_event_loop().run_in_executor(
                None, prune_older_than, db_path, retention_days * 86400
            )
            if n:
                log.info("pruner deleted %d events", n)
        except Exception:  # noqa: BLE001
            log.exception("pruner failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass
```

- [ ] **Step 14.4: Run test, verify it passes**

```bash
uv run pytest tests/test_cli.py -v
```
Expected: 2 passed.

- [ ] **Step 14.5: Run all tests**

```bash
uv run pytest -v
```
Expected: all green (~30 tests).

- [ ] **Step 14.6: Commit**

```bash
git add src/watchtower/cli.py tests/test_cli.py
git commit -m "M1.14: CLI entry — 'watchtower db init' and 'watchtower run'"
```

---

## Task 15: systemd unit + deploy script

**Files:**
- Create: `deploy/watchtower.service`
- Create: `deploy/deploy.sh`

- [ ] **Step 15.1: Write the systemd unit**

`deploy/watchtower.service`:
```ini
[Unit]
Description=Watchtower RF perimeter awareness daemon
After=network-online.target bluetooth.service
Wants=network-online.target

[Service]
Type=simple
User=admin
Group=admin
WorkingDirectory=/opt/watchtower
ExecStart=/opt/watchtower/.venv/bin/watchtower run --config /etc/watchtower/watchtower.toml
Restart=on-failure
RestartSec=5
StandardOutput=append:/var/log/watchtower/watchtower.log
StandardError=append:/var/log/watchtower/watchtower.err

# Security hardening (loosened for hardware access).
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
# Bluetooth + USB SDR access requires non-restricted device groups.
SupplementaryGroups=bluetooth plugdev

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 15.2: Write deploy script**

`deploy/deploy.sh`:
```bash
#!/usr/bin/env bash
# Deploy Watchtower to the Pi from the Windows host.
# Usage: ./deploy/deploy.sh [hostname]
set -euo pipefail

HOST="${1:-watchtower.local}"
USER_=admin
APP_DIR=/opt/watchtower
SVC=watchtower.service

echo "[+] rsync source -> $HOST:$APP_DIR"
ssh "$USER_@$HOST" "sudo install -d -o $USER_ -g $USER_ $APP_DIR"
rsync -az --delete \
  --exclude '.venv' --exclude '__pycache__' --exclude '.pytest_cache' \
  --exclude '*.db' --exclude '.git' \
  ./ "$USER_@$HOST:$APP_DIR/"

echo "[+] (re)creating venv and installing project"
ssh "$USER_@$HOST" "cd $APP_DIR && \
  if ! command -v uv >/dev/null 2>&1; then \
    curl -LsSf https://astral.sh/uv/install.sh | sh; \
    export PATH=\"\$HOME/.local/bin:\$PATH\"; \
  fi; \
  uv venv && uv sync --frozen 2>/dev/null || uv sync"

echo "[+] installing config (only if not already present)"
ssh "$USER_@$HOST" "test -f /etc/watchtower/watchtower.toml || \
  sudo cp $APP_DIR/config/watchtower.example.toml /etc/watchtower/watchtower.toml; \
  sudo chown $USER_:$USER_ /etc/watchtower/watchtower.toml"

echo "[+] installing systemd unit"
ssh "$USER_@$HOST" "sudo cp $APP_DIR/deploy/$SVC /etc/systemd/system/$SVC && \
  sudo systemctl daemon-reload && \
  sudo systemctl enable $SVC"

echo "[+] (re)starting service"
ssh "$USER_@$HOST" "sudo systemctl restart $SVC"
sleep 3
ssh "$USER_@$HOST" "systemctl is-active $SVC && \
  sudo journalctl -u $SVC -n 30 --no-pager"

echo "[+] deployed."
```

- [ ] **Step 15.3: Make deploy.sh executable**

```bash
chmod +x /c/Users/ihass/watchtower/deploy/deploy.sh
```

- [ ] **Step 15.4: First deploy to Pi**

Run on Windows:
```bash
cd /c/Users/ihass/watchtower
./deploy/deploy.sh watchtower.local
```
Expected: Pi has the project at `/opt/watchtower`, venv installed, service enabled and running.

(Note: this step requires user-confirmed sudo on the Pi the first time — interactive password.)

- [ ] **Step 15.5: Verify service is running**

```bash
ssh admin@watchtower.local "systemctl is-active watchtower && \
  sudo journalctl -u watchtower -n 50 --no-pager"
```
Expected: `active`, log shows scanners starting (BLE adverts, midband sweep events, possibly subghz events depending on environment).

- [ ] **Step 15.6: Commit**

```bash
cd /c/Users/ihass/watchtower
git add deploy/watchtower.service deploy/deploy.sh
git commit -m "M1.15: systemd unit + rsync-based deploy script"
```

---

## Task 16: Pi smoke test (integration)

**Files:**
- Create: `tests/integration/__init__.py`
- Create: `tests/integration/conftest.py`
- Create: `tests/integration/test_pi_smoke.py`

- [ ] **Step 16.1: Write integration test**

`tests/integration/__init__.py`: empty file.

`tests/integration/conftest.py`:
```python
"""Integration test config — only run when WATCHTOWER_PI_HOST is set."""
import os

import pytest


@pytest.fixture(scope="session")
def pi_host() -> str:
    h = os.environ.get("WATCHTOWER_PI_HOST")
    if not h:
        pytest.skip("set WATCHTOWER_PI_HOST=watchtower.local to run integration tests")
    return h
```

`tests/integration/test_pi_smoke.py`:
```python
"""Live smoke test against the running Pi service.

Prereq:
  - `./deploy/deploy.sh` ran successfully
  - WATCHTOWER_PI_HOST=watchtower.local
"""
import json
import subprocess
import time

import pytest

pytestmark = pytest.mark.integration


def _ssh(host: str, cmd: str) -> str:
    r = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", f"admin@{host}", cmd],
        capture_output=True, text=True, timeout=30,
    )
    if r.returncode != 0:
        raise AssertionError(f"ssh failed: {r.stderr}")
    return r.stdout


def test_service_active(pi_host: str):
    out = _ssh(pi_host, "systemctl is-active watchtower")
    assert out.strip() == "active"


def test_service_logs_scanners_started(pi_host: str):
    out = _ssh(pi_host, "sudo journalctl -u watchtower -n 200 --no-pager")
    assert "watchtower starting" in out


def test_db_exists_and_has_schema(pi_host: str):
    out = _ssh(pi_host, "sqlite3 /var/lib/watchtower/watchtower.db 'SELECT version FROM schema_meta;'")
    assert out.strip() == "1"


def test_ble_events_after_60s(pi_host: str):
    """After a minute of running, BLE events should be present (assumes
    at least one Bluetooth device — phone, headphones, etc — within range)."""
    # Wait for runtime to accumulate.
    time.sleep(60)
    out = _ssh(pi_host, "sqlite3 /var/lib/watchtower/watchtower.db \"SELECT COUNT(*) FROM raw_events WHERE scanner='ble_scanner';\"")
    n = int(out.strip())
    assert n > 0, "no BLE events captured after 60s — verify a BLE device is in range and bluetooth group is set"


def test_midband_events_after_60s(pi_host: str):
    out = _ssh(pi_host, "sqlite3 /var/lib/watchtower/watchtower.db \"SELECT COUNT(*) FROM raw_events WHERE scanner='midband_scanner';\"")
    n = int(out.strip())
    assert n > 0, "no midband events — RTL-SDR may not be visible to admin (check udev rules)"


def test_pruner_doesnt_crash(pi_host: str):
    # Service is up and the DB exists — just confirm the pruner ran or is queued.
    out = _ssh(pi_host, "sudo journalctl -u watchtower -n 500 --no-pager")
    # Either the pruner has logged a delete OR the log shows no pruner errors.
    assert "pruner failed" not in out
```

- [ ] **Step 16.2: Run integration tests against Pi**

```bash
cd /c/Users/ihass/watchtower
WATCHTOWER_PI_HOST=watchtower.local uv run pytest tests/integration -v -m integration
```
Expected: 6 passed (after 60s wait for BLE/midband events).

If `test_ble_events_after_60s` fails, check:
- Is `admin` in the `bluetooth` group? `ssh admin@watchtower.local "groups"` should include `bluetooth`. If not, run `sudo usermod -aG bluetooth admin && sudo systemctl restart watchtower`.
- Is there a Bluetooth device powered on within ~10m? Phone with BT enabled, headphones, etc.

If `test_midband_events_after_60s` fails, check:
- udev rule installed: `ls -la /etc/udev/rules.d/20-rtlsdr.rules`
- Both dongles enumerate: `ssh admin@watchtower.local "rtl_test -t 2>&1 | head -5"`
- Service logs show midband errors: `ssh admin@watchtower.local "sudo journalctl -u watchtower -n 100"`

- [ ] **Step 16.3: Commit**

```bash
git add tests/integration
git commit -m "M1.16: Pi smoke integration tests (BLE + midband + pruner)"
```

---

## Task 17: README quickstart + final verification

**Files:**
- Modify: `C:\Users\ihass\watchtower\README.md`

- [ ] **Step 17.1: Replace README contents**

`C:\Users\ihass\watchtower\README.md`:
```markdown
# Watchtower

Perimeter RF awareness layer for residential pre-intrusion casing detection
and 7-day forensic timeline. Single-Pi deployment, fully passive.

- Spec: `docs/superpowers/specs/2026-05-03-watchtower-design.md`
- Implementation plans: `docs/superpowers/plans/`

## Status

**Milestone 1 (capture + storage) — implemented.** Next: M2 resolver +
enrichment + home_state.

## Quickstart

### Develop (Windows host)

```bash
cd /c/Users/ihass/watchtower
uv sync
uv run pytest -v
```

### Deploy to the Pi

The Pi must already have `pi-setup.sh` run once. Then from the Windows host:

```bash
./deploy/deploy.sh watchtower.local
```

This rsyncs source, installs a uv venv on the Pi, drops a default config to
`/etc/watchtower/watchtower.toml`, and starts the systemd service.

### Verify on the Pi

```bash
ssh admin@watchtower.local
systemctl is-active watchtower
sudo journalctl -u watchtower -f
sqlite3 /var/lib/watchtower/watchtower.db \
  "SELECT scanner, COUNT(*) FROM raw_events GROUP BY scanner;"
```

### Run integration tests against the Pi

```bash
WATCHTOWER_PI_HOST=watchtower.local uv run pytest tests/integration -v -m integration
```

## Architecture

See the spec. Briefly:

```
HARDWARE   Pi 5 16GB · built-in BLE · USB WiFi (M2) · 2× RTL-SDR

CAPTURE    ble_scanner · wifi_scanner (stub) · subghz_scanner (rtl_433) ·
           midband_scanner (RTL-SDR energy sweep)
                ↓ uniform Event envelope on local bus
ENRICHMENT (M2)
DETECTION  (M3)
OUTPUT     LocalSink → SQLite (7-day retention)
```

## Configuration

All settings live in `/etc/watchtower/watchtower.toml`. See
`config/watchtower.example.toml` for a documented default.
```

- [ ] **Step 17.2: Run all tests and full build verification**

```bash
cd /c/Users/ihass/watchtower
uv run pytest -v
WATCHTOWER_PI_HOST=watchtower.local uv run pytest tests/integration -v -m integration
```
Expected: all green; integration tests pass against the live Pi.

- [ ] **Step 17.3: Commit and tag M1**

```bash
git add README.md
git commit -m "M1.17: README quickstart"
git tag -a m1-capture-storage -m "M1: capture + storage complete"
git log --oneline | head -20
```
Expected: 17 commits + 1 tag.

---

## M1 done — ready for M2

Working software at this milestone:
- Pi 5 runs `watchtower.service` 24/7
- 4 scanners (BLE live, WiFi stub, sub-GHz live, midband live) capture events
- Events stored in SQLite with 7-day retention pruner
- Configurable via `/etc/watchtower/watchtower.toml`
- Deployable from Windows host via `./deploy/deploy.sh watchtower.local`
- Integration tests verify the live system

What you can do now:
```sql
-- Most-seen MACs in last hour
SELECT json_extract(features_json, '$.mac') AS mac, COUNT(*) AS n
FROM raw_events WHERE ts_unix > strftime('%s','now') - 3600
GROUP BY mac ORDER BY n DESC LIMIT 20;

-- Event rates per scanner
SELECT scanner, COUNT(*) AS n FROM raw_events GROUP BY scanner;

-- Recent decoded sub-GHz protocols
SELECT json_extract(features_json, '$.protocol') AS proto, COUNT(*)
FROM raw_events WHERE scanner='subghz_scanner' GROUP BY proto;
```

**Next milestone (M2)** — `device_resolver`, `enrichment_engine`, `presence_engine`, `home_state` model. Will be planned in `2026-MM-DD-m2-resolver-enrichment.md` once M1 is verified in production for a few days.
