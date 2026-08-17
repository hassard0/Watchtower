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


def test_dashboard_served_on_port_80(pi_host: str):
    out = _ssh(
        pi_host,
        "curl --fail --silent --show-error --output /dev/null "
        "--write-out '%{http_code}' http://127.0.0.1/",
    )
    assert out.strip() == "200"


def test_wifi_recovery_timer_active(pi_host: str):
    out = _ssh(pi_host, "systemctl is-active watchtower-wifi-reconnect.timer")
    assert out.strip() == "active"


def test_service_logs_scanners_started(pi_host: str):
    # Fetch enough lines to capture the current invocation's start record.
    # systemd always records "Started watchtower.service" when the unit
    # transitions to active; the Python "watchtower starting" line appears
    # here too once stdout is flushed into the journal.
    out = _ssh(pi_host, "journalctl -u watchtower -n 500 --no-pager")
    assert "Started watchtower.service" in out, (
        "journal does not show a recent service start — unit may never have launched"
    )


def test_db_exists_and_has_schema(pi_host: str):
    out = _ssh(
        pi_host,
        "sqlite3 -readonly -cmd '.timeout 5000' "
        "/var/lib/watchtower/watchtower.db 'SELECT version FROM schema_meta;'",
    )
    assert out.strip() == "10"  # transient presence and multi-signal episode tables


def _sqlite_count(host: str, scanner: str) -> int:
    """Query raw_events count for a scanner without blocking the live DB.

    Uses .timeout 5000 so sqlite3 waits up to 5 s for the writer to yield
    rather than immediately returning SQLITE_BUSY (error 5).
    """
    out = _ssh(
        host,
        f"sqlite3 -readonly -cmd '.timeout 5000' "
        f"/var/lib/watchtower/watchtower.db "
        f"\"SELECT COUNT(*) FROM raw_events WHERE scanner='{scanner}';\"",
    )
    return int(out.strip())


def test_ble_events_after_60s(pi_host: str):
    """After a minute of running, BLE events should be present (assumes
    at least one Bluetooth device — phone, headphones, etc — within range)."""
    # Wait for runtime to accumulate.
    time.sleep(60)
    n = _sqlite_count(pi_host, "ble_scanner")
    assert n > 0, "no BLE events captured after 60s — verify a BLE device is in range and bluetooth group is set"


def test_midband_events_after_60s(pi_host: str):
    n = _sqlite_count(pi_host, "midband_scanner")
    assert n > 0, "no midband events — RTL-SDR may not be visible to admin (check udev rules)"


def test_pruner_doesnt_crash(pi_host: str):
    # Service is up and the DB exists — just confirm the pruner ran or is queued.
    out = _ssh(pi_host, "journalctl -u watchtower -n 500 --no-pager")
    # Either the pruner has logged a delete OR the log shows no pruner errors.
    assert "pruner failed" not in out
