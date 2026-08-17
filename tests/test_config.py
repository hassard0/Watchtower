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

[api]
host = "127.0.0.1"
port = 8088

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
    assert cfg.api.host == "127.0.0.1"
    assert cfg.api.port == 8088
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
    assert cfg.api.port == 80                # default
    assert cfg.scanners.ble.enabled is True  # default


def test_load_config_missing_file_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "no.toml")


def test_deployment_example_keeps_plain_http_on_loopback():
    example = Path(__file__).parents[1] / "config" / "watchtower.example.toml"
    cfg = load_config(example)
    assert cfg.api.host == "127.0.0.1"
    assert cfg.api.port == 8080
