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
    interface: str = "wlan0"
    scan_interval_sec: float = 30.0


@dataclass
class SubGhzCfg:
    enabled: bool = True
    device_index: int = 0
    center_freq_hz: int = 433_920_000
    sample_rate_hz: int = 2_048_000
    rtl_433_args: list[str] = field(default_factory=lambda: ["-F", "json", "-d", "0"])


@dataclass
class MidbandCfg:
    enabled: bool = True
    device_index: int = 1
    sweep_freqs_hz: list[int] = field(default_factory=lambda: [
        # 22-band wide-band sweep — see DEFAULT_SWEEP_FREQS_HZ in scanners/midband.py
        25_000_000, 98_000_000, 122_000_000, 146_000_000, 155_000_000,
        162_550_000, 195_000_000, 315_000_000, 433_920_000, 462_500_000,
        488_000_000, 617_000_000, 734_000_000, 881_000_000, 915_000_000,
        944_000_000, 1_090_000_000, 1_227_000_000, 1_350_000_000,
        1_575_420_000, 1_602_000_000, 1_675_000_000,
    ])
    dwell_seconds: float = 1.0
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
