"""Watchtower CLI entrypoint."""
from __future__ import annotations

import asyncio
import logging
import signal
from pathlib import Path

import click

from watchtower.active_probe import GattProber
from watchtower.analytics import Analytics, load_settings
from watchtower.api import ApiServer
from watchtower.findmy_tracker import FindMyTracker
from watchtower.honeypot import Honeypot
from watchtower.bus import Bus
from watchtower.config import load_config
from watchtower.logging_setup import setup_logging
from watchtower.local_discovery import LocalIdentityDiscovery
from watchtower.scanners.base import Scanner
from watchtower.scanners.ble import BleScanner
from watchtower.scanners.midband import MidbandScanner
from watchtower.scanners.subghz import SubGhzScanner
from watchtower.scanners.wifi import WifiScanner
from watchtower.sinks.local import LocalSink
from watchtower.storage.db import init_db
from watchtower.storage.pruner import prune_older_than
from watchtower.sub_decoder import SubDecoder, reap_old_captures

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
    ble_scanner: BleScanner | None = None
    if cfg.scanners.ble.enabled:
        ble_scanner = BleScanner(adapter=cfg.scanners.ble.adapter)
        scanners.append(ble_scanner)
    if cfg.scanners.wifi.enabled:
        scanners.append(WifiScanner(
            interface=cfg.scanners.wifi.interface,
            scan_interval_sec=cfg.scanners.wifi.scan_interval_sec,
        ))
    if cfg.scanners.subghz.enabled:
        scanners.append(SubGhzScanner(
            rtl_433_args=cfg.scanners.subghz.rtl_433_args,
            device_index=cfg.scanners.subghz.device_index,
        ))
    # Offline sub-GHz protocol decoder. Midband captures IQ when energy at a
    # <1 GHz freq spikes; this worker pops those captures and runs rtl_433
    # against them. Resulting events flow into the same bus as the other
    # scanners and land in raw_events tagged scanner=subghz_scanner.
    sub_decoder: SubDecoder | None = None
    capture_dir = Path(cfg.storage.db_path).parent / "sub_captures"
    reap_old_captures(capture_dir)
    if cfg.scanners.midband.enabled:
        sub_decoder = SubDecoder(on_event=lambda ev: bus.publish(ev))
        scanners.append(MidbandScanner(
            device_index=cfg.scanners.midband.device_index,
            sweep_freqs_hz=cfg.scanners.midband.sweep_freqs_hz,
            dwell_seconds=cfg.scanners.midband.dwell_seconds,
            sample_rate_hz=cfg.scanners.midband.sample_rate_hz,
            capture_dir=capture_dir,
            capture_callback=sub_decoder.submit,
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
    analytics_task = asyncio.create_task(_analytics_loop(stop, cfg.storage.db_path))
    scanner_tasks = [asyncio.create_task(_scanner_loop(s, stop)) for s in scanners]
    sub_decoder_task = asyncio.create_task(sub_decoder.run()) if sub_decoder else None

    # Active GATT prober — toggle-able via settings.active_probing_enabled.
    pause_factory = (lambda: ble_scanner.pause_for_probe()) if ble_scanner else None
    gatt_prober = GattProber(
        cfg.storage.db_path,
        adapter=cfg.scanners.ble.adapter,
        enabled_check=lambda: bool(load_settings(cfg.storage.db_path).get("active_probing_enabled")),
        pause_scanner_factory=pause_factory,
    )
    prober_task = asyncio.create_task(gatt_prober.run(stop))

    # BLE lure honeypot — toggle-able via settings.honeypot_enabled.
    def _hp_enabled():
        return bool(load_settings(cfg.storage.db_path).get("honeypot_enabled"))
    def _hp_rotate_min():
        return float(load_settings(cfg.storage.db_path).get("honeypot_rotate_minutes") or 30)
    honeypot = Honeypot(cfg.storage.db_path, enabled_check=_hp_enabled,
                        rotate_minutes_check=_hp_rotate_min)
    honeypot_task = asyncio.create_task(honeypot.run(stop))

    # OpenHaystack-style Pi-as-AirTag broadcaster.
    findmy_tracker = FindMyTracker(
        cfg.storage.db_path,
        enabled_check=lambda: bool(load_settings(cfg.storage.db_path).get("findmy_tracker_enabled")),
        honeypot_check=_hp_enabled,
    )
    findmy_task = asyncio.create_task(findmy_tracker.run(stop))

    identity_discovery = LocalIdentityDiscovery(
        cfg.storage.db_path, settings_getter=lambda: load_settings(cfg.storage.db_path),
        pause_scanner_factory=pause_factory,
    )
    identity_task = asyncio.create_task(identity_discovery.run(stop))

    api = ApiServer(cfg.storage.db_path, host=cfg.api.host, port=cfg.api.port)
    api.set_findmy_tracker(findmy_tracker)
    api.set_ble_adapter(cfg.scanners.ble.adapter)
    api.set_pause_scanner_factory(pause_factory)
    await api.start()

    await stop.wait()
    log.info("watchtower stopping scanners…")
    for s in scanners:
        await s.stop()
    for t in scanner_tasks:
        t.cancel()
    for t in scanner_tasks:
        try:
            await t
        except asyncio.CancelledError:
            pass
    if sub_decoder is not None:
        await sub_decoder.stop()
    tasks_to_cancel = [pruner_task, analytics_task, prober_task, honeypot_task, findmy_task, identity_task]
    if sub_decoder_task is not None:
        tasks_to_cancel.append(sub_decoder_task)
    for t in tasks_to_cancel:
        t.cancel()
        try:
            await t
        except asyncio.CancelledError:
            pass
    await api.stop()
    await sink.stop()
    await bus.shutdown()
    log.info("watchtower stopped")


async def _scanner_loop(scanner: Scanner, stop: asyncio.Event, retry_sec: float = 10.0) -> None:
    """Keep an individual scanner alive across transient hardware failures."""
    while not stop.is_set():
        try:
            await scanner.start()
            if not stop.is_set():
                log.warning("%s stopped unexpectedly; retrying in %.0fs", scanner.name.value, retry_sec)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("%s crashed; retrying in %.0fs", scanner.name.value, retry_sec)
        if stop.is_set():
            break
        try:
            await asyncio.wait_for(stop.wait(), timeout=retry_sec)
        except asyncio.TimeoutError:
            pass


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


async def _analytics_loop(stop: asyncio.Event, db_path: str) -> None:
    """Roll up raw events into entities/visits/baseline/alerts every 30s."""
    interval = 30
    analytics = Analytics(db_path)
    while not stop.is_set():
        try:
            summary = await asyncio.get_event_loop().run_in_executor(None, analytics.step)
            if summary.get("processed"):
                log.info("analytics: processed=%d entities_touched=%d",
                         summary["processed"], summary["entities_touched"])
        except Exception:  # noqa: BLE001
            log.exception("analytics failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass
