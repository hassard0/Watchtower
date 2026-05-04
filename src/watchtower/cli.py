"""Watchtower CLI entrypoint."""
from __future__ import annotations

import asyncio
import logging
import signal
from pathlib import Path

import click

from watchtower.analytics import Analytics
from watchtower.api import ApiServer
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
        scanners.append(WifiScanner(
            interface=cfg.scanners.wifi.interface,
            scan_interval_sec=cfg.scanners.wifi.scan_interval_sec,
        ))
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
    analytics_task = asyncio.create_task(_analytics_loop(stop, cfg.storage.db_path))
    scanner_tasks = [asyncio.create_task(s.start()) for s in scanners]

    api = ApiServer(cfg.storage.db_path, host="0.0.0.0", port=8080)
    await api.start()

    await stop.wait()
    log.info("watchtower stopping scanners…")
    for s in scanners:
        await s.stop()
    for t in scanner_tasks:
        t.cancel()
    for t in (pruner_task, analytics_task):
        t.cancel()
        try:
            await t
        except asyncio.CancelledError:
            pass
    await api.stop()
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
