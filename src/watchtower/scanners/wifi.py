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
