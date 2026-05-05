"""WiFi scanner.

Pi 5's built-in wlan0 doesn't have stable monitor-mode support, so this scanner
uses **active scanning** via `iw dev <iface> scan` to enumerate nearby APs.
This is non-destructive: the Pi briefly switches channels but stays associated
to its home AP. Returns full scan results: BSSID, SSID, channel, signal,
flags, capabilities.

Falls back to:
- stub mode (idle) when the configured interface doesn't exist
- error mode (logs and idles) when `iw` isn't installed

Future: when a USB monitor-mode adapter is added, this can be replaced with a
true passive monitor capture via scapy.
"""
from __future__ import annotations

import asyncio
import logging
import re
import shutil
from pathlib import Path

from watchtower.events import Event, EventKind, Features, Scanner as ScannerName
from watchtower.scanners.base import Scanner

log = logging.getLogger(__name__)


def _adapter_present(iface: str) -> bool:
    return Path(f"/sys/class/net/{iface}").exists()


_BSS_LINE = re.compile(r"^BSS\s+([0-9a-f:]+)", re.IGNORECASE)


def _parse_iw_scan(output: str) -> list[dict]:
    """Parse `iw dev X scan` output into a list of AP dicts."""
    aps: list[dict] = []
    cur: dict | None = None
    for line in output.splitlines():
        m = _BSS_LINE.match(line.strip())
        if m:
            if cur:
                aps.append(cur)
            cur = {"bssid": m.group(1).lower(), "ssid": None, "channel": None,
                   "signal": None, "freq": None, "encryption": None}
            continue
        if cur is None:
            continue
        s = line.strip()
        if s.startswith("SSID:"):
            cur["ssid"] = s.split(":", 1)[1].strip() or None
        elif s.startswith("freq:"):
            try:
                cur["freq"] = int(float(s.split(":", 1)[1].strip()))
            except ValueError:
                pass
        elif s.startswith("signal:"):
            try:
                cur["signal"] = float(s.split(":", 1)[1].strip().split()[0])
            except (ValueError, IndexError):
                pass
        elif s.startswith("DS Parameter set: channel"):
            try:
                cur["channel"] = int(s.split("channel")[1].strip())
            except (ValueError, IndexError):
                pass
        elif s.startswith("RSN:"):
            cur["encryption"] = "WPA2"
        elif s.startswith("WPA:"):
            cur["encryption"] = cur.get("encryption") or "WPA"
    if cur:
        aps.append(cur)
    return aps


def _is_random_bssid(mac: str) -> bool:
    try:
        first = int(mac.split(":")[0], 16)
    except (IndexError, ValueError):
        return False
    return bool(first & 0x02)


class WifiScanner(Scanner):
    name = ScannerName.WIFI

    def __init__(self, interface: str = "wlan0", scan_interval_sec: float = 30.0) -> None:
        super().__init__()
        self._iface = interface
        self._interval = scan_interval_sec

    async def run(self) -> None:
        if not _adapter_present(self._iface):
            log.warning("wifi: interface '%s' not present — running in stub mode", self._iface)
            await self._stop_event.wait()
            return
        if not shutil.which("iw"):
            log.warning("wifi: 'iw' command not installed — running in stub mode")
            await self._stop_event.wait()
            return

        log.info("wifi: active-scanning via 'iw dev %s scan' every %ds",
                 self._iface, int(self._interval))
        while not self._stop_event.is_set():
            try:
                proc = await asyncio.create_subprocess_exec(
                    "iw", "dev", self._iface, "scan",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15.0)
                except asyncio.TimeoutError:
                    proc.kill()
                    log.warning("wifi: scan timed out")
                    await self._wait_or_stop(self._interval)
                    continue
                if proc.returncode != 0:
                    err = stderr.decode("utf-8", errors="replace").strip()
                    log.warning("wifi: iw scan failed (rc=%d): %s", proc.returncode, err[:200])
                    await self._wait_or_stop(self._interval)
                    continue
                aps = _parse_iw_scan(stdout.decode("utf-8", errors="replace"))
                from watchtower.oui import vendor_for_mac
                for ap in aps:
                    feats = Features(
                        mac=ap.get("bssid"),
                        rssi=int(ap["signal"]) if ap.get("signal") is not None else None,
                        is_random_mac=_is_random_bssid(ap["bssid"]) if ap.get("bssid") else None,
                        local_name=ap.get("ssid"),
                        frequency_hz=ap.get("freq") and ap["freq"] * 1_000_000,
                        vendor_oui=vendor_for_mac(ap.get("bssid") or ""),
                    )
                    feats.decoded = {
                        "ssid": ap.get("ssid"),
                        "channel": ap.get("channel"),
                        "encryption": ap.get("encryption"),
                    }
                    ev = Event(
                        scanner=ScannerName.WIFI,
                        kind=EventKind.WIFI_BEACON_SEEN,
                        features=feats,
                        raw=ap,
                    )
                    await self._emit(ev)
                log.debug("wifi: scan returned %d APs", len(aps))
            except Exception:  # noqa: BLE001
                log.exception("wifi: scan loop error")
            await self._wait_or_stop(self._interval)

    async def _wait_or_stop(self, secs: float) -> None:
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=secs)
        except asyncio.TimeoutError:
            pass
