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
        # rtl_433 25.02 deprecated -G; passing it causes immediate exit. Use default protocol set.
        self._args = rtl_433_args or ["-F", "json", "-d", str(device_index)]

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
