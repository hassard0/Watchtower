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
from watchtower.rf_identity import subghz_identification_metadata
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
    decoded["_watchtower"] = subghz_identification_metadata(decoded)
    feats = Features(
        protocol=model,
        frequency_hz=freq_hz,
        decoded=decoded,
        local_name=model,
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
        # -M time:utc:usec emits a status event every received packet so a
        # totally-quiet RF environment is distinguishable from a broken tuner.
        # -v gives one extra diagnostic line per minute.
        self._args = list(rtl_433_args or [
            "-F", "json",
            "-d", str(device_index),
            "-M", "stats:1:60",  # JSON stats record every 60s
            "-M", "level",       # include signal level in records
        ])
        # Decoder numbers remain stable even when a human-readable model label
        # changes between rtl_433 releases, making historical fingerprints
        # easier to correlate. Supported by rtl_433 25.02+.
        if "protocol" not in self._args:
            self._args.extend(["-M", "protocol"])

    async def run(self) -> None:
        cmd = ["rtl_433", *self._args]
        log.info("subghz: starting rtl_433: %s", " ".join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        # Drain stderr concurrently so a chatty rtl_433 (or one warning about
        # the tuner / sample rate / decoder pruning) can't fill the pipe and
        # block the producer. Surface anything non-empty so failures are
        # visible without needing to attach to /proc/PID/fd/2.
        async def _drain_stderr() -> None:
            assert proc.stderr is not None
            while True:
                chunk = await proc.stderr.readline()
                if not chunk:
                    return
                msg = chunk.decode("utf-8", errors="replace").rstrip()
                if msg:
                    log.warning("subghz[rtl_433]: %s", msg)
        stderr_task = asyncio.create_task(_drain_stderr())

        try:
            assert proc.stdout is not None
            decoded_count = 0
            last_heartbeat = asyncio.get_event_loop().time()
            HEARTBEAT_SEC = 300  # log activity every 5 minutes
            while not self._stop_event.is_set():
                line_bytes = await proc.stdout.readline()
                if not line_bytes:
                    log.warning("subghz: rtl_433 stdout closed (decoded=%d)", decoded_count)
                    break
                line = line_bytes.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                ev = _line_to_event(line)
                if ev is not None:
                    decoded_count += 1
                    await self._emit(ev)
                else:
                    # Non-event JSON lines are rtl_433's status records (model
                    # absent). Surface them as heartbeats so a quiet RF
                    # environment vs a broken tuner is distinguishable.
                    try:
                        d = json.loads(line)
                        if isinstance(d, dict) and "model" not in d:
                            log.info("subghz[heartbeat]: %s",
                                     {k: v for k, v in d.items() if k in ("time", "frames", "fsk", "ook", "since", "noise", "events")} or d)
                    except (json.JSONDecodeError, TypeError):
                        pass
                now = asyncio.get_event_loop().time()
                if now - last_heartbeat > HEARTBEAT_SEC:
                    log.info("subghz: alive — decoded=%d in last %ds", decoded_count, HEARTBEAT_SEC)
                    decoded_count = 0
                    last_heartbeat = now
        finally:
            stderr_task.cancel()
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except (ProcessLookupError, asyncio.TimeoutError):
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
