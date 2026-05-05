"""Offline sub-GHz protocol decoder.

The midband scanner sweeps <1 GHz frequencies (303, 315, 345, 390, 418,
433.92, 462, 488, 617, 734, 868, 881, 915, 944 MHz) and measures energy.
When energy at one of those frequencies spikes above its rolling baseline,
midband captures the IQ samples to disk and enqueues a `CaptureJob` here.
This worker pops jobs off the queue and runs `rtl_433 -r FILE` against each
capture, parsing any decoded protocol record back into a Watchtower
sub-GHz Event.

Why offline rather than live tuning rtl_433: the dedicated rtl_433 process
can only listen at one frequency at a time, and even with hopping it sees
~1/N of the air-time per band. Midband already has the wide coverage —
this worker turns its energy detections into actual decodes by reusing
rtl_433's protocol library against captured IQ.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Awaitable, Callable

from watchtower.events import Event, EventKind, Features, Scanner as ScannerName

log = logging.getLogger(__name__)

# Map a model string fragment to a Watchtower event-kind. Same lookup
# scheme as scanners/subghz.py — keep these in sync.
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


@dataclass
class CaptureJob:
    path: Path             # path to the IQ file (CU8 format)
    freq_hz: int           # center frequency at capture time
    sample_rate_hz: int
    ts_unix: int           # when the capture was taken


class SubDecoder:
    """Async worker that consumes IQ capture jobs and emits sub-GHz Events."""

    # Bound queue so a fault that floods captures can't OOM us.
    QUEUE_MAX = 64

    def __init__(self, on_event: Callable[[Event], Awaitable[None]]) -> None:
        self._queue: asyncio.Queue[CaptureJob] = asyncio.Queue(maxsize=self.QUEUE_MAX)
        self._on_event = on_event
        self._stop = asyncio.Event()
        # Stats — exposed via /api/state for visibility.
        self.captures_received = 0
        self.captures_decoded = 0
        self.events_emitted = 0
        self.dropped = 0

    def submit(self, job: CaptureJob) -> bool:
        """Non-blocking enqueue. Returns False (and unlinks the file) if the
        queue is full so a runaway capture loop doesn't fill the disk."""
        try:
            self._queue.put_nowait(job)
            self.captures_received += 1
            return True
        except asyncio.QueueFull:
            self.dropped += 1
            try:
                job.path.unlink(missing_ok=True)
            except OSError:
                pass
            return False

    async def stop(self) -> None:
        self._stop.set()

    async def run(self) -> None:
        while not self._stop.is_set():
            try:
                job = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            try:
                await self._decode_one(job)
            except Exception:  # noqa: BLE001
                log.exception("sub_decoder: failed processing %s", job.path)
            finally:
                try:
                    job.path.unlink(missing_ok=True)
                except OSError:
                    pass

    async def _decode_one(self, job: CaptureJob) -> None:
        if not job.path.exists():
            return
        # rtl_433 reads CU8 by extension. Pass center_freq + sample_rate so
        # the protocol decoders compute correct symbol timing. -F json is
        # one record per detected packet.
        cmd = [
            "rtl_433",
            "-r", str(job.path),
            "-s", str(job.sample_rate_hz),
            "-f", str(job.freq_hz),
            "-F", "json",
            "-M", "level",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            log.error("sub_decoder: rtl_433 not on PATH; sub-GHz captures cannot decode")
            return
        try:
            stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=20.0)
        except asyncio.TimeoutError:
            proc.kill()
            log.warning("sub_decoder: rtl_433 timed out on %s", job.path)
            return
        self.captures_decoded += 1
        decoded_in_this_capture = 0
        json_lines = 0
        for raw_line in stdout.splitlines():
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            json_lines += 1
            ev = self._line_to_event(line, job)
            if ev is not None:
                self.events_emitted += 1
                decoded_in_this_capture += 1
                await self._on_event(ev)
        log.info("sub_decoder: %s freq=%dM rtl_433 lines=%d decoded=%d total_decoded=%d/%d",
                 job.path.name, job.freq_hz // 1_000_000, json_lines,
                 decoded_in_this_capture, self.events_emitted, self.captures_decoded)

    @staticmethod
    def _line_to_event(line: str, job: CaptureJob) -> Event | None:
        try:
            d: dict = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            return None
        model = d.get("model")
        if not isinstance(model, str):
            # rtl_433 emits status/version/stats records too — skip non-protocol lines.
            return None
        kind = _classify_kind(model)
        decoded = {k: v for k, v in d.items() if k not in ("time", "freq", "model")}
        return Event(
            scanner=ScannerName.SUBGHZ,
            kind=kind,
            features=Features(
                protocol=model,
                frequency_hz=job.freq_hz,
                decoded=decoded,
            ),
            raw={**d, "_capture_ts": job.ts_unix, "_decoded_offline": True},
        )


def reap_old_captures(directory: Path, max_age_sec: int = 600) -> int:
    """Remove capture files left behind by crashes. Returns count removed."""
    if not directory.exists():
        return 0
    now = time.time()
    removed = 0
    for p in directory.iterdir():
        try:
            if (now - p.stat().st_mtime) > max_age_sec:
                p.unlink()
                removed += 1
        except OSError:
            pass
    return removed
