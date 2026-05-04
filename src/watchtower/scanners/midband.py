"""Mid-band scanner: sweeps a list of frequencies on RTL-SDR and emits energy events.

The point isn't decoding — that's the BLE/WiFi/sub-GHz scanners' job. The
midband scanner produces a quantitative "is there RF activity in this band
right now" signal that the detection layer baselines for anomaly detection.
"""
from __future__ import annotations

import asyncio
import logging
import math

import numpy as np

try:
    from rtlsdr import RtlSdr
except ImportError:  # librtlsdr not installed (dev machine without hardware)
    RtlSdr = None  # type: ignore[assignment,misc]

from watchtower.events import Event, EventKind, Features, Scanner as ScannerName
from watchtower.scanners.base import Scanner

log = logging.getLogger(__name__)

# Map a center freq (Hz) to a friendly band label and event kind.
_BAND_LABELS: list[tuple[int, int, str, EventKind]] = [
    # (low_hz, high_hz, label, kind)
    (108_000_000,  138_000_000, "AviationBand", EventKind.AVIATION_BAND_ENERGY),
    (700_000_000,  799_000_000, "700MHz",       EventKind.CELLULAR_BAND_ENERGY),
    (824_000_000,  894_000_000, "850MHz",       EventKind.CELLULAR_BAND_ENERGY),
    (895_000_000,  928_000_000, "900MHz",       EventKind.LORA_EMISSION),
    (929_000_000,  960_000_000, "GSM900",       EventKind.CELLULAR_BAND_ENERGY),
    (1_563_000_000, 1_587_000_000, "GPS-L1",    EventKind.AVIATION_BAND_ENERGY),
]


def _label_for_freq(freq_hz: int) -> tuple[str, EventKind]:
    for low, high, label, kind in _BAND_LABELS:
        if low <= freq_hz <= high:
            return label, kind
    return "OutOfBand", EventKind.CELLULAR_BAND_ENERGY


def _energy_dbm(iq: np.ndarray) -> float:
    """Mean power of complex IQ samples in dBm (relative; calibration offsets later)."""
    if iq.size == 0:
        return -200.0
    p = float(np.mean(np.abs(iq) ** 2))
    if p <= 0:
        return -200.0
    # 10*log10(p), then arbitrary -30 dB offset to keep typical values negative-dBm-shaped.
    return 10.0 * math.log10(p) - 30.0


class MidbandScanner(Scanner):
    name = ScannerName.MIDBAND

    def __init__(
        self,
        device_index: int = 1,
        sweep_freqs_hz: list[int] | None = None,
        dwell_seconds: float = 5.0,
        sample_rate_hz: int = 2_048_000,
        sample_count: int = 256 * 1024,
    ) -> None:
        super().__init__()
        self._device_index = device_index
        self._freqs = sweep_freqs_hz or [
            734_000_000, 881_000_000, 944_000_000, 1_575_420_000,
        ]
        self._dwell = dwell_seconds
        self._sample_rate = sample_rate_hz
        self._n = sample_count

    async def run(self) -> None:
        try:
            sdr = RtlSdr(device_index=self._device_index)
        except Exception as ex:  # noqa: BLE001
            log.exception("midband: failed to open RTL-SDR device %d", self._device_index)
            raise
        try:
            sdr.sample_rate = self._sample_rate
            sdr.gain = "auto"
            while not self._stop_event.is_set():
                for freq in self._freqs:
                    if self._stop_event.is_set():
                        break
                    sdr.center_freq = freq
                    # Reading samples is a blocking call — run in default executor.
                    iq = await asyncio.get_event_loop().run_in_executor(
                        None, sdr.read_samples, self._n
                    )
                    iq = np.asarray(iq, dtype=np.complex64)
                    e_dbm = _energy_dbm(iq)
                    label, kind = _label_for_freq(freq)
                    ev = Event(
                        scanner=ScannerName.MIDBAND,
                        kind=kind,
                        features=Features(
                            band_name=label,
                            frequency_hz=freq,
                            energy_dbm=e_dbm,
                        ),
                        raw={"sample_rate_hz": self._sample_rate, "n": self._n},
                    )
                    await self._emit(ev)
                    try:
                        await asyncio.wait_for(self._stop_event.wait(), timeout=self._dwell)
                    except asyncio.TimeoutError:
                        pass
        finally:
            try:
                sdr.close()
            except Exception:  # noqa: BLE001
                log.exception("midband: sdr.close failed")
