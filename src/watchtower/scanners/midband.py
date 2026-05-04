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
# Expanded for wide-band sweep coverage across 24 MHz – 1.7 GHz.
_BAND_LABELS: list[tuple[int, int, str, EventKind]] = [
    ( 24_000_000,   54_000_000, "HF-low",        EventKind.CELLULAR_BAND_ENERGY),
    ( 88_000_000,  108_000_000, "FM-broadcast",  EventKind.AVIATION_BAND_ENERGY),
    (108_000_000,  138_000_000, "Aviation-VHF",  EventKind.AVIATION_BAND_ENERGY),
    (144_000_000,  148_000_000, "Amateur-2m",    EventKind.CELLULAR_BAND_ENERGY),
    (148_000_000,  174_000_000, "VHF-business",  EventKind.WALKIETALKIE_EMISSION),
    (174_000_000,  216_000_000, "VHF-TV",        EventKind.CELLULAR_BAND_ENERGY),
    (225_000_000,  400_000_000, "Mil-Aero-UHF",  EventKind.AVIATION_BAND_ENERGY),
    (310_000_000,  320_000_000, "Keyfob-315",    EventKind.KEYFOB_EMISSION),
    (430_000_000,  440_000_000, "Amateur-70cm",  EventKind.CELLULAR_BAND_ENERGY),
    (433_500_000,  434_500_000, "ISM-433",       EventKind.KEYFOB_EMISSION),
    (462_000_000,  468_000_000, "FRS-GMRS",      EventKind.WALKIETALKIE_EMISSION),
    (470_000_000,  512_000_000, "UHF-TV-low",    EventKind.CELLULAR_BAND_ENERGY),
    (614_000_000,  698_000_000, "UHF-TV-high",   EventKind.CELLULAR_BAND_ENERGY),
    (700_000_000,  799_000_000, "LTE-700",       EventKind.CELLULAR_BAND_ENERGY),
    (824_000_000,  894_000_000, "Cellular-850",  EventKind.CELLULAR_BAND_ENERGY),
    (895_000_000,  928_000_000, "ISM-902",       EventKind.LORA_EMISSION),
    (929_000_000,  960_000_000, "GSM-900",       EventKind.CELLULAR_BAND_ENERGY),
    (1_080_000_000, 1_100_000_000, "ADS-B",      EventKind.AVIATION_BAND_ENERGY),
    (1_215_000_000, 1_240_000_000, "GPS-L2",     EventKind.AVIATION_BAND_ENERGY),
    (1_300_000_000, 1_400_000_000, "Cellular-L", EventKind.CELLULAR_BAND_ENERGY),
    (1_563_000_000, 1_587_000_000, "GPS-L1",     EventKind.AVIATION_BAND_ENERGY),
    (1_590_000_000, 1_700_000_000, "Sat-DL",     EventKind.CELLULAR_BAND_ENERGY),
]


# Default wide-band sweep: 22 representative center frequencies.
DEFAULT_SWEEP_FREQS_HZ: list[int] = [
    25_000_000,
    98_000_000,
    122_000_000,
    146_000_000,
    155_000_000,
    162_550_000,
    195_000_000,
    315_000_000,
    433_920_000,
    462_500_000,
    488_000_000,
    617_000_000,
    734_000_000,
    881_000_000,
    915_000_000,
    944_000_000,
    1_090_000_000,
    1_227_000_000,
    1_350_000_000,
    1_575_420_000,
    1_602_000_000,
    1_675_000_000,
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
        self._freqs = sweep_freqs_hz or list(DEFAULT_SWEEP_FREQS_HZ)
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
