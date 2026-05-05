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
# Two-tier coverage: broad allocations describe the "general zone" so any hit
# falls inside *something*; narrow allocations carve out the security-relevant
# sub-bands (keyfobs, TPMS, garage doors, EU LoRa). _label_for_freq picks the
# narrowest matching entry, so a 433.92 MHz hit is "ISM-433 / KEYFOB_EMISSION"
# rather than "Amateur-70cm / CELLULAR_BAND_ENERGY".
_BAND_LABELS: list[tuple[int, int, str, EventKind]] = [
    # ---------- Broad / catch-all allocations ----------
    ( 24_000_000,   54_000_000, "HF-low",        EventKind.CELLULAR_BAND_ENERGY),
    ( 88_000_000,  108_000_000, "FM-broadcast",  EventKind.AVIATION_BAND_ENERGY),
    (108_000_000,  138_000_000, "Aviation-VHF",  EventKind.AVIATION_BAND_ENERGY),
    (144_000_000,  148_000_000, "Amateur-2m",    EventKind.CELLULAR_BAND_ENERGY),
    (148_000_000,  174_000_000, "VHF-business",  EventKind.WALKIETALKIE_EMISSION),
    (174_000_000,  216_000_000, "VHF-TV",        EventKind.CELLULAR_BAND_ENERGY),
    (225_000_000,  400_000_000, "Mil-Aero-UHF",  EventKind.AVIATION_BAND_ENERGY),
    (430_000_000,  440_000_000, "Amateur-70cm",  EventKind.CELLULAR_BAND_ENERGY),
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
    # ---------- Narrow / security-relevant overrides ----------
    # NOAA weather radio (continuous broadcast — useful as a "RF chain alive" reference).
    (162_400_000,  162_600_000, "NOAA-WX",       EventKind.WALKIETALKIE_EMISSION),
    # Honda/Acura/Toyota/Hyundai keyfobs cluster in 303-307 MHz.
    (303_500_000,  308_000_000, "Keyfob-303",    EventKind.KEYFOB_EMISSION),
    # US/Asia keyfobs + TPMS centered at 315 MHz.
    (310_000_000,  320_000_000, "Keyfob-315",    EventKind.KEYFOB_EMISSION),
    # 345/347 MHz: TPMS and some Korean/Japanese keyfobs.
    (344_000_000,  348_500_000, "TPMS-345",      EventKind.KEYFOB_EMISSION),
    # 390 MHz garage-door openers (Liftmaster Security+, Genie Intellicode, Chamberlain).
    (388_000_000,  392_000_000, "Garage-390",    EventKind.GARAGE_EMISSION),
    # 418 MHz: legacy European key-fobs / RFID readers (esp. older BMW/Mercedes).
    (417_500_000,  418_500_000, "EU-Keyfob-418", EventKind.KEYFOB_EMISSION),
    # ISM 433.92 MHz: weather stations, doorbells, garage remotes, generic keyfobs, RTL-SDR
    # community sensors, TPMS in EU/some US, BLE-mesh-extender beacons.
    (433_500_000,  434_500_000, "ISM-433",       EventKind.KEYFOB_EMISSION),
    # EU SRD: 868 MHz LoRa, Z-Wave EU, ZigBee subset — falls inside our broad
    # Cellular-850 (824-894) entry; a narrow override re-tags it correctly.
    (863_000_000,  870_000_000, "EU-SRD-868",    EventKind.LORA_EMISSION),
    # Z-Wave US is centered at 908.42 MHz inside ISM-902 (already LORA_EMISSION).
]


# Default wide-band sweep: representative center frequencies covering the
# allocations a residential intrusion-monitor cares about. Skips 1100-1250
# MHz where the E4000 tuner has a PLL gap; scanner also auto-skips bad
# frequencies at runtime (5 min cooldown). At ~1s dwell each, full cycle
# is ~27 s.
DEFAULT_SWEEP_FREQS_HZ: list[int] = [
    25_000_000,
    98_000_000,
    122_000_000,
    146_000_000,
    155_000_000,
    162_550_000,
    195_000_000,
    303_825_000,    # Honda/Acura keyfobs
    315_000_000,
    345_000_000,    # TPMS sensors
    390_000_000,    # Liftmaster/Chamberlain/Genie garage doors
    418_000_000,    # legacy EU keyfobs
    433_920_000,
    462_500_000,
    488_000_000,
    617_000_000,
    734_000_000,
    868_350_000,    # EU LoRa / Z-Wave EU centre
    881_000_000,
    915_000_000,    # US LoRa / Z-Wave US (908.42 falls in this dwell)
    944_000_000,
    1_090_000_000,
    # 1_227_000_000,  # GPS L2 — E4000 PLL doesn't lock here.
    1_350_000_000,
    1_575_420_000,
    1_602_000_000,
    1_675_000_000,
]


def _label_for_freq(freq_hz: int) -> tuple[str, EventKind]:
    """Return the narrowest matching band so specific allocations (ISM-433,
    Keyfob-315) win over the broader allocations they overlap (Amateur-70cm,
    Mil-Aero-UHF). Without this, 433.92 MHz keyfobs get tagged
    cellular_band_energy and 315 MHz remotes get aviation_band_energy.
    """
    best: tuple[str, EventKind] | None = None
    best_width = float("inf")
    for low, high, label, kind in _BAND_LABELS:
        if low <= freq_hz <= high:
            width = high - low
            if width < best_width:
                best = (label, kind)
                best_width = width
    if best is not None:
        return best
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
        # Outer reconnect loop: if the SDR throws a USB error or the tuner
        # gets wedged, close and re-open instead of dying.
        skip_until: dict[int, float] = {}  # freq -> ts after which we'll retry
        while not self._stop_event.is_set():
            try:
                sdr = RtlSdr(device_index=self._device_index)
            except Exception:  # noqa: BLE001
                log.exception("midband: failed to open RTL-SDR device %d — retrying in 30s", self._device_index)
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=30.0)
                except asyncio.TimeoutError:
                    pass
                continue

            try:
                sdr.sample_rate = self._sample_rate
                sdr.gain = "auto"
                while not self._stop_event.is_set():
                    now = asyncio.get_event_loop().time()
                    for freq in self._freqs:
                        if self._stop_event.is_set():
                            break
                        # Honor per-freq cool-down for known-bad frequencies (E4000 PLL gaps, etc.)
                        if freq in skip_until and skip_until[freq] > now:
                            continue
                        try:
                            sdr.center_freq = freq
                            iq = await asyncio.get_event_loop().run_in_executor(
                                None, sdr.read_samples, self._n
                            )
                            iq = np.asarray(iq, dtype=np.complex64)
                            e_dbm = _energy_dbm(iq)
                        except Exception as ex:  # noqa: BLE001
                            # Likely PLL-not-locked or USB I/O glitch — skip this freq for 5 min.
                            log.warning("midband: freq %d failed (%s); skipping for 5 min", freq, str(ex)[:80])
                            skip_until[freq] = now + 300
                            # If the SDR raised a USB error, the device may need a full reset.
                            msg = str(ex).lower()
                            if "rtlsdr" in msg or "libusb" in msg or "no device" in msg:
                                raise  # break out to outer loop, reopen device
                            continue
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
            except Exception:  # noqa: BLE001
                log.exception("midband: scanner loop crashed — reopening device in 5s")
                try:
                    sdr.close()
                except Exception:  # noqa: BLE001
                    pass
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    pass
                continue
            else:
                try:
                    sdr.close()
                except Exception:  # noqa: BLE001
                    log.debug("midband: sdr.close raised, ignoring")
