"""Mid-band scanner: sweeps a list of frequencies on RTL-SDR and emits energy events.

The point isn't decoding — that's the BLE/WiFi/sub-GHz scanners' job. The
midband scanner produces a quantitative "is there RF activity in this band
right now" signal that the detection layer baselines for anomaly detection.
"""
from __future__ import annotations

import asyncio
import json
import logging
import math
import time
from pathlib import Path

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


# Default sweep: sub-GHz dense. Each security-relevant freq is listed
# *twice* and the wider context bands once, so with the configured
# ~0.5s dwell each sub-GHz freq is revisited every ~3s — about 3x the
# coverage a flat 26-freq sweep gives. Skips 1100-1250 MHz where the
# E4000 tuner has a PLL gap; scanner also auto-skips bad freqs at runtime.
DEFAULT_SWEEP_FREQS_HZ: list[int] = [
    # Pass 1 — sub-GHz priority
    303_825_000,    # Honda/Acura/Toyota keyfobs
    315_000_000,    # US keyfobs / TPMS / Liftmaster Security+ 2.0
    318_000_000,    # some Genie / Chamberlain / Faraday Future
    345_000_000,    # TPMS sensors / some EU keyfobs
    390_000_000,    # Liftmaster Security+ / older garage doors
    418_000_000,    # legacy EU keyfobs (older BMW/Mercedes)
    433_920_000,    # ISM (weather, doorbell, generic keyfob)
    462_500_000,    # FRS / GMRS walkie-talkies
    868_350_000,    # EU LoRa / Z-Wave EU
    915_000_000,    # US LoRa / Z-Wave US (908.42 covered)
    # Pass 2 — sub-GHz priority repeated for ~3 s revisit
    303_825_000, 315_000_000, 318_000_000, 345_000_000, 390_000_000,
    418_000_000, 433_920_000, 462_500_000, 868_350_000, 915_000_000,
    # Wide-band context — visited once per outer cycle
    25_000_000, 98_000_000, 122_000_000, 146_000_000, 155_000_000,
    162_550_000, 195_000_000, 488_000_000, 617_000_000, 734_000_000,
    881_000_000, 944_000_000, 1_090_000_000,
    # 1_227_000_000,  # GPS L2 — E4000 PLL doesn't lock here.
    1_350_000_000, 1_575_420_000, 1_602_000_000, 1_675_000_000,
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


# Frequencies eligible for IQ-capture-on-spike. These are the <1 GHz bands
# where rtl_433 has protocol decoders (keyfobs, garage doors, weather
# sensors, TPMS, LoRa, etc.). Midband-only freqs above 1 GHz aren't worth
# capturing — we have no decoder for them.
_CAPTURE_ELIGIBLE_HZ: frozenset[int] = frozenset({
    303_825_000, 315_000_000, 318_000_000, 345_000_000, 390_000_000,
    418_000_000, 433_920_000, 462_500_000, 488_000_000, 868_350_000,
    915_000_000,
})


# Hardcoded fallback noise floors per freq (dBm). Used as the *initial*
# baseline so the first reading after a service restart can already
# trigger spike captures, instead of having to learn for ~26 sweep cycles.
# Empirically observed values from this hardware; the EMA refines them.
_INITIAL_FLOOR_DBM: dict[int, float] = {
    25_000_000:    -70.5,  98_000_000:    -70.5, 122_000_000:   -70.9,
    146_000_000:   -70.8, 155_000_000:   -70.9, 162_550_000:   -70.9,
    195_000_000:   -70.9, 303_825_000:   -70.6, 315_000_000:   -70.7,
    318_000_000:   -70.6, 345_000_000:   -65.4, 390_000_000:   -68.4,
    418_000_000:   -67.5, 433_920_000:   -70.5, 462_500_000:   -70.4,
    488_000_000:   -70.5, 617_000_000:   -68.7, 734_000_000:   -63.8,
    868_350_000:   -65.1, 881_000_000:   -63.5, 915_000_000:   -65.5,
    944_000_000:   -64.0, 1_090_000_000: -65.0, 1_350_000_000: -65.0,
    1_575_420_000: -68.0, 1_602_000_000: -68.0, 1_675_000_000: -68.0,
}


def _save_iq_cu8(samples: np.ndarray, path) -> None:
    """Write complex64 samples as interleaved uint8 IQ (rtl-sdr's native CU8).

    rtl_433 reads CU8 directly. Each sample becomes 2 bytes (I, Q) in
    [0, 255] with 128 = zero, matching what `rtl_sdr -` would produce.
    """
    s = np.asarray(samples)
    out = np.empty(s.size * 2, dtype=np.uint8)
    out[0::2] = np.clip(s.real * 127.5 + 127.5, 0, 255).astype(np.uint8)
    out[1::2] = np.clip(s.imag * 127.5 + 127.5, 0, 255).astype(np.uint8)
    out.tofile(path)


class MidbandScanner(Scanner):
    name = ScannerName.MIDBAND

    # Capture IQ for offline rtl_433 decode when a sub-GHz freq exceeds its
    # rolling baseline by this many dB. The observed noise floor is stable
    # to within ~0.2 dB. 1.0 dB is the lowest setting that still avoids
    # firing on natural sweep-to-sweep jitter, and is sensitive enough to
    # catch faint button presses where RF is attenuated by walls/distance.
    # The rate-limit (CAPTURE_RATE_LIMIT_PER_MIN) protects disk if we trip
    # on something noisy.
    SPIKE_THRESHOLD_DB: float = 1.0

    # File where the EMA baseline is persisted between runs. Without this,
    # every service restart wipes the spike detector for ~26 sweep cycles
    # and we miss bursts arriving in that window.
    BASELINE_PERSIST_NAME: str = "midband_baseline.json"

    # EMA smoothing for the per-freq baseline. Smaller alpha = slower to
    # learn; we want stable so a single transient doesn't poison baseline.
    BASELINE_ALPHA: float = 0.05

    # Cap captures emitted per minute so a noisy front-end can't fill disk.
    CAPTURE_RATE_LIMIT_PER_MIN: int = 30

    def __init__(
        self,
        device_index: int = 1,
        sweep_freqs_hz: list[int] | None = None,
        dwell_seconds: float = 0.5,
        sample_rate_hz: int = 2_048_000,
        sample_count: int = 256 * 1024,
        capture_dir: Path | str | None = None,
        capture_callback=None,  # Callable[[CaptureJob], bool] — return True if accepted
    ) -> None:
        super().__init__()
        self._device_index = device_index
        self._freqs = sweep_freqs_hz or list(DEFAULT_SWEEP_FREQS_HZ)
        self._dwell = dwell_seconds
        self._sample_rate = sample_rate_hz
        self._n = sample_count
        self._capture_dir = Path(capture_dir) if capture_dir else None
        self._capture_callback = capture_callback
        self._baseline: dict[int, float] = {}     # per-freq EMA dBm
        self._capture_window_start = 0.0
        self._captures_in_window = 0
        if self._capture_dir is not None:
            self._capture_dir.mkdir(parents=True, exist_ok=True)
            self._baseline_path = self._capture_dir.parent / self.BASELINE_PERSIST_NAME
            self._load_baselines()
        else:
            self._baseline_path = None
        # Seed any freq we haven't observed with the hardcoded floor so the
        # very first sweep cycle can already fire spike captures.
        for f, floor in _INITIAL_FLOOR_DBM.items():
            self._baseline.setdefault(f, floor)
        self._baseline_dirty = False

    def _load_baselines(self) -> None:
        if self._baseline_path is None or not self._baseline_path.exists():
            return
        try:
            data = json.loads(self._baseline_path.read_text())
            if isinstance(data, dict):
                self._baseline = {int(k): float(v) for k, v in data.items()}
                log.info("midband: loaded %d persisted baselines", len(self._baseline))
        except Exception:  # noqa: BLE001
            log.exception("midband: failed loading baselines")

    def _save_baselines(self) -> None:
        if self._baseline_path is None or not self._baseline_dirty:
            return
        try:
            tmp = self._baseline_path.with_suffix(".tmp")
            tmp.write_text(json.dumps({str(k): round(v, 3) for k, v in self._baseline.items()}))
            tmp.replace(self._baseline_path)
            self._baseline_dirty = False
        except Exception:  # noqa: BLE001
            log.exception("midband: failed saving baselines")

    def _rate_limit_ok(self) -> bool:
        now = time.monotonic()
        if now - self._capture_window_start > 60.0:
            self._capture_window_start = now
            self._captures_in_window = 0
        if self._captures_in_window >= self.CAPTURE_RATE_LIMIT_PER_MIN:
            return False
        self._captures_in_window += 1
        return True

    def _maybe_capture(self, sdr, freq_hz: int, spike_iq: np.ndarray) -> bool:
        """Save the spike-detecting IQ + extra tail samples to disk for offline
        decode.

        spike_iq is the IQ window that triggered the spike check — the burst
        (or its leading edge) is *here*, not in samples that follow. We then
        read another ~500 ms to capture the trailing portion of longer packets
        (some weather sensors and TPMS frames run 200-500 ms). Total capture
        is ~625 ms which fits any rtl_433 supported protocol.
        """
        if not self._rate_limit_ok():
            return False
        try:
            extra = sdr.read_samples(1024 * 1024)
        except Exception:  # noqa: BLE001
            log.exception("midband: capture read_samples failed")
            return False
        # Concatenate trigger window + tail. Keep complex64 throughout.
        try:
            spike_arr = np.asarray(spike_iq, dtype=np.complex64)
            extra_arr = np.asarray(extra, dtype=np.complex64)
            combined = np.concatenate((spike_arr, extra_arr))
        except Exception:  # noqa: BLE001
            log.exception("midband: capture concat failed")
            return False
        try:
            ts = int(time.time())
            path = self._capture_dir / f"{freq_hz}-{ts}-{int(time.monotonic()*1000)%10000:04d}.cu8"
            _save_iq_cu8(combined, path)
        except Exception:  # noqa: BLE001
            log.exception("midband: capture write failed")
            return False
        try:
            from watchtower.sub_decoder import CaptureJob
            job = CaptureJob(
                path=path, freq_hz=freq_hz,
                sample_rate_hz=self._sample_rate, ts_unix=ts,
            )
            return self._capture_callback(job)
        except Exception:  # noqa: BLE001
            log.exception("midband: capture submit failed")
            try:
                path.unlink()
            except OSError:
                pass
            return False

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
                # Fixed high gain instead of "auto" — auto can settle too low
                # for weak distant transmitters (residential garage opener at
                # the far side of the house). 40 dB is well below the R820T2
                # max of 49.6 dB so we stay out of saturation.
                try:
                    sdr.gain = 40
                except Exception:  # noqa: BLE001
                    sdr.gain = "auto"
                while not self._stop_event.is_set():
                    now = asyncio.get_event_loop().time()
                    # Persist learned baselines once per outer cycle so a
                    # restart doesn't blank our spike detector.
                    self._save_baselines()
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

                        # Trigger an offline-decode capture if the energy at
                        # this <1 GHz freq spiked above its learned baseline.
                        # We include the IQ that *detected* the spike — the
                        # burst itself is in `iq`, not in samples that come
                        # later — plus extra samples for the burst tail.
                        spiked = False
                        if (self._capture_callback is not None
                                and self._capture_dir is not None
                                and freq in _CAPTURE_ELIGIBLE_HZ):
                            base = self._baseline.get(freq)
                            if base is not None and (e_dbm - base) >= self.SPIKE_THRESHOLD_DB:
                                spiked = self._maybe_capture(sdr, freq, iq)
                            # Update EMA after the spike check so a real
                            # spike doesn't immediately raise the baseline.
                            self._baseline[freq] = (
                                e_dbm if base is None
                                else base + self.BASELINE_ALPHA * (e_dbm - base)
                            )
                            self._baseline_dirty = True

                        ev = Event(
                            scanner=ScannerName.MIDBAND,
                            kind=kind,
                            features=Features(
                                band_name=label,
                                frequency_hz=freq,
                                energy_dbm=e_dbm,
                            ),
                            raw={
                                "sample_rate_hz": self._sample_rate,
                                "n": self._n,
                                "capture_triggered": spiked,
                                "baseline_dbm": round(self._baseline.get(freq, e_dbm), 2),
                            },
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
