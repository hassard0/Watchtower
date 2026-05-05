"""Tests for MidbandScanner — RTL-SDR energy sweeper."""
import asyncio

import numpy as np
import pytest

from watchtower.events import EventKind, Scanner as ScannerName
from watchtower.scanners.midband import (
    MidbandScanner, _energy_dbm, _label_for_freq, DEFAULT_SWEEP_FREQS_HZ,
)


def test_label_for_freq_picks_narrowest_match():
    # Common security-relevant <1 GHz allocations all need to land on the
    # narrow-and-correct label, not the broader containing range.
    cases = [
        (303_825_000, "Keyfob-303",    EventKind.KEYFOB_EMISSION),    # was Mil-Aero
        (315_000_000, "Keyfob-315",    EventKind.KEYFOB_EMISSION),    # was Mil-Aero
        (345_000_000, "TPMS-345",      EventKind.KEYFOB_EMISSION),    # was Mil-Aero
        (390_000_000, "Garage-390",    EventKind.GARAGE_EMISSION),    # was Mil-Aero
        (418_000_000, "EU-Keyfob-418", EventKind.KEYFOB_EMISSION),    # was OutOfBand
        (433_920_000, "ISM-433",       EventKind.KEYFOB_EMISSION),    # was Amateur-70cm
        (162_550_000, "NOAA-WX",       EventKind.WALKIETALKIE_EMISSION),
        (868_350_000, "EU-SRD-868",    EventKind.LORA_EMISSION),      # was Cellular-850
    ]
    for freq, expected_label, expected_kind in cases:
        label, kind = _label_for_freq(freq)
        assert label == expected_label, f"{freq}: got {label!r} expected {expected_label!r}"
        assert kind == expected_kind, f"{freq}: got {kind} expected {expected_kind}"


def test_default_sweep_includes_security_critical_freqs():
    # Each band we care about should be visited by the default sweep.
    for required in (303_825_000, 315_000_000, 345_000_000, 390_000_000,
                     418_000_000, 433_920_000, 868_350_000, 915_000_000):
        assert required in DEFAULT_SWEEP_FREQS_HZ, f"missing {required} from sweep"


def test_energy_dbm_scales_with_amplitude():
    weak = np.full(1024, 0.01 + 0.0j, dtype=np.complex64)
    strong = np.full(1024, 1.0 + 0.0j, dtype=np.complex64)
    assert _energy_dbm(strong) > _energy_dbm(weak)


def test_energy_dbm_returns_finite_for_zero_input():
    z = np.zeros(1024, dtype=np.complex64)
    e = _energy_dbm(z)
    # Zero input: clamp to a safe floor (-200 dBm) instead of -inf.
    assert e == pytest.approx(-200.0, abs=1.0)


async def test_midband_scanner_emits_per_frequency(monkeypatch):
    """Patch RtlSdr to feed canned IQ samples; verify one event per freq."""
    received = []

    class FakeRtlSdr:
        def __init__(self, device_index=0):
            self.device_index = device_index
            self.center_freq = 0
            self.sample_rate = 0
            self.gain = 0

        def read_samples(self, n):
            return np.full(n, 0.5 + 0.0j, dtype=np.complex64)

        def close(self):
            pass

    monkeypatch.setattr("watchtower.scanners.midband.RtlSdr", FakeRtlSdr)

    s = MidbandScanner(
        device_index=1,
        sweep_freqs_hz=[700_000_000, 900_000_000],
        dwell_seconds=0.05,
        sample_rate_hz=2_048_000,
    )
    s.on_event(lambda ev: received.append(ev))
    runner = asyncio.create_task(s.start())
    await asyncio.sleep(0.3)  # enough time for at least one full sweep
    await s.stop()
    runner.cancel()
    try:
        await runner
    except asyncio.CancelledError:
        pass

    # We should have at least one event per configured frequency.
    band_names = {ev.features.band_name for ev in received}
    assert "LTE-700" in band_names
    assert "ISM-902" in band_names
    for ev in received:
        assert ev.scanner == ScannerName.MIDBAND
        assert ev.kind in (
            EventKind.CELLULAR_BAND_ENERGY,
            EventKind.LORA_EMISSION,
            EventKind.AVIATION_BAND_ENERGY,
            EventKind.WALKIETALKIE_EMISSION,
            EventKind.KEYFOB_EMISSION,
        )
        assert ev.features.energy_dbm is not None
