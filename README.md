# Watchtower

Perimeter RF awareness layer for residential pre-intrusion casing detection
and 7-day forensic timeline. Single-Pi deployment, fully passive.

- Spec: `docs/superpowers/specs/2026-05-03-watchtower-design.md`
- Implementation plans: `docs/superpowers/plans/`

## Status

**Milestone 1 (capture + storage) — implemented.** Next: M2 resolver +
enrichment + home_state.

## Quickstart

### Develop (Windows host)

```bash
cd /c/Users/ihass/watchtower
uv sync
uv run pytest -v
```

### Deploy to the Pi

The Pi must already have `pi-setup.sh` run once. Then from the Windows host:

```bash
./deploy/deploy.sh watchtower.local
```

This rsyncs source, installs a uv venv on the Pi, drops a default config to
`/etc/watchtower/watchtower.toml`, and starts the systemd service.

### Verify on the Pi

```bash
ssh admin@watchtower.local
systemctl is-active watchtower
sudo journalctl -u watchtower -f
sqlite3 /var/lib/watchtower/watchtower.db \
  "SELECT scanner, COUNT(*) FROM raw_events GROUP BY scanner;"
```

### Run integration tests against the Pi

```bash
WATCHTOWER_PI_HOST=watchtower.local uv run pytest tests/integration -v -m integration
```

## Architecture

See the spec. Briefly:

```
HARDWARE   Pi 5 16GB · built-in BLE · USB WiFi (M2) · 2× RTL-SDR

CAPTURE    ble_scanner · wifi_scanner (stub) · subghz_scanner (rtl_433) ·
           midband_scanner (RTL-SDR energy sweep)
                ↓ uniform Event envelope on local bus
ENRICHMENT (M2)
DETECTION  (M3)
OUTPUT     LocalSink → SQLite (7-day retention)
```

## Configuration

All settings live in `/etc/watchtower/watchtower.toml`. See
`config/watchtower.example.toml` for a documented default.
