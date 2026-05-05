"""IEEE OUI lookup.

Resolves the first 3 bytes of a MAC to the registering manufacturer using the
IEEE OUI registry (~50k entries).

We sidestep the `mac_vendor_lookup` package's runtime API because it wraps
every operation in `loop.run_until_complete()`, which deadlocks when called
from inside an already-running asyncio loop (which is most of Watchtower).
Instead we reuse the package's *cache file* — a simple `PREFIX:Vendor` text
file at `~/.cache/mac-vendors.txt` — and load it once into a plain dict.

If the cache is missing on first run, we fall back to bundled data from the
package's wheel (if present) or download via aiohttp on a dedicated thread.
"""
from __future__ import annotations

import logging
import os
import threading
import time

log = logging.getLogger(__name__)

def _default_cache_path() -> str:
    # Service runs with ProtectHome=true so ~/.cache is invisible. Prefer the
    # state dir we already own, fall back to ~/.cache for ad-hoc CLI use.
    for candidate in ("/var/lib/watchtower/oui-cache.txt",
                      os.path.expanduser("~/.cache/mac-vendors.txt")):
        parent = os.path.dirname(candidate)
        if os.path.isdir(parent) and os.access(parent, os.W_OK):
            return candidate
    return os.path.expanduser("~/.cache/mac-vendors.txt")


CACHE_PATH = _default_cache_path()
OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"
REFRESH_INTERVAL_SEC = 30 * 86400  # ~monthly

_prefixes: dict[str, str] | None = None
_load_lock = threading.Lock()
_last_refresh_unix: float = 0.0


def _normalize_mac_prefix(mac: str) -> str | None:
    """Return the upper-case 6-hex-digit prefix of a MAC, or None if malformed."""
    if not mac:
        return None
    mac = mac.replace(":", "").replace("-", "").replace(".", "").upper()
    if len(mac) < 6:
        return None
    prefix = mac[:6]
    try:
        int(prefix, 16)
    except ValueError:
        return None
    return prefix


def _load_from_file(path: str) -> dict[str, str]:
    out: dict[str, str] = {}
    with open(path, "rb") as f:
        for raw in f:
            line = raw.decode("utf-8", errors="replace").rstrip("\n").rstrip("\r")
            if not line or ":" not in line:
                continue
            prefix, vendor = line.split(":", 1)
            prefix = prefix.strip().upper()
            vendor = vendor.strip()
            if len(prefix) == 6 and vendor:
                out[prefix] = vendor
    return out


def _ensure_loaded() -> dict[str, str] | None:
    """Lazy-load the prefix dict from the local cache file."""
    global _prefixes
    if _prefixes is not None:
        return _prefixes if _prefixes else None
    with _load_lock:
        if _prefixes is not None:
            return _prefixes if _prefixes else None
        if not os.path.exists(CACHE_PATH):
            log.warning("oui: cache file %s missing — vendor lookup disabled until refresh", CACHE_PATH)
            _prefixes = {}
            return None
        try:
            _prefixes = _load_from_file(CACHE_PATH)
            log.info("oui: loaded %d IEEE prefixes from %s", len(_prefixes), CACHE_PATH)
        except Exception:  # noqa: BLE001
            log.exception("oui: failed to read %s", CACHE_PATH)
            _prefixes = {}
            return None
    return _prefixes


def vendor_for_mac(mac: str) -> str | None:
    """Return manufacturer name for a MAC, or None if unknown.

    Skips IEEE locally-administered MACs (bit 1 of MSB set) — those have no
    OUI. We don't filter BLE random addresses by bit pattern since public Apple
    MACs overlap the same ranges; misses fall through cheaply via dict lookup.
    """
    if not mac:
        return None
    try:
        first_byte = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return None
    if first_byte & 0x02:
        return None
    prefix = _normalize_mac_prefix(mac)
    if prefix is None:
        return None
    table = _ensure_loaded()
    if not table:
        return None
    return table.get(prefix)


def _download_in_thread() -> bool:
    """Download a fresh copy of the IEEE OUI registry on a private thread.

    Owns its own asyncio loop, so it is safe to call from anywhere — including
    inside an already-running asyncio loop on another thread.
    """
    result: list[bool] = [False]

    def worker():
        try:
            import asyncio
            import aiohttp
            from urllib.parse import urlparse  # noqa: F401

            async def _do():
                tmp_path = CACHE_PATH + ".tmp"
                os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
                async with aiohttp.ClientSession(
                    headers={
                        # IEEE returns 418 to bare or generic UAs. Identify
                        # the project so admins can contact us if needed.
                        "User-Agent": "Watchtower/0.1 (+https://github.com/hassard0/Watchtower) python-aiohttp",
                        "Accept": "text/plain, */*",
                    }
                ) as session:
                    async with session.get(OUI_URL, timeout=aiohttp.ClientTimeout(total=120)) as resp:
                        resp.raise_for_status()
                        prefixes_local: dict[str, str] = {}
                        with open(tmp_path, "wb") as f:
                            async for raw in resp.content:
                                if b"(base 16)" in raw:
                                    prefix, vendor = (s.strip() for s in raw.split(b"(base 16)", 1))
                                    prefixes_local[prefix.decode()] = vendor.decode(errors="replace")
                                    f.write(prefix + b":" + vendor + b"\n")
                if not prefixes_local:
                    log.error("oui: refresh produced empty file")
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
                    return False
                os.replace(tmp_path, CACHE_PATH)
                # Swap into the live table.
                global _prefixes
                with _load_lock:
                    _prefixes = prefixes_local
                log.info("oui: refreshed %d prefixes from IEEE", len(prefixes_local))
                return True

            loop = asyncio.new_event_loop()
            try:
                result[0] = loop.run_until_complete(_do())
            finally:
                loop.close()
        except Exception:  # noqa: BLE001
            log.exception("oui: refresh thread failed")

    t = threading.Thread(target=worker, daemon=True, name="oui-refresh")
    t.start()
    t.join(timeout=180)
    return result[0]


def maybe_refresh(force: bool = False) -> bool:
    """Refresh the IEEE OUI database from the network if stale.

    Returns True if a refresh ran. Called from the analytics loop ~once per
    cycle; most calls return False because the cache is recent enough.
    """
    global _last_refresh_unix
    now = time.time()
    # Seed our age tracker from the cache file's mtime on first call so we
    # don't re-download a recently downloaded file across restarts.
    if _last_refresh_unix == 0.0:
        try:
            _last_refresh_unix = os.path.getmtime(CACHE_PATH)
        except OSError:
            _last_refresh_unix = 0.0
    if not force and _last_refresh_unix > 0 and (now - _last_refresh_unix) < REFRESH_INTERVAL_SEC:
        return False
    ok = _download_in_thread()
    if ok:
        _last_refresh_unix = now
    else:
        # Back off failed refreshes for ~6 h instead of retrying every cycle.
        _last_refresh_unix = now - REFRESH_INTERVAL_SEC + 6 * 3600
    return ok
