"""Local Bluetooth and LAN friendly-name discovery.

All network traffic is link-local discovery traffic. UPnP descriptions are
fetched only from the private address that sent the SSDP response, with no
redirects, which keeps this from becoming a general URL fetcher.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from watchtower.bluetooth_identity import (
    ingest_bluez_devices,
    list_bluez_devices,
    scan_classic,
)
from watchtower.name_resolution import clean_name, record_name_candidate
from watchtower.storage.db import get_connection

_MAC = re.compile(r"(?i)^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
log = logging.getLogger(__name__)


def read_neighbors() -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        lines = Path("/proc/net/arp").read_text(encoding="utf-8").splitlines()[1:]
    except OSError:
        return out
    for line in lines:
        fields = line.split()
        if len(fields) >= 4 and _MAC.fullmatch(fields[3]) and fields[3] != "00:00:00:00:00:00":
            out[fields[0]] = fields[3].lower()
    return out


def read_dhcp_names() -> list[dict[str, str]]:
    paths = [Path("/var/lib/misc/dnsmasq.leases"), Path("/var/lib/NetworkManager/dnsmasq.leases")]
    paths.extend(Path("/run/NetworkManager").glob("dnsmasq*.leases") if Path("/run/NetworkManager").exists() else [])
    out: list[dict[str, str]] = []
    for path in paths:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) >= 4 and _MAC.fullmatch(fields[1]) and fields[3] not in {"*", "-"}:
                out.append({"ip": fields[2], "mac": fields[1].lower(), "name": fields[3]})
    return out


def discover_mdns(timeout_sec: float = 2.5) -> list[dict[str, str]]:
    try:
        from zeroconf import (
            ServiceBrowser,
            ServiceListener,
            Zeroconf,
            ZeroconfServiceTypes,
        )
    except ImportError:
        return []
    found: list[dict[str, str]] = []
    zc = Zeroconf()

    class Listener(ServiceListener):
        def add_service(self, zeroconf, service_type, name):
            info = zeroconf.get_service_info(service_type, name, timeout=800)
            if not info:
                return
            instance = name[:-len(service_type)].rstrip(".") if name.endswith(service_type) else name
            properties = {}
            for key, value in (info.properties or {}).items():
                try:
                    properties[bytes(key).decode("utf-8", "replace")] = bytes(value).decode("utf-8", "replace")
                except (TypeError, ValueError):
                    continue
            display_name = properties.get("fn") or properties.get("name") or instance
            for address in info.parsed_scoped_addresses():
                found.append({"ip": address.split("%")[0], "name": display_name,
                              "service": service_type, "host": (info.server or "").rstrip("."),
                              "modelName": properties.get("md", "")})

        def update_service(self, zeroconf, service_type, name):
            self.add_service(zeroconf, service_type, name)

        def remove_service(self, zeroconf, service_type, name):
            pass

    browsers = []
    try:
        types = ZeroconfServiceTypes.find(zc=zc, timeout=min(1.5, timeout_sec))
        listener = Listener()
        for service_type in list(types)[:40]:
            browsers.append(ServiceBrowser(zc, service_type, listener))
        time.sleep(max(0.5, timeout_sec - 1.0))
    finally:
        for browser in browsers:
            browser.cancel()
        zc.close()
    return found


def _private_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.split("%")[0])
        return ip.is_private or ip.is_link_local
    except ValueError:
        return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _upnp_description(location: str, responder_ip: str) -> dict[str, str] | None:
    parsed = urllib.parse.urlsplit(location)
    if parsed.scheme != "http" or not parsed.hostname or not _private_ip(parsed.hostname):
        return None
    try:
        if ipaddress.ip_address(parsed.hostname) != ipaddress.ip_address(responder_ip):
            return None
    except ValueError:
        return None
    try:
        req = urllib.request.Request(location, headers={"User-Agent": "Watchtower/0.1"})
        opener = urllib.request.build_opener(_NoRedirect())
        with opener.open(req, timeout=2.0) as response:
            data = response.read(262145)
        if len(data) > 262144:
            return None
        root = ET.fromstring(data)
    except (OSError, ValueError, ET.ParseError):
        return None
    values: dict[str, str] = {"ip": responder_ip}
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        if tag in {"friendlyName", "manufacturer", "modelName", "UDN"} and element.text:
            values[tag] = element.text.strip()
    return values if values.get("friendlyName") else None


def discover_upnp(timeout_sec: float = 2.5) -> list[dict[str, str]]:
    request = (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
               b"MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(0.25)
    locations: dict[tuple[str, str], None] = {}
    try:
        sock.sendto(request, ("239.255.255.250", 1900))
        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline:
            try:
                data, sender = sock.recvfrom(65535)
            except TimeoutError:
                continue
            headers = {}
            for line in data.decode("iso-8859-1", "replace").splitlines()[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()
            if headers.get("location") and _private_ip(sender[0]):
                locations[(headers["location"], sender[0])] = None
    finally:
        sock.close()
    out = []
    for location, responder_ip in list(locations)[:30]:
        description = _upnp_description(location, responder_ip)
        if description:
            out.append(description)
    return out


def ingest_lan_names(db_path: Path | str, observations: list[dict[str, Any]],
                     neighbors: dict[str, str] | None = None) -> int:
    neighbors = neighbors or read_neighbors()
    # A DNS-SD host commonly advertises both IPv4 and IPv6. If any address
    # maps to an ARP neighbor, use that MAC for every service/address so one
    # physical device does not become several rows.
    host_macs: dict[str, str] = {}
    for item in observations:
        host = str(item.get("host") or "").strip().lower()
        mac = str(item.get("mac") or neighbors.get(str(item.get("ip") or "")) or "").lower()
        if host and _MAC.fullmatch(mac):
            host_macs[host] = mac
    now = int(time.time())
    count = 0
    with get_connection(db_path) as conn:
        for item in observations:
            ip = str(item.get("ip") or "")
            host = str(item.get("host") or "").strip().lower()
            mac = str(item.get("mac") or neighbors.get(ip) or host_macs.get(host) or "").lower()
            if not ip and not _MAC.fullmatch(mac):
                continue
            eid = (f"lan:mac:{mac}" if _MAC.fullmatch(mac) else
                   f"lan:host:{host}" if host else f"lan:ip:{ip}")
            conn.execute(
                """INSERT INTO entities(entity_id,scanner,kind,first_seen_unix,last_seen_unix,visit_count,total_observations,is_random_mac)
                   VALUES (?,'lan_discovery','lan_device',?,?,0,1,0)
                   ON CONFLICT(entity_id) DO UPDATE SET last_seen_unix=excluded.last_seen_unix,
                     total_observations=entities.total_observations+1""",
                (eid, now, now),
            )
            source = str(item.get("source") or "reverse_dns")
            name = item.get("name")
            if source == "mdns_service_name":
                name = normalize_mdns_instance(name)
            evidence = {k: item[k] for k in ("ip", "host", "service", "manufacturer", "modelName") if item.get(k)}
            if record_name_candidate(conn, eid, name, source, evidence=evidence):
                count += 1
    return count


def normalize_mdns_instance(value: Any) -> str | None:
    """Remove common serial/MAC decorations from DNS-SD instance labels."""
    name = str(value or "").strip()
    name = re.sub(r"^[0-9A-F]{8,}@", "", name, flags=re.IGNORECASE)
    name = re.sub(
        r"^(?:[0-9A-F]{2}[-_:]){2,}[0-9A-F]{2}(?:\.\d+)?\s+",
        "", name, flags=re.IGNORECASE,
    )
    name = re.sub(r"\s*\[(?:[0-9A-F]{2}:){5}[0-9A-F]{2}\]\s*$", "", name,
                  flags=re.IGNORECASE)
    return clean_name(name)


def discover_and_ingest_lan(db_path: Path | str) -> int:
    neighbors = read_neighbors()
    observations: list[dict[str, Any]] = []
    for lease in read_dhcp_names():
        observations.append({**lease, "source": "dhcp_hostname"})
    for ip, mac in neighbors.items():
        try:
            hostname = socket.gethostbyaddr(ip)[0].split(".")[0]
        except (socket.herror, socket.gaierror, OSError):
            continue
        observations.append({"ip": ip, "mac": mac, "name": hostname, "source": "reverse_dns"})
    for item in discover_mdns():
        observations.append({**item, "source": "mdns_service_name"})
    for item in discover_upnp():
        observations.append({**item, "name": item.get("friendlyName"), "source": "upnp_friendly_name"})
    return ingest_lan_names(db_path, observations, neighbors)


class LocalIdentityDiscovery:
    def __init__(self, db_path: Path | str, settings_getter, pause_scanner_factory=None) -> None:
        self.db_path = Path(db_path)
        self.settings_getter = settings_getter
        self.pause_scanner_factory = pause_scanner_factory

    async def run(self, stop: asyncio.Event) -> None:
        # Cache ingestion starts quickly; active inquiries then run every 10 min.
        await asyncio.sleep(5)
        classic_counter = 0
        while not stop.is_set():
            settings = self.settings_getter()
            try:
                if settings.get("classic_name_discovery_enabled", True):
                    fn = scan_classic if classic_counter % 5 == 0 else list_bluez_devices
                    if fn is scan_classic and self.pause_scanner_factory:
                        async with await self.pause_scanner_factory():
                            devices = await asyncio.to_thread(fn)
                    else:
                        devices = await asyncio.to_thread(fn)
                    await asyncio.to_thread(ingest_bluez_devices, self.db_path, devices)
                if settings.get("lan_name_discovery_enabled", True):
                    await asyncio.to_thread(discover_and_ingest_lan, self.db_path)
            except asyncio.CancelledError:
                raise
            except Exception:
                # Discovery is opportunistic; hardware/network failures retry.
                log.exception("local identity discovery failed; retrying")
            classic_counter += 1
            try:
                await asyncio.wait_for(stop.wait(), timeout=120)
            except TimeoutError:
                pass
