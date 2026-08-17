"""High-confidence Apple ecosystem name and model extraction.

Apple devices commonly disclose user-facing names through Bonjour. This
module consumes only clear-text, local-link metadata. It does not try to
reverse rotating Continuity or Find My identifiers into owners.
"""
from __future__ import annotations

import re
from typing import Any

from watchtower.name_resolution import clean_name


# Query these even when general DNS-SD enumeration is truncated or delayed.
APPLE_DNS_SD_TYPES = (
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_companion-link._tcp.local.",
    "_device-info._tcp.local.",
    "_apple-mobdev2._tcp.local.",
    "_sleep-proxy._udp.local.",
    "_hap._tcp.local.",
    "_homekit._tcp.local.",
)

_SERVICE_SOURCES = {
    "_airplay._tcp.local.": "airplay_display_name",
    "_raop._tcp.local.": "airplay_display_name",
    "_companion-link._tcp.local.": "apple_companion_name",
    "_device-info._tcp.local.": "apple_device_info_name",
    "_apple-mobdev2._tcp.local.": "apple_mobile_device_name",
    "_sleep-proxy._udp.local.": "apple_sleep_proxy_name",
    "_hap._tcp.local.": "homekit_accessory_name",
    "_homekit._tcp.local.": "homekit_accessory_name",
}

# Exact identifiers verified against Apple support material or observed on the
# owner's devices. Unknown identifiers still receive a useful family label.
_MODEL_LABELS = {
    "AppleTV5,3": "Apple TV HD",
    "AppleTV6,2": "Apple TV 4K (1st generation)",
    "Mac16,9": "Mac Studio (2025, M4 Max)",
}

_APPLE_MODEL_PREFIXES = (
    "AppleTV", "AudioAccessory", "HomePod", "Mac", "MacBook", "Macmini",
    "MacPro", "iMac", "iPhone", "iPad", "iPod", "Watch",
)
_MAC = re.compile(r"(?i)^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
_RAOP_PREFIX = re.compile(r"(?i)^[0-9a-f]{12}@")
_SLEEP_PROXY_PREFIX = re.compile(
    r"(?i)^(?:[0-9a-f]{2}[-_:]){2,}[0-9a-f]{2}(?:\.\d+)?\s+"
)


def _property(properties: dict[str, Any], *names: str) -> str:
    wanted = {name.casefold() for name in names}
    for key, value in properties.items():
        if str(key).casefold() in wanted and isinstance(value, str):
            return value.strip()
    return ""


def normalize_apple_instance(value: Any, service: str = "") -> str | None:
    """Remove protocol identifiers while retaining the user-facing portion."""
    name = str(value or "").strip()
    service = service.casefold()
    if service.startswith("_raop."):
        name = _RAOP_PREFIX.sub("", name)
    if service.startswith("_sleep-proxy."):
        name = _SLEEP_PROXY_PREFIX.sub("", name)
    return clean_name(name)


def apple_model_label(identifier: Any) -> str | None:
    """Turn a Bonjour model identifier into a useful, non-serial label."""
    model = clean_name(identifier)
    if not model or model in {"0,1,2", "0,1", "1"}:
        return None
    if model in _MODEL_LABELS:
        return _MODEL_LABELS[model]
    if model.startswith("AppleTV"):
        return f"Apple TV ({model})"
    if model.startswith("AudioAccessory") or model.startswith("HomePod"):
        return f"Apple HomePod ({model})"
    if model.startswith("Mac"):
        return f"Apple Mac ({model})"
    if model.startswith("iPhone"):
        return f"Apple iPhone ({model})"
    if model.startswith("iPad"):
        return f"Apple iPad ({model})"
    if model.startswith("Watch"):
        return f"Apple Watch ({model})"
    return model


def analyze_apple_service(
    service: str,
    instance: Any,
    host: Any,
    properties: dict[str, Any] | None,
) -> dict[str, Any]:
    """Extract safe name, model, vendor, and exact-address link evidence."""
    properties = properties or {}
    service_key = str(service or "").casefold()
    source = _SERVICE_SOURCES.get(service_key, "mdns_service_name")

    txt_name = _property(properties, "fn", "name")
    name = normalize_apple_instance(txt_name or instance, service_key)
    name_origin = "txt" if txt_name else "service_instance"
    if not name and service_key in _SERVICE_SOURCES:
        host_label = str(host or "").removesuffix(".").removesuffix(".local")
        name = clean_name(host_label.replace("-", " "))
        if name:
            source = "apple_bonjour_host_name"
            name_origin = "host_name"
    model_id = _property(properties, "model", "am", "rpMd")
    if service_key in {
        "_hap._tcp.local.", "_homekit._tcp.local.", "_device-info._tcp.local.",
    }:
        model_id = model_id or _property(properties, "md")
    model = apple_model_label(model_id)
    manufacturer = clean_name(_property(properties, "manufacturer"))

    apple_hardware = bool(
        (manufacturer and manufacturer.casefold() == "apple")
        or any(model_id.startswith(prefix) for prefix in _APPLE_MODEL_PREFIXES)
        or service_key == "_companion-link._tcp.local."
    )
    device_mac = _property(properties, "deviceid")
    bluetooth_mac = _property(properties, "btaddr", "rpBA")
    device_mac = device_mac.lower() if _MAC.fullmatch(device_mac) else ""
    bluetooth_mac = bluetooth_mac.lower() if _MAC.fullmatch(bluetooth_mac) else ""

    evidence = {
        "service": service_key,
        "host": str(host or "").rstrip("."),
        "apple_hardware": apple_hardware,
        "name_origin": name_origin,
    }
    if manufacturer:
        evidence["manufacturer"] = manufacturer
    if model_id:
        evidence["model_identifier"] = model_id[:80]
    if model:
        evidence["model"] = model

    return {
        "name": name,
        "source": source,
        "model": model,
        "model_identifier": model_id,
        "manufacturer": manufacturer,
        "apple_hardware": apple_hardware,
        "device_mac": device_mac,
        "bluetooth_mac": bluetooth_mac,
        "evidence": evidence,
    }
