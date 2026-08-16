"""NetworkManager-backed Wi-Fi status and configuration request helpers."""
from __future__ import annotations

import hmac
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4


WIFI_RUNTIME_DIR = Path("/run/watchtower-wifi")
WIFI_TOKEN_PATH = Path("/etc/watchtower/wifi-admin.token")
_SECURED = {"wpa2", "wpa3"}


class WifiError(RuntimeError):
    """A user-facing Wi-Fi management error."""


def split_nmcli_terse(line: str) -> list[str]:
    """Split nmcli's escaped terse output without losing literal colons."""
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for char in line.rstrip("\r\n"):
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    if escaped:
        current.append("\\")
    fields.append("".join(current))
    return fields


def security_kind(value: str | None) -> str:
    raw = (value or "").upper()
    if not raw or raw == "--":
        return "open"
    if "SAE" in raw or "WPA3" in raw:
        return "wpa3"
    return "wpa2"


def _nmcli(args: list[str], timeout: float = 20.0) -> subprocess.CompletedProcess[str]:
    if not shutil.which("nmcli"):
        raise WifiError("NetworkManager CLI is not installed")
    try:
        return subprocess.run(
            ["nmcli", *args], capture_output=True, text=True,
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise WifiError("NetworkManager timed out") from exc


def wifi_status(interface: str = "wlan0", *, rescan: bool = False) -> dict[str, Any]:
    """Return current, visible, and saved Wi-Fi networks without secrets."""
    scan = _nmcli([
        "--terse", "--escape", "yes",
        "--fields", "IN-USE,SSID,SIGNAL,SECURITY,FREQ,CHAN",
        "device", "wifi", "list", "ifname", interface,
        "--rescan", "yes" if rescan else "auto",
    ])
    if scan.returncode != 0:
        raise WifiError((scan.stderr or "Wi-Fi scan failed").strip()[:240])

    by_network: dict[tuple[str, str], dict[str, Any]] = {}
    for line in scan.stdout.splitlines():
        fields = split_nmcli_terse(line)
        if len(fields) < 6:
            continue
        in_use, ssid, signal, security, freq, channel = fields[:6]
        if not ssid:
            continue
        kind = security_kind(security)
        key = (ssid, kind)
        try:
            strength = max(0, min(100, int(signal)))
        except ValueError:
            strength = 0
        item = {
            "ssid": ssid,
            "signal": strength,
            "security": kind,
            "security_label": security or "Open",
            "frequency_mhz": int(freq) if freq.isdigit() else None,
            "channel": int(channel) if channel.isdigit() else None,
            "connected": in_use.strip() == "*",
        }
        previous = by_network.get(key)
        if previous is None or item["connected"] or strength > previous["signal"]:
            by_network[key] = item

    networks = sorted(
        by_network.values(),
        key=lambda item: (not item["connected"], -item["signal"], item["ssid"].lower()),
    )
    active = next((item for item in networks if item["connected"]), None)

    saved_proc = _nmcli([
        "--terse", "--escape", "yes",
        "--fields", "NAME,UUID,TYPE,AUTOCONNECT",
        "connection", "show",
    ])
    saved: list[dict[str, Any]] = []
    if saved_proc.returncode == 0:
        for line in saved_proc.stdout.splitlines():
            fields = split_nmcli_terse(line)
            if len(fields) < 4 or fields[2] not in {"wifi", "802-11-wireless"}:
                continue
            name, connection_uuid, _, autoconnect = fields[:4]
            ssid_proc = _nmcli([
                "--escape", "no", "--get-values", "802-11-wireless.ssid",
                "connection", "show", "uuid", connection_uuid,
            ], timeout=5.0)
            ssid = ssid_proc.stdout.strip() if ssid_proc.returncode == 0 else ""
            saved.append({
                "name": name,
                "uuid": connection_uuid,
                "ssid": ssid,
                "autoconnect": autoconnect.lower() == "yes",
                "active": bool(active and active["ssid"] == ssid),
            })

    return {
        "interface": interface,
        "available": True,
        "current": active,
        "networks": networks,
        "saved": sorted(saved, key=lambda item: (not item["active"], item["ssid"].lower())),
    }


def token_valid(provided: str | None, token_path: Path = WIFI_TOKEN_PATH) -> bool:
    try:
        expected = token_path.read_text(encoding="utf-8").strip()
    except OSError:
        return False
    return bool(provided and expected and hmac.compare_digest(provided.strip(), expected))


def validate_connect_request(body: dict[str, Any]) -> dict[str, str]:
    ssid = str(body.get("ssid") or "").strip()
    security = str(body.get("security") or "wpa2").lower()
    password = str(body.get("password") or "")
    if not ssid or len(ssid.encode("utf-8")) > 32:
        raise WifiError("SSID must be between 1 and 32 bytes")
    if any(ord(char) < 32 for char in ssid):
        raise WifiError("SSID contains unsupported control characters")
    if security not in {"open", *_SECURED}:
        raise WifiError("Unsupported Wi-Fi security type")
    if security in _SECURED:
        if not 8 <= len(password) <= 63:
            raise WifiError("Wi-Fi password must be 8 to 63 characters")
        if any(ord(char) < 32 for char in password):
            raise WifiError("Wi-Fi password contains unsupported control characters")
    else:
        password = ""
    return {"ssid": ssid, "security": security, "password": password}


def queue_request(
    action: str,
    payload: dict[str, Any],
    runtime_dir: Path = WIFI_RUNTIME_DIR,
) -> str:
    if action not in {"connect", "forget"}:
        raise WifiError("Unsupported Wi-Fi action")
    if not runtime_dir.is_dir():
        raise WifiError("Wi-Fi configuration helper is not installed")
    request_path = runtime_dir / "request.json"
    active_path = runtime_dir / "active.json"
    if request_path.exists() or active_path.exists():
        raise WifiError("Another Wi-Fi change is already in progress")

    request_id = str(uuid4())
    request = {"request_id": request_id, "action": action, **payload}
    temp_path = runtime_dir / f".{request_id}.tmp"
    try:
        with temp_path.open("x", encoding="utf-8") as handle:
            os.chmod(temp_path, 0o600)
            json.dump(request, handle, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        temp_path.replace(request_path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise
    return request_id


def read_result(request_id: str, runtime_dir: Path = WIFI_RUNTIME_DIR) -> dict[str, Any] | None:
    try:
        safe_id = str(UUID(request_id))
    except (ValueError, TypeError) as exc:
        raise WifiError("Invalid request identifier") from exc
    path = runtime_dir / "results" / f"{safe_id}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WifiError("Wi-Fi helper returned an invalid result") from exc
