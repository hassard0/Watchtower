import ast
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from watchtower.wifi import (
    WifiError,
    queue_request,
    security_kind,
    split_nmcli_terse,
    token_valid,
    validate_connect_request,
)


def test_nmcli_terse_parser_unescapes_colons_and_backslashes():
    assert split_nmcli_terse(r"*:Cafe\: Upstairs:91:WPA2:2412:1") == [
        "*", "Cafe: Upstairs", "91", "WPA2", "2412", "1",
    ]
    assert split_nmcli_terse(r"name\\with\\slashes:uuid:wifi:yes")[0] == r"name\with\slashes"


@pytest.mark.parametrize(
    ("label", "expected"),
    [("", "open"), ("--", "open"), ("WPA2", "wpa2"), ("WPA2 WPA3 SAE", "wpa3")],
)
def test_security_kind(label, expected):
    assert security_kind(label) == expected


def test_validate_connect_request_never_returns_extra_fields():
    assert validate_connect_request({
        "ssid": "Home", "security": "wpa2", "password": "correct horse", "ignored": "x",
    }) == {"ssid": "Home", "security": "wpa2", "password": "correct horse"}


def test_validate_connect_request_rejects_short_secret_and_long_ssid():
    with pytest.raises(WifiError, match="8 to 63"):
        validate_connect_request({"ssid": "Home", "security": "wpa2", "password": "short"})
    with pytest.raises(WifiError, match="1 and 32 bytes"):
        validate_connect_request({"ssid": "é" * 17, "security": "open"})


def test_open_network_discards_supplied_password():
    assert validate_connect_request({
        "ssid": "Guest", "security": "open", "password": "should-not-be-kept",
    })["password"] == ""


def test_queue_request_is_private_and_atomic(tmp_path: Path):
    (tmp_path / "results").mkdir()
    request_id = queue_request("connect", {"ssid": "Home", "password": "secret"}, tmp_path)
    request = json.loads((tmp_path / "request.json").read_text())
    assert request["request_id"] == request_id
    assert request["action"] == "connect"
    assert not list(tmp_path.glob(".*.tmp"))
    if os.name != "nt":
        assert (tmp_path / "request.json").stat().st_mode & 0o777 == 0o600
    with pytest.raises(WifiError, match="already in progress"):
        queue_request("forget", {"uuid": "x"}, tmp_path)


def test_queue_request_respects_active_helper_lock(tmp_path: Path):
    (tmp_path / "active.json").write_text("{}")
    with pytest.raises(WifiError, match="already in progress"):
        queue_request("connect", {"ssid": "Home"}, tmp_path)


def test_token_comparison(tmp_path: Path):
    token = tmp_path / "token"
    token.write_text("abcdef\n")
    assert token_valid("abcdef", token)
    assert not token_valid("abcdeg", token)
    assert not token_valid(None, token)


def test_wifi_status_redacts_credentials():
    from watchtower.wifi import wifi_status

    outputs = [
        (0, "*:Home:88:WPA2:2412:1\n:Guest:40:--:5180:36\n", ""),
        (0, "Home profile:11111111-1111-1111-1111-111111111111:wifi:yes\n", ""),
        (0, "Home\n", ""),
    ]

    def fake_nmcli(args, timeout=20.0):
        import subprocess
        rc, stdout, stderr = outputs.pop(0)
        return subprocess.CompletedProcess(args, rc, stdout, stderr)

    with patch("watchtower.wifi._nmcli", side_effect=fake_nmcli):
        status = wifi_status(rescan=True)
    assert status["current"]["ssid"] == "Home"
    assert status["networks"][1]["security"] == "open"
    assert status["saved"][0]["active"] is True
    assert "password" not in json.dumps(status).lower()


def test_networkmanager_keyfile_escaping_preserves_valid_passphrase_symbols():
    source = Path("deploy/watchtower-wifi-config").read_text(encoding="utf-8")
    tree = ast.parse(source)
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "keyfile_escape"
    )
    namespace = {}
    exec(compile(ast.Module(body=[function], type_ignores=[]), "wifi-helper", "exec"), namespace)
    escape = namespace["keyfile_escape"]
    assert escape(r"hash#semicolon;back\slash") == r"hash#semicolon;back\\slash"
    assert escape(" leading and trailing ") == r"\sleading and trailing\s"
