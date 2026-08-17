"""Static safety checks for the Pi-side private HTTPS deployment."""
from pathlib import Path


DEPLOY = Path(__file__).parents[1] / "deploy"


def test_nginx_redirects_http_and_proxies_https_to_loopback():
    config = (DEPLOY / "watchtower-nginx.conf").read_text(encoding="utf-8")
    assert "return 308 https://$host$request_uri;" in config
    assert "listen 443 ssl default_server;" in config
    assert "proxy_pass http://127.0.0.1:8080;" in config
    assert "ssl_protocols TLSv1.2 TLSv1.3;" in config


def test_ca_bootstrap_exposes_certificate_not_private_key():
    config = (DEPLOY / "watchtower-nginx.conf").read_text(encoding="utf-8")
    assert "location = /watchtower-ca.crt" in config
    assert "alias /etc/watchtower/tls/watchtower-ca.crt;" in config
    assert "watchtower-ca.key" not in config


def test_certificate_refresh_preserves_ca_and_protects_keys():
    script = (DEPLOY / "watchtower-cert-refresh.sh").read_text(encoding="utf-8")
    assert "refusing to replace its trust identity" in script
    assert 'chmod 0600 "$CA_KEY"' in script
    assert 'install -o root -g root -m 0600 "$tmp_dir/watchtower.key"' in script
    assert "extendedKeyUsage=serverAuth" in script
    assert "OnUnitActiveSec=15min" in (
        DEPLOY / "watchtower-cert-refresh.timer"
    ).read_text(encoding="utf-8")


def test_installer_upgrades_configs_without_an_api_section():
    script = (DEPLOY / "install-https.sh").read_text(encoding="utf-8")
    assert "if grep -q '^\\[api\\]'" in script
    assert "printf '\\n[api]\\nhost" in script
