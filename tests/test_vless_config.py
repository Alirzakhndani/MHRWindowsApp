from pathlib import Path
from urllib.parse import parse_qs, urlparse, unquote
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vless_config import build_vless_uri, config_to_vless_defaults, stable_uuid


def test_build_vless_uri_for_v2box_ws_tls():
    uri = build_vless_uri(
        user_id="550e8400-e29b-41d4-a716-446655440000",
        address="example.com",
        port=443,
        name="iPhone Profile",
        host="cdn.example.com",
        path="/vless",
        sni="example.com",
    )

    parsed = urlparse(uri)
    params = parse_qs(parsed.query)

    assert parsed.scheme == "vless"
    assert parsed.username == "550e8400-e29b-41d4-a716-446655440000"
    assert parsed.hostname == "example.com"
    assert parsed.port == 443
    assert params["encryption"] == ["none"]
    assert params["security"] == ["tls"]
    assert params["type"] == ["ws"]
    assert params["host"] == ["cdn.example.com"]
    assert params["path"] == ["/vless"]
    assert params["sni"] == ["example.com"]
    assert unquote(parsed.fragment) == "iPhone Profile"


def test_stable_uuid_derives_repeatable_uuid_from_auth_key():
    assert stable_uuid("secret-auth-key") == stable_uuid("secret-auth-key")
    assert stable_uuid("secret-auth-key") != stable_uuid("another-secret")


def test_config_to_vless_defaults_for_apps_script():
    defaults = config_to_vless_defaults(
        {
            "mode": "apps_script",
            "front_domain": "www.google.com",
            "script_id": "AKfycbExample",
            "auth_key": "secret",
            "verify_ssl": True,
        }
    )

    assert defaults["address"] == "www.google.com"
    assert defaults["host"] == "script.google.com"
    assert defaults["sni"] == "www.google.com"
    assert defaults["path"] == "/macros/s/AKfycbExample/exec"
    assert defaults["allow_insecure"] is False


def test_build_vless_uri_requires_server_address():
    with pytest.raises(ValueError, match="Server address is required"):
        build_vless_uri(user_id="secret", address="")
