import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))

import auth_proxy


def test_security_headers_are_stripped_case_insensitively():
    headers = [
        ("x-openhost-is-owner", "true"),
        ("X-WebAuth-User", "attacker"),
        ("Remote-User", "attacker"),
        ("Accept", "text/html"),
    ]

    result = auth_proxy._strip_headers(headers, auth_proxy.ALWAYS_STRIP_HEADERS)

    assert result == [("Accept", "text/html")]


def test_hop_by_hop_headers_are_stripped():
    headers = [("Connection", "keep-alive"), ("Host", "internal"), ("X-Test", "ok")]

    result = auth_proxy._strip_headers(headers, auth_proxy.HOP_BY_HOP_HEADERS)

    assert result == [("X-Test", "ok")]


def test_port_from_env_uses_default(monkeypatch):
    monkeypatch.delenv("TEST_PORT", raising=False)

    assert auth_proxy._port_from_env("TEST_PORT", 8080) == 8080


@pytest.mark.parametrize("value", ["0", "65536", "nope"])
def test_port_from_env_rejects_invalid_values(monkeypatch, value):
    monkeypatch.setenv("TEST_PORT", value)

    with pytest.raises(ValueError):
        auth_proxy._port_from_env("TEST_PORT", 8080)
