"""The authorization gate must refuse anything not explicitly allowed."""

from __future__ import annotations

import pytest

from web_vul_scanner.core.authorization import Authorization, UnauthorizedTargetError


def test_non_loopback_host_is_refused_by_default() -> None:
    auth = Authorization()
    assert not auth.is_allowed("http://example.com/login")
    with pytest.raises(UnauthorizedTargetError):
        auth.ensure_allowed("http://example.com/login")


def test_explicitly_allowed_host_passes() -> None:
    auth = Authorization(["example.com"])
    auth.ensure_allowed("http://example.com/anything")
    assert auth.is_allowed("https://example.com/other")


def test_allow_accepts_host_port_and_url_forms() -> None:
    assert Authorization(["example.com:8080"]).is_allowed("http://example.com:8080/")
    assert Authorization(["http://example.com/x"]).is_allowed("http://example.com/y")


def test_port_specific_allow_does_not_leak_to_other_ports() -> None:
    auth = Authorization(["example.com:8080"])
    assert auth.is_allowed("http://example.com:8080/")
    assert not auth.is_allowed("http://example.com:9090/")


@pytest.mark.parametrize(
    "url",
    ["http://127.0.0.1:5000/", "http://localhost:5000/", "http://[::1]:5000/"],
)
def test_loopback_is_allowed_by_default(url: str) -> None:
    assert Authorization().is_allowed(url)


def test_loopback_can_be_disabled() -> None:
    auth = Authorization(allow_loopback=False)
    assert not auth.is_allowed("http://127.0.0.1:5000/")
