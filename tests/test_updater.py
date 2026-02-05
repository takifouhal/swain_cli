from __future__ import annotations

from types import SimpleNamespace

import pytest

import swain_cli.updater as updater
from swain_cli.errors import CLIError


def test_normalize_tag() -> None:
    assert updater._normalize_tag("") == "latest"
    assert updater._normalize_tag("latest") == "latest"
    assert updater._normalize_tag("v0.3.14") == "v0.3.14"
    assert updater._normalize_tag("0.3.14") == "v0.3.14"


def test_asset_name_windows_arm64_falls_back(monkeypatch) -> None:
    monkeypatch.setattr(
        updater,
        "get_platform_info",
        lambda: SimpleNamespace(os_name="windows", arch="arm64"),
    )
    assert updater._asset_name() == "swain_cli-windows-x86_64.exe"


def test_build_update_asset_latest(monkeypatch) -> None:
    monkeypatch.setattr(
        updater,
        "get_platform_info",
        lambda: SimpleNamespace(os_name="linux", arch="x86_64"),
    )
    asset = updater.build_update_asset("latest")
    assert asset.tag == "latest"
    assert asset.asset_name == "swain_cli-linux-x86_64"
    assert "/releases/latest/download/" in asset.asset_url
    assert asset.checksum_url.endswith(".sha256")
    assert asset.signature_url.endswith(".asc")


def test_parse_sha256_text() -> None:
    digest = "a" * 64
    assert updater._parse_sha256_text(f"{digest}  swain_cli") == digest
    assert updater._parse_sha256_text(f"SHA256 (swain_cli) = {digest}") == digest
    with pytest.raises(CLIError):
        updater._parse_sha256_text("no digest here")
