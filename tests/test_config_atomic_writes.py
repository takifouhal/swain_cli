from pathlib import Path

import pytest

import swain_cli.config as config
from swain_cli.config import ProfileConfig
from swain_cli.errors import CLIError

try:
    import tomllib  # py311+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib


def test_write_default_config_writes_valid_toml(tmp_path: Path) -> None:
    target = tmp_path / "config.toml"
    assert not target.exists()

    config.write_default_config(target, force=False)

    payload = tomllib.loads(target.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)


def test_write_default_config_atomic_failure_keeps_original(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "config.toml"
    original = 'swain_base_url = "https://api.original.example"\n'
    target.write_text(original, encoding="utf-8")

    def fail_replace(src, dst):
        _ = src
        _ = dst
        raise OSError("boom")

    monkeypatch.setattr(config.os, "replace", fail_replace)

    with pytest.raises(CLIError):
        config.write_default_config(target, force=True)

    assert target.read_text(encoding="utf-8") == original


def test_upsert_profile_writes_valid_toml(tmp_path: Path) -> None:
    target = tmp_path / "config.toml"

    profile = ProfileConfig(
        languages=["python"],
        engine="embedded",
        generator_version="7.6.0",
    )
    config.upsert_profile("backend", profile, overwrite=True, path=target)

    payload = tomllib.loads(target.read_text(encoding="utf-8"))
    assert payload["profiles"]["backend"]["languages"] == ["python"]
    assert payload["profiles"]["backend"]["engine"] == "embedded"
    assert payload["profiles"]["backend"]["generator_version"] == "7.6.0"


def test_upsert_profile_atomic_failure_keeps_original(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "config.toml"
    original = "swain_base_url = \"https://api.original.example\"\n"
    target.write_text(original, encoding="utf-8")

    profile = ProfileConfig(languages=["python"])

    def fail_replace(src, dst):
        _ = src
        _ = dst
        raise OSError("boom")

    monkeypatch.setattr(config.os, "replace", fail_replace)

    with pytest.raises(CLIError):
        config.upsert_profile("backend", profile, overwrite=True, path=target)

    assert target.read_text(encoding="utf-8") == original
