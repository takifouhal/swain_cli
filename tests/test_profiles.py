import json
from pathlib import Path

from typer.testing import CliRunner

import swain_cli.cli as cli
import swain_cli.constants as constants
from swain_cli.config import load_config, resolve_config_path

runner = CliRunner()


def test_load_config_parses_profiles(tmp_path, monkeypatch):
    config_path = tmp_path / "config.toml"
    monkeypatch.setenv("SWAIN_CLI_CONFIG", str(config_path))
    config_path.write_text(
        """
swain_base_url = "https://api.example.com"

[profiles.frontend]
languages = ["python", "typescript"]
engine = "embedded"
generator_version = "7.5.0"
additional_properties = ["packageName=from_profile"]
generator_arg = ["--global-property=apis=Job"]
post_hooks = ["echo hi"]
run_hooks = false

[profiles.frontend.hooks]
python = ["ruff format ."]
""".lstrip(),
        encoding="utf-8",
    )
    cfg = load_config(config_path)
    assert cfg.swain_base_url == "https://api.example.com"
    assert "frontend" in cfg.profiles
    profile = cfg.profiles["frontend"]
    assert profile.languages == ["python", "typescript"]
    assert profile.generator_version == "7.5.0"
    assert profile.additional_properties == ["packageName=from_profile"]
    assert profile.post_hooks == ["echo hi"]
    assert profile.run_hooks is False
    assert profile.post_hooks_by_language == {"python": ["ruff format ."]}


def test_profiles_cli_list_and_show_json(tmp_path, monkeypatch):
    config_path = tmp_path / "config.toml"
    monkeypatch.setenv("SWAIN_CLI_CONFIG", str(config_path))
    config_path.write_text(
        """
[profiles.backend]
languages = ["go"]
parallel = 2
""".lstrip(),
        encoding="utf-8",
    )
    list_result = runner.invoke(cli.app, ["profiles", "list", "--json"])
    assert list_result.exit_code == 0
    list_payload = json.loads(list_result.stdout)
    assert list_payload["profiles"] == [{"name": "backend", "languages": ["go"]}]

    show_result = runner.invoke(cli.app, ["profiles", "show", "backend", "--json"])
    assert show_result.exit_code == 0
    show_payload = json.loads(show_result.stdout)
    assert show_payload["name"] == "backend"
    assert show_payload["profile"]["languages"] == ["go"]
    assert show_payload["profile"]["parallel"] == 2


def test_gen_profile_applies_defaults_in_plan(monkeypatch, tmp_path):
    config_path = resolve_config_path()
    Path(config_path).write_text(
        """
[profiles.frontend]
languages = ["python"]
generator_version = "7.5.0"
additional_properties = ["packageName=from_profile"]
generator_arg = ["--global-property=apis=Job"]
parallel = 4
patch_base_url = false
""".lstrip(),
        encoding="utf-8",
    )
    result = runner.invoke(
        cli.app,
        [
            "gen",
            "--profile",
            "frontend",
            "--schema",
            "https://example.com/openapi.json",
            "--out",
            "sdks",
            "--plan-only",
            "--plan-format",
            "json",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["generator"]["version"] == "7.5.0"
    assert payload["settings"]["parallel"] == 4
    assert payload["settings"]["patch_base_url"] is False
    assert payload["runs"][0]["resolved_language"] == "python"

    cmd = payload["runs"][0]["generator_args"]
    assert "packageName=from_profile" in cmd
    assert "--global-property=apis=Job" in cmd


def test_gen_profile_does_not_override_explicit_flags(tmp_path, monkeypatch):
    config_path = tmp_path / "config.toml"
    monkeypatch.setenv("SWAIN_CLI_CONFIG", str(config_path))
    config_path.write_text(
        """
[profiles.frontend]
languages = ["python"]
parallel = 4
patch_base_url = false
""".lstrip(),
        encoding="utf-8",
    )
    result = runner.invoke(
        cli.app,
        [
            "gen",
            "--profile",
            "frontend",
            "--schema",
            "https://example.com/openapi.json",
            "--out",
            "sdks",
            "--parallel",
            "2",
            "--patch-base-url",
            "--plan-only",
            "--plan-format",
            "json",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["settings"]["parallel"] == 2
    assert payload["settings"]["patch_base_url"] is True


def test_profiles_show_unknown_profile_exits_with_usage(tmp_path, monkeypatch):
    config_path = tmp_path / "config.toml"
    monkeypatch.setenv("SWAIN_CLI_CONFIG", str(config_path))
    config_path.write_text(
        """
[profiles.backend]
languages = ["go"]
""".lstrip(),
        encoding="utf-8",
    )
    result = runner.invoke(cli.app, ["profiles", "show", "missing"])
    assert result.exit_code == constants.EXIT_CODE_USAGE
    assert "unknown profile: missing" in result.stdout
    assert "available: backend" in result.stdout
    assert "Traceback" not in result.stdout


def test_gen_unknown_profile_exits_with_usage(tmp_path, monkeypatch):
    config_path = tmp_path / "config.toml"
    monkeypatch.setenv("SWAIN_CLI_CONFIG", str(config_path))
    config_path.write_text(
        """
[profiles.frontend]
languages = ["python"]
""".lstrip(),
        encoding="utf-8",
    )
    result = runner.invoke(cli.app, ["gen", "--profile", "missing", "--out", "sdks", "--plan-only"])
    assert result.exit_code == constants.EXIT_CODE_USAGE
    assert "unknown profile: missing" in result.stdout
    assert "available: frontend" in result.stdout
    assert "Traceback" not in result.stdout
