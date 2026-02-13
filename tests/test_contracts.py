import json

from typer.testing import CliRunner

import swain_cli.cli as cli
import swain_cli.constants as constants

runner = CliRunner()


def test_engine_paths_json_contract() -> None:
    result = runner.invoke(cli.app, ["engine", "paths", "--json"])
    assert result.exit_code == 0

    payload = json.loads(result.stdout)

    assert set(payload.keys()) == {
        "platform",
        "cache_root",
        "downloads_dir",
        "jar_cache_dir",
        "jre_install_dir",
        "schema_cache_dir",
    }
    assert set(payload["platform"].keys()) == {"os", "arch"}
    for key in (
        "cache_root",
        "downloads_dir",
        "jar_cache_dir",
        "jre_install_dir",
        "schema_cache_dir",
    ):
        assert isinstance(payload[key], str)
        assert payload[key]


def test_config_show_json_contract(tmp_path) -> None:
    config_path = tmp_path / "config.toml"
    result = runner.invoke(
        cli.app,
        ["config", "show", "--json"],
        env={constants.CONFIG_ENV_VAR: str(config_path)},
    )
    assert result.exit_code == 0

    payload = json.loads(result.stdout)

    assert set(payload.keys()) == {"path", "values", "sources"}
    assert isinstance(payload["path"], str)
    assert isinstance(payload["values"], dict)
    assert isinstance(payload["sources"], dict)


def test_plugins_list_json_contract(tmp_path) -> None:
    config_path = tmp_path / "config.toml"
    result = runner.invoke(
        cli.app,
        ["plugins", "list", "--json"],
        env={constants.CONFIG_ENV_VAR: str(config_path)},
    )
    assert result.exit_code == 0

    payload = json.loads(result.stdout)
    assert set(payload.keys()) == {"plugins"}
    assert isinstance(payload["plugins"], list)

    for row in payload["plugins"]:
        assert set(row.keys()) == {"name", "value", "loaded", "error"}


def test_gen_plan_only_json_contract_redacts_secrets(tmp_path) -> None:
    config_path = tmp_path / "config.toml"
    schema = "https://api.example.com/dynamic-swagger?token=secret"

    result = runner.invoke(
        cli.app,
        [
            "gen",
            "--schema",
            schema,
            "-o",
            "out",
            "-l",
            "python",
            "--plan-only",
            "--plan-format",
            "json",
        ],
        env={
            constants.CONFIG_ENV_VAR: str(config_path),
            constants.CACHE_ENV_VAR: str(tmp_path / "cache"),
        },
    )
    assert result.exit_code == 0

    assert "token=secret" not in result.stdout
    assert "token=***" in result.stdout

    payload = json.loads(result.stdout)
    assert set(payload.keys()) == {"mode", "schema", "settings", "engine", "generator", "runs"}
    assert payload["mode"] == "plan-only"
    assert isinstance(payload["runs"], list)
    assert payload["runs"]
    assert set(payload["runs"][0].keys()) == {
        "language",
        "resolved_language",
        "out_dir",
        "generator_args",
    }
