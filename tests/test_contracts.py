import json

from typer.testing import CliRunner

import swain_cli.cli as cli

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
