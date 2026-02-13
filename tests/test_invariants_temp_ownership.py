import json
from pathlib import Path

import swain_cli.generator as generator
from swain_cli.args import GenArgs
from swain_cli.plugins import PluginSchemaResult


def test_gen_does_not_delete_explicit_schema_path(monkeypatch, tmp_path) -> None:
    schema_file = tmp_path / "schema.json"
    schema_file.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(generator, "resolve_generator_jar", lambda version: tmp_path / "jar.jar")

    def fake_run(jar, engine, cmd, java_opts):
        schema_path = Path(cmd[cmd.index("-i") + 1])
        assert schema_path == schema_file
        assert schema_path.exists()
        return 0, ""

    monkeypatch.setattr(generator, "run_openapi_generator", fake_run)

    args = GenArgs(
        out=str(tmp_path / "out"),
        languages=["python"],
        schema=str(schema_file),
    )

    assert generator.handle_gen(args) == 0
    assert schema_file.exists()


def test_gen_deletes_plugin_schema_when_owned(monkeypatch, tmp_path) -> None:
    schema_file = tmp_path / "plugin_schema.json"
    schema_file.write_text(
        json.dumps({"swagger": "2.0", "host": "", "schemes": [], "basePath": "/api", "paths": {}}),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        generator,
        "resolve_schema_with_plugins",
        lambda *a, **k: PluginSchemaResult(schema=str(schema_file), temp_path=schema_file),
    )
    monkeypatch.setattr(generator, "resolve_generator_jar", lambda version: tmp_path / "jar.jar")

    def fake_run(jar, engine, cmd, java_opts):
        schema_path = Path(cmd[cmd.index("-i") + 1])
        assert schema_path == schema_file
        assert schema_path.exists()
        return 0, ""

    monkeypatch.setattr(generator, "run_openapi_generator", fake_run)

    args = GenArgs(
        out=str(tmp_path / "out"),
        languages=["python"],
    )

    assert generator.handle_gen(args) == 0
    assert not schema_file.exists()
