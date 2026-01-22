import json
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

import swain_cli.constants as constants
import swain_cli.generator as generator
import swain_cli.swain_api as swain_api
from swain_cli.args import GenArgs


def test_typescript_alias():
    assert constants.LANGUAGE_ALIASES["typescript"] == "typescript-axios"


def test_build_generate_command_alias(tmp_path):
    args = GenArgs(
        out=str(tmp_path),
        languages=["typescript"],
        config=None,
        templates=None,
        additional_properties=[],
        generator_arg=[],
        system_properties=[],
        skip_validate_spec=False,
        verbose=False,
    )
    resolved, target, cmd = generator.build_generate_command(
        "schema.yaml", "typescript", args, tmp_path
    )
    assert resolved == "typescript-axios"
    assert target == tmp_path / "typescript-axios"
    assert cmd[:7] == [
        "generate",
        "-i",
        "schema.yaml",
        "-g",
        "typescript-axios",
        "-o",
        str(target),
    ]


def test_handle_gen_with_crudsql(monkeypatch, tmp_path):
    schema_file = tmp_path / "schema.json"

    monkeypatch.setenv(constants.TENANT_ID_ENV_VAR, "101")

    def fake_fetch(url, token, tenant_id=None):
        assert url == "https://api.example.com"
        assert token == "token-abc"
        assert tenant_id == "101"
        schema_file.write_text(
            '{"swagger":"2.0","host":"","schemes":[],"basePath":"/api","paths":{}}'
        )
        return schema_file

    captured = {}

    def fake_run(jar, engine, cmd, java_opts):
        captured["cmd"] = cmd
        captured["java_opts"] = java_opts
        schema_path = cmd[cmd.index("-i") + 1]
        spec = json.loads(Path(schema_path).read_text())
        assert spec["host"] == "api.example.com"
        assert spec["schemes"] == ["https"]
        assert spec["basePath"] == "/api"
        return 0, ""

    monkeypatch.setattr(generator, "fetch_crudsql_schema", fake_fetch)
    monkeypatch.setattr(generator, "require_auth_token", lambda purpose="": "token-abc")
    monkeypatch.setattr(generator, "resolve_generator_jar", lambda version: tmp_path / "jar.jar")
    monkeypatch.setattr(generator, "run_openapi_generator", fake_run)

    args = GenArgs(
        generator_version=None,
        engine="embedded",
        schema=None,
        crudsql_url="https://api.example.com",
        swain_base_url=None,
        swain_project_id=None,
        swain_connection_id=None,
        out=str(tmp_path / "out"),
        languages=["python"],
        config=None,
        templates=None,
        additional_properties=[],
        generator_arg=[],
        system_properties=[],
        skip_validate_spec=False,
        verbose=False,
        swain_tenant_id=None,
        java_opts=[],
    )

    assert generator.handle_gen(args) == 0
    assert "cmd" in captured
    assert captured.get("java_opts") == constants.DEFAULT_JAVA_OPTS
    cmd = captured["cmd"]
    assert constants.SKIP_OPERATION_EXAMPLE_FLAG in cmd
    assert any(constants.GLOBAL_PROPERTY_DISABLE_DOCS in part for part in cmd)
    assert not schema_file.exists()
    assert os.path.isdir(args.out)


def test_handle_gen_derives_crud_base_from_swain_base(monkeypatch, tmp_path):
    schema_file = tmp_path / "schema.json"
    captured: Dict[str, Any] = {}

    def fake_fetch(base, token, tenant_id=None):
        captured["crud_base"] = base
        schema_file.write_text(
            '{"swagger":"2.0","host":"","schemes":[],"basePath":"/api","paths":{}}'
        )
        return schema_file

    def fake_determine(base, token, provided, *, allow_prompt):
        captured["swain_base"] = base
        return "11"

    monkeypatch.setattr(generator, "fetch_crudsql_schema", fake_fetch)
    monkeypatch.setattr(generator, "determine_swain_tenant_id", fake_determine)
    monkeypatch.setattr(generator, "require_auth_token", lambda purpose="": "token-abc")
    monkeypatch.setattr(generator, "resolve_generator_jar", lambda version: tmp_path / "jar.jar")

    def fake_run(jar, engine, cmd, java_opts):
        schema_path = cmd[cmd.index("-i") + 1]
        spec = json.loads(Path(schema_path).read_text())
        assert spec["host"] == "api.example.com"
        assert spec["schemes"] == ["https"]
        assert spec["basePath"] == "/crud/api"
        return 0, ""

    monkeypatch.setattr(generator, "run_openapi_generator", fake_run)

    args = GenArgs(
        generator_version=None,
        engine="embedded",
        schema=None,
        crudsql_url=None,
        swain_base_url="https://api.example.com",
        swain_project_id=None,
        swain_connection_id=None,
        out=str(tmp_path / "out"),
        languages=["python"],
        config=None,
        templates=None,
        additional_properties=[],
        generator_arg=[],
        swain_tenant_id=None,
        system_properties=[],
        skip_validate_spec=False,
        verbose=False,
        java_opts=[],
    )

    assert generator.handle_gen(args) == 0
    assert captured["swain_base"] == "https://api.example.com"
    assert captured["crud_base"] == "https://api.example.com/crud"
    assert not schema_file.exists()


def test_handle_gen_defaults_to_swain(monkeypatch, tmp_path):
    schema_file = tmp_path / "schema.json"

    monkeypatch.setenv(constants.TENANT_ID_ENV_VAR, "202")

    def fake_fetch(url, token, tenant_id=None):
        assert url == constants.DEFAULT_CRUDSQL_API_BASE_URL
        assert token == "token-default"
        assert tenant_id == "202"
        schema_file.write_text(
            '{"swagger":"2.0","host":"","schemes":[],"basePath":"/api","paths":{}}'
        )
        return schema_file

    monkeypatch.setattr(generator, "fetch_crudsql_schema", fake_fetch)
    monkeypatch.setattr(generator, "require_auth_token", lambda purpose="": "token-default")
    monkeypatch.setattr(generator, "resolve_generator_jar", lambda version: tmp_path / "jar.jar")
    monkeypatch.setattr(
        generator,
        "run_openapi_generator",
        lambda jar, engine, cmd, java_opts: (0, ""),
    )

    out_dir = tmp_path / "out"
    args = GenArgs(
        generator_version=None,
        engine="embedded",
        schema=None,
        crudsql_url=None,
        swain_base_url=None,
        swain_project_id=None,
        swain_connection_id=None,
        out=str(out_dir),
        languages=["python"],
        config=None,
        templates=None,
        additional_properties=[],
        generator_arg=[],
        swain_tenant_id=None,
        system_properties=[],
        skip_validate_spec=False,
        verbose=False,
        java_opts=[],
    )

    assert generator.handle_gen(args) == 0
    assert not schema_file.exists()
    assert out_dir.is_dir()


def test_handle_gen_with_swain_connection(monkeypatch, tmp_path):
    connection = swain_api.SwainConnection(
        id=77,
        database_name="main-db",
        driver="postgres",
        stage="prod",
        project_name="Alpha",
        schema_name="public",
        build_id=12,
        build_endpoint="https://build.example.com",
        connection_endpoint=None,
        raw={"id": 77, "project_id": 99},
    )
    schema_file = tmp_path / "swain.json"

    def fake_fetch_schema(base, conn, token, tenant_id=None):
        assert base == "https://api.example.com"
        assert conn.id == connection.id
        assert token == "token-swain"
        assert tenant_id == "303"
        schema_file.write_text(
            '{"swagger":"2.0","host":"","schemes":[],"basePath":"/api","paths":{}}'
        )
        return schema_file

    captured: Dict[str, Any] = {}

    def fake_run(jar, engine, cmd, java_opts):
        captured["cmd"] = cmd
        captured["java_opts"] = java_opts
        schema_path = cmd[cmd.index("-i") + 1]
        spec = json.loads(Path(schema_path).read_text())
        assert spec["host"] == "build.example.com"
        assert spec["schemes"] == ["https"]
        return 0, ""

    monkeypatch.setenv(constants.TENANT_ID_ENV_VAR, "303")

    def fake_fetch_connection(base, token, cid, tenant_id=None):
        assert tenant_id == "303"
        return connection

    monkeypatch.setattr(generator, "fetch_swain_connection_by_id", fake_fetch_connection)
    monkeypatch.setattr(generator, "fetch_swain_connection_schema", fake_fetch_schema)
    monkeypatch.setattr(generator, "require_auth_token", lambda purpose="": "token-swain")
    monkeypatch.setattr(generator, "resolve_generator_jar", lambda version: tmp_path / "jar.jar")
    monkeypatch.setattr(generator, "run_openapi_generator", fake_run)

    args = GenArgs(
        generator_version=None,
        engine="embedded",
        schema=None,
        crudsql_url="https://api.example.com",
        swain_base_url="https://api.example.com",
        swain_project_id=None,
        swain_connection_id=connection.id,
        swain_tenant_id=None,
        out=str(tmp_path / "out"),
        languages=["python"],
        config=None,
        templates=None,
        additional_properties=[],
        generator_arg=[],
        system_properties=[],
        skip_validate_spec=False,
        verbose=False,
        java_opts=[],
    )

    assert generator.handle_gen(args) == 0
    assert "cmd" in captured
    assert captured.get("java_opts") == constants.DEFAULT_JAVA_OPTS
    assert not schema_file.exists()


def test_handle_gen_retries_on_out_of_memory(monkeypatch, tmp_path):
    schema_file = tmp_path / "schema.json"
    schema_file.write_text("{}")

    monkeypatch.setenv(constants.TENANT_ID_ENV_VAR, "999")
    monkeypatch.setattr(generator, "resolve_generator_jar", lambda version: tmp_path / "jar.jar")
    monkeypatch.setattr(generator, "require_auth_token", lambda purpose="": "token")
    monkeypatch.setattr(
        generator,
        "fetch_crudsql_schema",
        lambda base, token, tenant_id=None: schema_file,
    )

    calls: List[Tuple[List[str], int]] = []

    def fake_run(jar, engine, cmd, java_opts):
        call_index = len(calls)
        if call_index == 0:
            assert java_opts == constants.DEFAULT_JAVA_OPTS
            calls.append((java_opts, call_index))
            return 1, "java.lang.OutOfMemoryError"
        assert any(
            opt.startswith(constants.FALLBACK_JAVA_HEAP_OPTION) for opt in java_opts
        )
        calls.append((java_opts, call_index))
        return 0, ""

    monkeypatch.setattr(generator, "run_openapi_generator", fake_run)

    args = GenArgs(
        generator_version=None,
        engine="embedded",
        schema=None,
        crudsql_url="https://api.example.com",
        swain_base_url=None,
        swain_project_id=None,
        swain_connection_id=None,
        out=str(tmp_path / "out"),
        languages=["python"],
        config=None,
        templates=None,
        additional_properties=[],
        generator_arg=[],
        system_properties=[],
        skip_validate_spec=False,
        verbose=False,
        swain_tenant_id=None,
        java_opts=[],
    )

    assert generator.handle_gen(args) == 0
    assert len(calls) == 2


def test_handle_gen_disables_docs_when_out_of_memory_with_custom_java(monkeypatch, tmp_path):
    schema_file = tmp_path / "schema.json"
    schema_file.write_text("{}")

    monkeypatch.setenv(constants.TENANT_ID_ENV_VAR, "777")
    monkeypatch.setattr(generator, "resolve_generator_jar", lambda version: tmp_path / "jar.jar")
    monkeypatch.setattr(generator, "require_auth_token", lambda purpose="": "token")
    monkeypatch.setattr(
        generator,
        "fetch_crudsql_schema",
        lambda base, token, tenant_id=None: schema_file,
    )

    calls: List[List[str]] = []

    def fake_run(jar, engine, cmd, java_opts):
        calls.append(list(cmd))
        if len(calls) == 1:
            return 1, "java.lang.OutOfMemoryError"
        return 0, ""

    monkeypatch.setattr(generator, "run_openapi_generator", fake_run)

    args = GenArgs(
        generator_version=None,
        engine="embedded",
        schema=None,
        crudsql_url="https://api.example.com",
        swain_base_url=None,
        swain_project_id=None,
        swain_connection_id=None,
        out=str(tmp_path / "out"),
        languages=["go"],
        config=None,
        templates=None,
        additional_properties=[],
        generator_arg=[],
        system_properties=[],
        skip_validate_spec=False,
        verbose=False,
        swain_tenant_id=None,
        java_opts=["-Xmx6g"],
    )

    assert generator.handle_gen(args) == 0
    assert len(calls) == 2
    first_cmd, second_cmd = calls
    assert any("apiDocs=false" in part for part in first_cmd)
    assert any("apiDocs=false" in part for part in second_cmd)
