import json
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest
from typer.testing import CliRunner

import swain_cli
import swain_cli.cli as cli
import swain_cli.constants as constants
import swain_cli.swain_api as swain_api

runner = CliRunner()


def test_cli_help_invocation():
    result = runner.invoke(cli.app, ["--help"])
    assert result.exit_code == 0
    assert "Usage:" in result.stdout


def test_cli_version_flag():
    result = runner.invoke(cli.app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == f"swain_cli {swain_cli.__version__}"


def test_cli_without_command_shows_help():
    result = runner.invoke(cli.app, [])
    assert result.exit_code == constants.EXIT_CODE_USAGE
    assert "Commands" in result.stdout


def test_main_returns_interrupt_code_on_keyboard_interrupt(monkeypatch):
    class FakeCommand:
        def main(self, *args, **kwargs):
            raise KeyboardInterrupt

    monkeypatch.setattr(cli.typer.main, "get_command", lambda _app: FakeCommand())
    assert cli.main(["--help"]) == constants.EXIT_CODE_INTERRUPT


def test_main_returns_interrupt_code_on_abort(monkeypatch):
    class FakeCommand:
        def main(self, *args, **kwargs):
            raise cli.typer.Abort()

    monkeypatch.setattr(cli.typer.main, "get_command", lambda _app: FakeCommand())
    assert cli.main(["--help"]) == constants.EXIT_CODE_INTERRUPT


def test_cli_interactive_accepts_java_opt_and_generator_args(monkeypatch):
    captured: Dict[str, Any] = {}

    def fake_handle_interactive(args):
        captured["java_opts"] = getattr(args, "java_opts", None)
        captured["generator_args"] = getattr(args, "generator_args", None)
        captured["crudsql_url"] = getattr(args, "crudsql_url", None)
        captured["swain_base_url"] = getattr(args, "swain_base_url", None)
        return 0

    monkeypatch.setattr(cli, "handle_interactive", fake_handle_interactive)
    result = runner.invoke(
        cli.app,
        [
            "interactive",
            "--java-opt",
            "-Xms1g",
            "--java-opt",
            "-Xmx6g",
            "--generator-arg",
            "--global-property=apis=Foo",
            "--generator-arg",
            "--skip-operation-example",
            "--swain-base-url",
            "https://api.override",
        ],
    )
    assert result.exit_code == 0
    assert captured.get("java_opts") == ["-Xms1g", "-Xmx6g"]
    assert captured.get("generator_args") == [
        "--global-property=apis=Foo",
        "--skip-operation-example",
    ]
    assert captured.get("swain_base_url") == "https://api.override"
    assert captured.get("crudsql_url") is None


def test_handle_interactive_skip_generation(monkeypatch, capfd):
    project = swain_api.SwainProject(id=1, name="Project", raw={})
    connection = swain_api.SwainConnection(
        id=2,
        database_name="main-db",
        driver="postgres",
        stage="prod",
        project_name="Project",
        schema_name="public",
        build_id=10,
        build_endpoint="https://connection.example.com",
        connection_endpoint=None,
        raw={"id": 2, "project_id": 1},
    )

    confirm_values = iter([False])

    text_values = iter(
        [
            "sdks",
            "python",
        ]
    )

    def fake_confirm(prompt, default=True):
        try:
            return next(confirm_values)
        except StopIteration:
            pytest.fail(f"unexpected confirm prompt: {prompt}")

    def fake_text(prompt, default=None, validate=None, allow_empty=False):
        try:
            value = next(text_values)
        except StopIteration:
            pytest.fail(f"unexpected text prompt: {prompt}")
        if callable(validate):
            error = validate(value)
            if error:
                pytest.fail(f"validation failed unexpectedly: {error}")
        return value

    monkeypatch.setattr(cli, "prompt_confirm", fake_confirm)
    monkeypatch.setattr(cli, "prompt_text", fake_text)
    monkeypatch.setattr(cli, "interactive_auth_setup", lambda auth_base_url=None: None)
    monkeypatch.setattr(cli, "require_auth_token", lambda purpose="": "env-token")
    monkeypatch.setattr(
        cli,
        "determine_swain_tenant_id",
        lambda base, token, provided, *, allow_prompt: provided,
    )
    monkeypatch.setattr(
        swain_api,
        "fetch_swain_projects",
        lambda base, token, tenant_id=None, **_: [project],
    )
    monkeypatch.setattr(
        swain_api,
        "fetch_swain_connections",
        lambda base, token, tenant_id=None, project_id=None, **_: [connection],
    )

    def fail_handle_gen(args):
        pytest.fail("generation should not run when user declines")

    monkeypatch.setattr(cli, "handle_gen", fail_handle_gen)

    result = cli.handle_interactive(SimpleNamespace(generator_version=None))
    assert result == 0
    out, err = capfd.readouterr()
    assert "interactive SDK generation wizard" in out
    assert "generation skipped" in out
    assert err == ""


def test_handle_interactive_runs_generation_with_tenant(monkeypatch):
    project = swain_api.SwainProject(id=102, name="Project", raw={})
    connection = swain_api.SwainConnection(
        id=110,
        database_name="main-db",
        driver="postgres",
        stage="prod",
        project_name="Project",
        schema_name="public",
        build_id=12,
        build_endpoint="https://connection.example.com",
        connection_endpoint=None,
        raw={"id": 110, "project_id": 102},
    )

    confirm_values = iter([True])

    text_values = iter(
        [
            "sdks",
            "go",
        ]
    )

    def fake_confirm(prompt, default=True):
        try:
            return next(confirm_values)
        except StopIteration:
            pytest.fail(f"unexpected confirm prompt: {prompt}")

    def fake_text(prompt, default=None, validate=None, allow_empty=False):
        try:
            value = next(text_values)
        except StopIteration:
            pytest.fail(f"unexpected text prompt: {prompt}")
        if callable(validate):
            error = validate(value)
            if error:
                pytest.fail(f"validation failed unexpectedly: {error}")
        return value

    monkeypatch.setattr(cli, "prompt_confirm", fake_confirm)
    monkeypatch.setattr(cli, "prompt_text", fake_text)
    monkeypatch.setattr(cli, "prompt_select", lambda prompt, choices: choices[0].value)
    monkeypatch.setattr(cli, "interactive_auth_setup", lambda auth_base_url=None: None)
    monkeypatch.setattr(cli, "require_auth_token", lambda purpose="": "token-xyz")

    dynamic_bases: List[str] = []

    def fake_dynamic_swagger(base):
        dynamic_bases.append(base)
        return f"{base}/api/dynamic_swagger"

    monkeypatch.setattr(cli, "crudsql_dynamic_swagger_url", fake_dynamic_swagger)

    def fake_determine(base, token, provided, *, allow_prompt):
        assert base == "https://api.example.com"
        assert token == "token-xyz"
        assert allow_prompt is True
        return "14"

    monkeypatch.setattr(cli, "determine_swain_tenant_id", fake_determine)
    seen_bases: List[str] = []

    def fake_fetch_projects(base, token, tenant_id=None, **_):
        seen_bases.append(base)
        return [project]

    def fake_fetch_connections(base, token, tenant_id=None, project_id=None, **_):
        seen_bases.append(base)
        return [connection]

    monkeypatch.setattr(swain_api, "fetch_swain_projects", fake_fetch_projects)
    monkeypatch.setattr(swain_api, "fetch_swain_connections", fake_fetch_connections)

    captured: Dict[str, Any] = {}

    def fake_handle_gen(args):
        captured["args"] = args
        return 0

    monkeypatch.setattr(cli, "handle_gen", fake_handle_gen)

    result = cli.handle_interactive(
        SimpleNamespace(
            generator_version=None,
            java_opts=["-Xmx5g"],
            generator_args=["--global-property=apis=Job"],
            swain_base_url="https://api.example.com",
        )
    )
    assert result == 0
    assert "args" in captured
    passed_args = captured["args"]
    assert passed_args.swain_tenant_id == "14"
    assert passed_args.swain_project_id == project.id
    assert passed_args.swain_connection_id == connection.id
    assert passed_args.java_opts == ["-Xmx5g"]
    assert passed_args.generator_arg == [
        "--global-property=apis=Job",
        f"--global-property={constants.GLOBAL_PROPERTY_DISABLE_DOCS}",
        constants.SKIP_OPERATION_EXAMPLE_FLAG,
    ]
    assert passed_args.swain_base_url == "https://api.example.com"
    assert passed_args.crudsql_url is None
    assert seen_bases == ["https://api.example.com", "https://api.example.com"]
    assert dynamic_bases == ["https://api.example.com/crud"]


def test_cli_projects_outputs_json(monkeypatch):
    project = swain_api.SwainProject(id=1, name="Alpha", description="demo", raw={})

    monkeypatch.setattr(cli, "require_auth_token", lambda purpose="": "token-123")

    def fake_determine(base, token, provided, *, allow_prompt):
        cli.log("tenant resolved")
        return "7"

    monkeypatch.setattr(cli, "determine_swain_tenant_id", fake_determine)
    monkeypatch.setattr(
        cli,
        "fetch_swain_projects_with_fallback",
        lambda *args, **kwargs: [project],
    )

    result = runner.invoke(cli.app, ["projects"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload == [{"id": 1, "name": "Alpha", "description": "demo"}]
    assert "tenant resolved" not in result.stdout


def test_cli_connections_requires_project_or_connection_id():
    result = runner.invoke(cli.app, ["connections"])
    assert result.exit_code == constants.EXIT_CODE_USAGE


def test_cli_connections_outputs_json(monkeypatch):
    connection = swain_api.SwainConnection(
        id=2,
        database_name="main-db",
        driver="postgres",
        stage="prod",
        project_name="Alpha",
        schema_name="public",
        build_id=10,
        build_endpoint="https://build.example.com",
        connection_endpoint="https://conn.example.com",
        raw={"id": 2, "project_id": 1},
    )

    monkeypatch.setattr(cli, "require_auth_token", lambda purpose="": "token-xyz")
    monkeypatch.setattr(
        cli,
        "determine_swain_tenant_id",
        lambda base, token, provided, *, allow_prompt: "1",
    )
    monkeypatch.setattr(
        cli,
        "fetch_swain_connections_with_fallback",
        lambda *args, **kwargs: [connection],
    )

    result = runner.invoke(cli.app, ["connections", "--project-id", "1"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload == [
        {
            "id": 2,
            "database_name": "main-db",
            "driver": "postgres",
            "stage": "prod",
            "project_name": "Alpha",
            "schema_name": "public",
            "build_id": 10,
            "endpoint": "https://conn.example.com",
        }
    ]


def test_cli_schema_outputs_schema_to_stdout_and_cleans_tempfile(monkeypatch, tmp_path):
    temp_schema = tmp_path / "schema.json"
    temp_schema.write_text('{"openapi":"3.0.0"}', encoding="utf-8")

    connection = swain_api.SwainConnection(
        id=9,
        database_name=None,
        driver=None,
        stage=None,
        project_name=None,
        schema_name=None,
        build_id=None,
        build_endpoint=None,
        connection_endpoint=None,
        raw={"id": 9},
    )

    monkeypatch.setattr(cli, "require_auth_token", lambda purpose="": "token-xyz")
    monkeypatch.setattr(
        cli,
        "determine_swain_tenant_id",
        lambda base, token, provided, *, allow_prompt: "1",
    )
    monkeypatch.setattr(
        cli,
        "fetch_swain_connection_by_id",
        lambda *args, **kwargs: connection,
    )
    monkeypatch.setattr(
        cli,
        "fetch_swain_connection_schema",
        lambda *args, **kwargs: temp_schema,
    )

    result = runner.invoke(cli.app, ["schema", "--connection-id", "9"])
    assert result.exit_code == 0
    assert result.stdout == '{"openapi":"3.0.0"}'
    assert not temp_schema.exists()


def test_cli_schema_writes_schema_to_file(monkeypatch, tmp_path):
    temp_schema = tmp_path / "temp_schema.json"
    temp_schema.write_text('{"openapi":"3.0.0"}', encoding="utf-8")

    connection = swain_api.SwainConnection(
        id=9,
        database_name=None,
        driver=None,
        stage=None,
        project_name=None,
        schema_name=None,
        build_id=None,
        build_endpoint=None,
        connection_endpoint=None,
        raw={"id": 9},
    )

    out_path = tmp_path / "out" / "schema.json"

    monkeypatch.setattr(cli, "require_auth_token", lambda purpose="": "token-xyz")
    monkeypatch.setattr(
        cli,
        "determine_swain_tenant_id",
        lambda base, token, provided, *, allow_prompt: "1",
    )
    monkeypatch.setattr(
        cli,
        "fetch_swain_connection_by_id",
        lambda *args, **kwargs: connection,
    )
    monkeypatch.setattr(
        cli,
        "fetch_swain_connection_schema",
        lambda *args, **kwargs: temp_schema,
    )

    result = runner.invoke(
        cli.app,
        ["schema", "--connection-id", "9", "--out", str(out_path)],
    )
    assert result.exit_code == 0
    assert result.stdout == ""
    assert out_path.exists()
    assert out_path.read_text(encoding="utf-8") == '{"openapi":"3.0.0"}'
    assert not temp_schema.exists()
