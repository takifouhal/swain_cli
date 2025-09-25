import base64
import io
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Tuple

import httpx
import keyring
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError
import pytest
from typer.testing import CliRunner

import swain_cli.cli as cli


class MemoryKeyring(KeyringBackend):
    priority = 1

    def __init__(self) -> None:
        self._storage = {}

    def get_password(self, service, username):
        return self._storage.get((service, username))

    def set_password(self, service, username, password):
        self._storage[(service, username)] = password

    def delete_password(self, service, username):
        try:
            del self._storage[(service, username)]
        except KeyError as exc:
            raise PasswordDeleteError(str(exc))


@pytest.fixture(autouse=True)
def memory_keyring():
    original = keyring.get_keyring()
    keyring.set_keyring(MemoryKeyring())
    try:
        yield
    finally:
        keyring.set_keyring(original)


runner = CliRunner()


def test_typescript_alias():
    assert cli.LANGUAGE_ALIASES["typescript"] == "typescript-axios"


def test_normalize_os_variants():
    assert cli.normalize_os("Darwin") == "macos"
    assert cli.normalize_os("WINDOWS") == "windows"
    assert cli.normalize_os("linux") == "linux"
    assert cli.normalize_os("FreeBSD") == "freebsd"


def test_normalize_arch_variants():
    assert cli.normalize_arch("x86_64") == "x86_64"
    assert cli.normalize_arch("AMD64") == "x86_64"
    assert cli.normalize_arch("arm64") == "arm64"
    assert cli.normalize_arch("aarch64") == "arm64"
    assert cli.normalize_arch("riscv64") == "riscv64"


def test_cache_root_honors_env(tmp_path, monkeypatch):
    custom = tmp_path / "custom-cache"
    monkeypatch.setenv(cli.CACHE_ENV_VAR, str(custom))
    result = cli.cache_root()
    assert result == custom
    assert result.is_dir()


def test_get_jre_asset_unsupported(monkeypatch):
    cli.get_platform_info.cache_clear()
    monkeypatch.setattr(cli.platform, "system", lambda: "Plan9")
    monkeypatch.setattr(cli.platform, "machine", lambda: "mips")
    with pytest.raises(cli.CLIError):
        cli.get_jre_asset()
    cli.get_platform_info.cache_clear()


def test_cli_help_invocation():
    result = runner.invoke(cli.app, ["--help"])
    assert result.exit_code == 0
    assert "Usage:" in result.stdout


def test_cli_without_command_shows_help():
    result = runner.invoke(cli.app, [])
    assert result.exit_code == cli.EXIT_CODE_USAGE
    assert "Commands" in result.stdout


def test_cli_interactive_accepts_java_opt_and_generator_args(monkeypatch):
    captured: Dict[str, Any] = {}

    def fake_handle_interactive(args):
        captured["java_opts"] = getattr(args, "java_opts", None)
        captured["generator_args"] = getattr(args, "generator_args", None)
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
        ],
    )
    assert result.exit_code == 0
    assert captured.get("java_opts") == ["-Xms1g", "-Xmx6g"]
    assert captured.get("generator_args") == [
        "--global-property=apis=Foo",
        "--skip-operation-example",
    ]


def test_build_generate_command_alias(tmp_path):
    args = SimpleNamespace(
        config=None,
        templates=None,
        additional_properties=None,
        generator_arg=None,
        property=[],
        skip_validate_spec=False,
        verbose=False,
    )
    resolved, target, cmd = cli.build_generate_command(
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


def test_crudsql_dynamic_swagger_url_variants():
    assert (
        cli.crudsql_dynamic_swagger_url("https://api.example.com")
        == "https://api.example.com/api/dynamic_swagger"
    )
    assert (
        cli.crudsql_dynamic_swagger_url("https://api.example.com/base")
        == "https://api.example.com/base/api/dynamic_swagger"
    )
    with pytest.raises(cli.CLIError):
        cli.crudsql_dynamic_swagger_url("api.example.com")


class FakeResponse:
    def __init__(self, url, *, status_code=200, content=b"", json_data=None, reason="OK"):
        self.url = url
        self.status_code = status_code
        self.content = content
        self._json_data = json_data
        self.reason_phrase = reason
        self.headers = {}
        self.text = content.decode("utf-8", "replace") if isinstance(content, bytes) else str(content)

    def json(self):
        if self._json_data is not None:
            return self._json_data
        return json.loads(self.content.decode("utf-8"))

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("GET", self.url)
            raise httpx.HTTPStatusError(
                "error",
                request=request,
                response=self,
            )


class FakeClient:
    def __init__(self, responses, calls=None):
        self._responses = list(responses)
        self.calls = [] if calls is None else calls

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def _next_response(self, url):
        if not self._responses:
            raise AssertionError("unexpected request")
        response = self._responses.pop(0)
        assert response.url == str(url)
        return response

    def get(self, url, headers=None, params=None, json=None):
        response = self._next_response(url)
        self.calls.append(("GET", str(url), headers or {}, params, json))
        return response

    def post(self, url, headers=None, params=None, json=None):
        response = self._next_response(url)
        self.calls.append(("POST", str(url), headers or {}, params, json))
        return response


def make_jwt(payload: Dict[str, Any]) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signature = base64.urlsafe_b64encode(b"signature").decode().rstrip("=")
    return f"{header}.{body}.{signature}"


def test_determine_swain_tenant_id_env(monkeypatch):
    token = make_jwt({"tenant_ids": [1, 2, 3]})
    monkeypatch.setenv(cli.TENANT_ID_ENV_VAR, "600")
    result = cli.determine_swain_tenant_id(token, None, allow_prompt=False)
    assert result == "600"


def test_determine_swain_tenant_id_single_claim(monkeypatch):
    token = make_jwt({"tenant_ids": [987]})
    monkeypatch.delenv(cli.TENANT_ID_ENV_VAR, raising=False)
    result = cli.determine_swain_tenant_id(token, None, allow_prompt=False)
    assert result == "987"


def test_determine_swain_tenant_id_multiple_claims_requires_choice(monkeypatch):
    token = make_jwt({"tenant_ids": [10, 20]})
    monkeypatch.delenv(cli.TENANT_ID_ENV_VAR, raising=False)
    with pytest.raises(cli.CLIError):
        cli.determine_swain_tenant_id(token, None, allow_prompt=False)


def test_fetch_crudsql_schema_success(monkeypatch, tmp_path):
    discovery = FakeResponse(
        "https://api.example.com/api/schema-location",
        json_data={"schema_url": "/openapi/custom.json"},
        content=b"{}",
    )
    schema = FakeResponse(
        "https://api.example.com/openapi/custom.json",
        content=b"{\"swagger\": \"2.0\"}"
    )
    calls = []

    def fake_client(**kwargs):
        if not calls:
            return FakeClient([discovery], calls)
        return FakeClient([schema], calls)

    monkeypatch.setattr(cli.httpx, "Client", fake_client)
    temp_path = cli.fetch_crudsql_schema(
        "https://api.example.com",
        "token123",
        tenant_id="42",
    )
    try:
        data = json.loads(temp_path.read_text())
        assert data["swagger"] == "2.0"
    finally:
        temp_path.unlink(missing_ok=True)
    assert [entry[1] for entry in calls] == [
        "https://api.example.com/api/schema-location",
        "https://api.example.com/openapi/custom.json",
    ]
    discovery_headers = calls[0][2]
    assert discovery_headers["Authorization"] == "Bearer token123"
    assert discovery_headers["X-Tenant-ID"] == "42"
    schema_headers = calls[1][2]
    assert schema_headers["Authorization"] == "Bearer token123"
    assert schema_headers["X-Tenant-ID"] == "42"


def test_fetch_crudsql_schema_http_error(monkeypatch):
    response = FakeResponse(
        "https://api.example.com/api/schema-location",
        status_code=401,
        content=b"denied",
        reason="Unauthorized",
    )

    def fake_client(**kwargs):
        return FakeClient([response])

    monkeypatch.setattr(cli.httpx, "Client", fake_client)
    with pytest.raises(cli.CLIError) as excinfo:
        cli.fetch_crudsql_schema(
            "https://api.example.com",
            "token123",
            tenant_id="88",
        )
    assert "401" in str(excinfo.value)


def test_fetch_crudsql_schema_falls_back(monkeypatch):
    discovery = FakeResponse(
        "https://api.example.com/api/schema-location",
        status_code=404,
        content=b"missing",
        reason="Not Found",
    )
    schema = FakeResponse(
        "https://api.example.com/api/dynamic_swagger",
        content=b"{}",
    )

    worked_calls = []

    def fake_client(**kwargs):
        if not worked_calls:
            worked_calls.append("discovery")
            return FakeClient([discovery])
        return FakeClient([schema])

    monkeypatch.setattr(cli.httpx, "Client", fake_client)
    temp_path = cli.fetch_crudsql_schema(
        "https://api.example.com",
        "token123",
        tenant_id="55",
    )
    try:
        assert temp_path.read_text() == "{}"
    finally:
        temp_path.unlink(missing_ok=True)


def test_extract_archive_unknown(tmp_path):
    archive = tmp_path / "archive.xyz"
    archive.write_text("dummy")
    with pytest.raises(cli.CLIError):
        cli.extract_archive(archive, tmp_path / "out")


def test_read_login_token_stdin(monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO("stdin-token\n"))
    args = SimpleNamespace(token=None, stdin=True, no_prompt=False)
    assert cli.read_login_token(args) == "stdin-token"


def test_read_login_token_no_prompt(monkeypatch):
    monkeypatch.delenv(cli.AUTH_TOKEN_ENV_VAR, raising=False)
    args = SimpleNamespace(token=None, stdin=False, no_prompt=True)
    with pytest.raises(cli.CLIError):
        cli.read_login_token(args)


def test_swain_login_with_credentials_success(monkeypatch):
    response = FakeResponse(
        "https://api.example.com/api/auth/login",
        json_data={"token": "abc", "refresh_token": "refresh"},
        content=b"{}",
    )

    def fake_client(**kwargs):
        return FakeClient([response])

    monkeypatch.setattr(cli.httpx, "Client", fake_client)
    data = cli.swain_login_with_credentials(
        "https://api.example.com", "user@example.com", "secret"
    )
    assert data["token"] == "abc"
    assert data["refresh_token"] == "refresh"


def test_read_login_token_with_credentials(monkeypatch):
    def fake_login(base, username, password):
        assert base == "https://api.example.com"
        assert username == "alice"
        assert password == "wonderland"
        return {"token": "abc", "refresh_token": "refresh"}

    monkeypatch.setattr(cli, "swain_login_with_credentials", fake_login)
    args = SimpleNamespace(
        token=None,
        stdin=False,
        no_prompt=False,
        username="alice",
        password="wonderland",
        credentials=False,
        auth_base_url="https://api.example.com",
    )
    token = cli.read_login_token(args)
    assert token == "abc"
    assert getattr(args, "login_refresh_token") == "refresh"


def test_read_login_token_prompts_for_missing_credentials(monkeypatch):
    monkeypatch.setattr(cli, "prompt_text", lambda *a, **k: "bob")
    monkeypatch.setattr(cli, "prompt_password", lambda *a, **k: "builder")
    monkeypatch.setattr(
        cli,
        "swain_login_with_credentials",
        lambda base, user, pwd: {"token": "xyz", "refresh_token": None},
    )
    args = SimpleNamespace(
        token=None,
        stdin=False,
        no_prompt=False,
        username=None,
        password=None,
        credentials=True,
        auth_base_url=None,
    )
    token = cli.read_login_token(args)
    assert token == "xyz"
    assert getattr(args, "login_refresh_token") is None


def test_auth_login_uses_keyring():
    args = SimpleNamespace(token="supersecret", stdin=False, no_prompt=False)
    assert cli.handle_auth_login(args) == 0
    state = cli.load_auth_state()
    assert state.access_token == "supersecret"
    assert state.refresh_token is None


def test_handle_auth_login_with_credentials(monkeypatch):
    def fake_login(base, username, password):
        assert username == "carol"
        assert password == "password123"
        return {"token": "new-token", "refresh_token": "new-refresh"}

    monkeypatch.setattr(cli, "swain_login_with_credentials", fake_login)
    args = SimpleNamespace(
        token=None,
        stdin=False,
        no_prompt=False,
        username="carol",
        password="password123",
        credentials=False,
        auth_base_url="https://api.swain.technology",
    )
    assert cli.handle_auth_login(args) == 0
    state = cli.load_auth_state()
    assert state.access_token == "new-token"
    assert state.refresh_token == "new-refresh"


def test_auth_logout_removes_token():
    args = SimpleNamespace(token="supersecret", stdin=False, no_prompt=False)
    cli.handle_auth_login(args)
    assert cli.handle_auth_logout(SimpleNamespace()) == 0
    state = cli.load_auth_state()
    assert state.access_token is None
    assert state.refresh_token is None


def test_auth_status_prefers_env(monkeypatch, capfd):
    monkeypatch.setenv(cli.AUTH_TOKEN_ENV_VAR, "env-token-value")
    assert cli.handle_auth_status(SimpleNamespace()) == 0
    out, err = capfd.readouterr()
    assert "environment variable" in out
    assert "env-token-value" not in out
    assert "effective token" in out
    assert err == ""


def test_handle_gen_with_crudsql(monkeypatch, tmp_path):
    schema_file = tmp_path / "schema.json"

    monkeypatch.setenv(cli.TENANT_ID_ENV_VAR, "101")

    def fake_fetch(url, token, tenant_id=None):
        assert url == "https://api.example.com"
        assert token == "token-abc"
        assert tenant_id == "101"
        schema_file.write_text("{}")
        return schema_file

    captured = {}

    def fake_run(jar, engine, cmd, java_opts):
        captured["cmd"] = cmd
        captured["java_opts"] = java_opts
        return 0, ""

    monkeypatch.setattr(cli, "fetch_crudsql_schema", fake_fetch)
    monkeypatch.setattr(cli, "require_auth_token", lambda purpose="": "token-abc")
    monkeypatch.setattr(cli, "resolve_generator_jar", lambda version: tmp_path / "jar.jar")
    monkeypatch.setattr(cli, "run_openapi_generator", fake_run)

    args = SimpleNamespace(
        generator_version=None,
        engine="embedded",
        schema=None,
        crudsql_url="https://api.example.com",
        swain_project_id=None,
        swain_connection_id=None,
        out=str(tmp_path / "out"),
        languages=["python"],
        config=None,
        templates=None,
        additional_properties=None,
        generator_arg=None,
        property=[],
        skip_validate_spec=False,
        verbose=False,
        swain_tenant_id=None,
    )

    assert cli.handle_gen(args) == 0
    assert "cmd" in captured
    assert captured.get("java_opts") == cli.DEFAULT_JAVA_OPTS
    assert not schema_file.exists()
    assert os.path.isdir(args.out)


def test_handle_gen_defaults_to_swain(monkeypatch, tmp_path):
    schema_file = tmp_path / "schema.json"

    monkeypatch.setenv(cli.TENANT_ID_ENV_VAR, "202")

    def fake_fetch(url, token, tenant_id=None):
        assert url == cli.DEFAULT_CRUDSQL_BASE_URL
        assert token == "token-default"
        assert tenant_id == "202"
        schema_file.write_text("{}")
        return schema_file

    monkeypatch.setattr(cli, "fetch_crudsql_schema", fake_fetch)
    monkeypatch.setattr(cli, "require_auth_token", lambda purpose="": "token-default")
    monkeypatch.setattr(cli, "resolve_generator_jar", lambda version: tmp_path / "jar.jar")
    monkeypatch.setattr(
        cli,
        "run_openapi_generator",
        lambda jar, engine, cmd, java_opts: (0, ""),
    )

    out_dir = tmp_path / "out"
    args = SimpleNamespace(
        generator_version=None,
        engine="embedded",
        schema=None,
        crudsql_url=None,
        swain_project_id=None,
        swain_connection_id=None,
        out=str(out_dir),
        languages=["python"],
        config=None,
        templates=None,
        additional_properties=None,
        generator_arg=None,
        swain_tenant_id=None,
        property=[],
        skip_validate_spec=False,
        verbose=False,
    )

    assert cli.handle_gen(args) == 0
    assert not schema_file.exists()
    assert out_dir.is_dir()


def test_fetch_swain_projects_parses_pages(monkeypatch):
    page1 = FakeResponse(
        "https://api.example.com/api/Project",
        json_data={
            "data": [{"id": 1, "name": "Alpha"}],
            "total_pages": 2,
        },
        content=b"{}",
    )
    page2 = FakeResponse(
        "https://api.example.com/api/Project",
        json_data={
            "data": [{"id": 2, "name": "Beta"}],
            "total_pages": 2,
        },
        content=b"{}",
    )
    calls: List[Any] = []

    def fake_client(**kwargs):
        return FakeClient([page1, page2], calls)

    monkeypatch.setattr(cli.httpx, "Client", fake_client)
    projects = cli.fetch_swain_projects(
        "https://api.example.com",
        "token",
        tenant_id="999",
    )
    assert [project.id for project in projects] == [1, 2]
    assert calls[0][0] == "GET"
    assert calls[0][3]["page"] == 1
    assert calls[1][3]["page"] == 2
    assert calls[0][2]["X-Tenant-ID"] == "999"
    assert calls[1][2]["X-Tenant-ID"] == "999"


def test_fetch_swain_connections_parses_payload(monkeypatch):
    response = FakeResponse(
        "https://api.example.com/api/Connection/filter",
        json_data={
            "data": [
                {
                    "id": 55,
                    "dbname": "analytics",
                    "driver": "postgres",
                    "stage": {"name": "prod"},
                    "project": {"name": "Alpha"},
                    "current_schema": {
                        "name": "public",
                        "current_build": {
                            "id": 7,
                            "api_endpoint": "https://build.example.com",
                        },
                    },
                    "api_endpoint": "https://connection.example.com",
                }
            ]
        },
        content=b"{}",
    )
    calls: List[Any] = []

    def fake_client(**kwargs):
        return FakeClient([response], calls)

    monkeypatch.setattr(cli.httpx, "Client", fake_client)
    connections = cli.fetch_swain_connections(
        "https://api.example.com",
        "token",
        tenant_id="777",
        project_id=1,
    )
    assert len(connections) == 1
    conn = connections[0]
    assert conn.id == 55
    assert conn.driver == "postgres"
    assert conn.stage == "prod"
    assert conn.schema_name == "public"
    assert conn.build_endpoint == "https://build.example.com"
    assert calls[0][0] == "POST"
    assert calls[0][2]["X-Tenant-ID"] == "777"


def test_handle_gen_with_swain_connection(monkeypatch, tmp_path):
    connection = cli.SwainConnection(
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

    def fake_fetch_schema(conn, token, tenant_id=None):
        assert conn.id == connection.id
        assert token == "token-swain"
        assert tenant_id == "303"
        schema_file.write_text("{}")
        return schema_file

    captured: Dict[str, Any] = {}

    def fake_run(jar, engine, cmd, java_opts):
        captured["cmd"] = cmd
        captured["java_opts"] = java_opts
        return 0, ""

    monkeypatch.setenv(cli.TENANT_ID_ENV_VAR, "303")

    def fake_fetch_connection(base, token, cid, tenant_id=None):
        assert tenant_id == "303"
        return connection

    monkeypatch.setattr(
        cli,
        "fetch_swain_connection_by_id",
        fake_fetch_connection,
    )
    monkeypatch.setattr(cli, "fetch_swain_connection_schema", fake_fetch_schema)
    monkeypatch.setattr(cli, "require_auth_token", lambda purpose="": "token-swain")
    monkeypatch.setattr(cli, "resolve_generator_jar", lambda version: tmp_path / "jar.jar")
    monkeypatch.setattr(cli, "run_openapi_generator", fake_run)

    args = SimpleNamespace(
        generator_version=None,
        engine="embedded",
        schema=None,
        crudsql_url="https://api.example.com",
        swain_project_id=None,
        swain_connection_id=connection.id,
        swain_tenant_id=None,
        out=str(tmp_path / "out"),
        languages=["python"],
        config=None,
        templates=None,
        additional_properties=None,
        generator_arg=None,
        property=[],
        skip_validate_spec=False,
        verbose=False,
    )

    assert cli.handle_gen(args) == 0
    assert "cmd" in captured
    assert captured.get("java_opts") == cli.DEFAULT_JAVA_OPTS
    assert not schema_file.exists()


def test_handle_gen_retries_on_out_of_memory(monkeypatch, tmp_path):
    schema_file = tmp_path / "schema.json"
    schema_file.write_text("{}")

    monkeypatch.setenv(cli.TENANT_ID_ENV_VAR, "999")
    monkeypatch.setattr(cli, "resolve_generator_jar", lambda version: tmp_path / "jar.jar")
    monkeypatch.setattr(cli, "require_auth_token", lambda purpose="": "token" )
    monkeypatch.setattr(
        cli,
        "fetch_crudsql_schema",
        lambda base, token, tenant_id=None: schema_file,
    )

    calls: List[Tuple[List[str], int]] = []

    def fake_run(jar, engine, cmd, java_opts):
        call_index = len(calls)
        if call_index == 0:
            assert java_opts == cli.DEFAULT_JAVA_OPTS
            calls.append((java_opts, call_index))
            return 1, "java.lang.OutOfMemoryError"
        assert any(opt.startswith(cli.FALLBACK_JAVA_HEAP_OPTION) for opt in java_opts)
        calls.append((java_opts, call_index))
        return 0, ""

    monkeypatch.setattr(cli, "run_openapi_generator", fake_run)

    args = SimpleNamespace(
        generator_version=None,
        engine="embedded",
        schema=None,
        crudsql_url="https://api.example.com",
        swain_project_id=None,
        swain_connection_id=None,
        out=str(tmp_path / "out"),
        languages=["python"],
        config=None,
        templates=None,
        additional_properties=None,
        generator_arg=None,
        property=[],
        skip_validate_spec=False,
        verbose=False,
        swain_tenant_id=None,
    )

    assert cli.handle_gen(args) == 0
    assert len(calls) == 2


def test_handle_gen_disables_docs_when_out_of_memory_with_custom_java(monkeypatch, tmp_path):
    schema_file = tmp_path / "schema.json"
    schema_file.write_text("{}")

    monkeypatch.setenv(cli.TENANT_ID_ENV_VAR, "777")
    monkeypatch.setattr(cli, "resolve_generator_jar", lambda version: tmp_path / "jar.jar")
    monkeypatch.setattr(cli, "require_auth_token", lambda purpose="": "token")
    monkeypatch.setattr(
        cli,
        "fetch_crudsql_schema",
        lambda base, token, tenant_id=None: schema_file,
    )

    calls: List[List[str]] = []

    def fake_run(jar, engine, cmd, java_opts):
        calls.append(list(cmd))
        if len(calls) == 1:
            return 1, "java.lang.OutOfMemoryError"
        return 0, ""

    monkeypatch.setattr(cli, "run_openapi_generator", fake_run)

    args = SimpleNamespace(
        generator_version=None,
        engine="embedded",
        schema=None,
        crudsql_url="https://api.example.com",
        swain_project_id=None,
        swain_connection_id=None,
        out=str(tmp_path / "out"),
        languages=["go"],
        config=None,
        templates=None,
        additional_properties=None,
        generator_arg=None,
        property=[],
        skip_validate_spec=False,
        verbose=False,
        swain_tenant_id=None,
        java_opts=["-Xmx6g"],
    )

    assert cli.handle_gen(args) == 0
    assert len(calls) == 2
    first_cmd, second_cmd = calls
    assert any("apiDocs=false" in part for part in first_cmd)
    assert any("apiDocs=false" in part for part in second_cmd)

def test_handle_interactive_skip_generation(monkeypatch, capfd):
    confirm_values = iter([False, False])

    text_values = iter(
        [
            "http://example.com/openapi.yaml",
            "sdks",
            "python",
        ]
    )

    def fake_confirm(prompt, default=True):
        return next(confirm_values)

    def fake_text(prompt, default=None, validate=None, allow_empty=False):
        value = next(text_values)
        if callable(validate):
            error = validate(value)
            if error:
                pytest.fail(f"validation failed unexpectedly: {error}")
        return value

    monkeypatch.setattr(cli, "prompt_confirm", fake_confirm)
    monkeypatch.setattr(cli, "prompt_text", fake_text)
    monkeypatch.setattr(cli, "interactive_auth_setup", lambda: None)
    monkeypatch.setattr(cli, "guess_default_schema", lambda: None)
    monkeypatch.setattr(cli, "require_auth_token", lambda purpose="": "env-token")
    monkeypatch.setattr(
        cli,
        "fetch_crudsql_schema",
        lambda base, token, tenant_id=None: Path("schema.json"),
    )
    monkeypatch.setattr(cli, "handle_gen", lambda args: 0)

    result = cli.handle_interactive(SimpleNamespace(generator_version=None))
    assert result == 0
    out, err = capfd.readouterr()
    assert "interactive SDK generation wizard" in out
    assert err == ""


def test_handle_interactive_runs_generation_with_tenant(monkeypatch):
    project = cli.SwainProject(id=102, name="Project", raw={})
    connection = cli.SwainConnection(
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

    confirm_values = iter([True, True])

    text_values = iter(
        [
            "https://api.example.com",
            "sdks",
            "go",
        ]
    )

    def fake_confirm(prompt, default=True):
        return next(confirm_values)

    def fake_text(prompt, default=None, validate=None, allow_empty=False):
        value = next(text_values)
        if callable(validate):
            error = validate(value)
            if error:
                pytest.fail(f"validation failed unexpectedly: {error}")
        return value

    monkeypatch.setattr(cli, "prompt_confirm", fake_confirm)
    monkeypatch.setattr(cli, "prompt_text", fake_text)
    monkeypatch.setattr(cli, "prompt_select", lambda prompt, choices: choices[0].value)
    monkeypatch.setattr(cli, "interactive_auth_setup", lambda: None)
    monkeypatch.setattr(cli, "require_auth_token", lambda purpose="": "token-xyz")

    def fake_determine(token, provided, *, allow_prompt):
        assert token == "token-xyz"
        assert allow_prompt is True
        return "14"

    monkeypatch.setattr(cli, "determine_swain_tenant_id", fake_determine)
    monkeypatch.setattr(
        cli,
        "fetch_swain_projects",
        lambda base, token, tenant_id=None: [project],
    )
    monkeypatch.setattr(
        cli,
        "fetch_swain_connections",
        lambda base, token, tenant_id=None, project_id=None: [connection],
    )

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
        f"--global-property={cli.GLOBAL_PROPERTY_DISABLE_DOCS}",
    ]
