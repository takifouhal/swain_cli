import io
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

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

    def get(self, url, headers=None):
        if not self._responses:
            raise AssertionError("unexpected request")
        response = self._responses.pop(0)
        assert response.url == str(url)
        self.calls.append(str(url))
        return response


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
    temp_path = cli.fetch_crudsql_schema("https://api.example.com", "token123")
    try:
        data = json.loads(temp_path.read_text())
        assert data["swagger"] == "2.0"
    finally:
        temp_path.unlink(missing_ok=True)
    assert calls == [
        "https://api.example.com/api/schema-location",
        "https://api.example.com/openapi/custom.json",
    ]


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
        cli.fetch_crudsql_schema("https://api.example.com", "token123")
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
    temp_path = cli.fetch_crudsql_schema("https://api.example.com", "token123")
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


def test_auth_login_uses_keyring():
    args = SimpleNamespace(token="supersecret", stdin=False, no_prompt=False)
    assert cli.handle_auth_login(args) == 0
    assert cli.load_auth_state().access_token == "supersecret"


def test_auth_logout_removes_token():
    args = SimpleNamespace(token="supersecret", stdin=False, no_prompt=False)
    cli.handle_auth_login(args)
    assert cli.handle_auth_logout(SimpleNamespace()) == 0
    assert cli.load_auth_state().access_token is None


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

    def fake_fetch(url, token):
        assert url == "https://api.example.com"
        assert token == "token-abc"
        schema_file.write_text("{}")
        return schema_file

    captured = {}

    def fake_run(jar, engine, cmd):
        captured["cmd"] = cmd
        return 0

    monkeypatch.setattr(cli, "fetch_crudsql_schema", fake_fetch)
    monkeypatch.setattr(cli, "require_auth_token", lambda purpose="": "token-abc")
    monkeypatch.setattr(cli, "resolve_generator_jar", lambda version: tmp_path / "jar.jar")
    monkeypatch.setattr(cli, "run_openapi_generator", fake_run)

    args = SimpleNamespace(
        generator_version=None,
        engine="embedded",
        schema=None,
        crudsql_url="https://api.example.com",
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
    assert not schema_file.exists()
    assert os.path.isdir(args.out)


def test_handle_gen_defaults_to_swain(monkeypatch, tmp_path):
    schema_file = tmp_path / "schema.json"

    def fake_fetch(url, token):
        assert url == cli.DEFAULT_CRUDSQL_BASE_URL
        assert token == "token-default"
        schema_file.write_text("{}")
        return schema_file

    monkeypatch.setattr(cli, "fetch_crudsql_schema", fake_fetch)
    monkeypatch.setattr(cli, "require_auth_token", lambda purpose="": "token-default")
    monkeypatch.setattr(cli, "resolve_generator_jar", lambda version: tmp_path / "jar.jar")
    monkeypatch.setattr(cli, "run_openapi_generator", lambda jar, engine, cmd: 0)

    out_dir = tmp_path / "out"
    args = SimpleNamespace(
        generator_version=None,
        engine="embedded",
        schema=None,
        crudsql_url=None,
        out=str(out_dir),
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
    assert not schema_file.exists()
    assert out_dir.is_dir()


def test_handle_interactive_skip_generation(monkeypatch, capfd):
    confirm_values = iter(
        [
            False,  # fetch from CrudSQL? no
            False,  # additional properties
            False,  # system properties
            False,  # raw generator args
            True,  # use embedded runtime
            False,  # skip validation
            False,  # verbose
            False,  # run now
        ]
    )

    text_values = iter(
        [
            "http://example.com/openapi.yaml",
            "sdks",
            "python",
            "",
            "",
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
    monkeypatch.setattr(cli, "fetch_crudsql_schema", lambda base, token: Path("schema.json"))
    monkeypatch.setattr(cli, "handle_gen", lambda args: 0)

    result = cli.handle_interactive(SimpleNamespace(generator_version=None))
    assert result == 0
    out, err = capfd.readouterr()
    assert "interactive SDK generation wizard" in out
    assert err == ""
