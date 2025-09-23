import argparse
import io
import json
import os
import subprocess
import sys
import urllib.error

import pytest

import swain_cli.cli as cli


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
    cli.get_engine_paths.cache_clear()
    cli.get_platform_info.cache_clear()
    explicit = tmp_path / "custom-cache"
    monkeypatch.setenv(cli.CACHE_ENV_VAR, str(explicit))
    try:
        result = cli.cache_root()
        assert result == explicit
        assert result.is_dir()
    finally:
        cli.get_engine_paths.cache_clear()
        cli.get_platform_info.cache_clear()


def test_get_jre_asset_unsupported(monkeypatch):
    monkeypatch.setattr(cli.platform, "system", lambda: "Plan9")
    monkeypatch.setattr(cli.platform, "machine", lambda: "mips")
    with pytest.raises(cli.CLIError):
        cli.get_jre_asset()


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX-only path expectations")
def test_cli_help_invocation(tmp_path):
    env = os.environ.copy()
    env["SWAIN_CLI_CACHE_DIR"] = str(tmp_path)
    completed = subprocess.run(
        [sys.executable, "-m", "swain_cli.cli", "--help"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    )
    assert "usage" in completed.stdout.lower()


def test_build_generate_command_alias(tmp_path):
    args = argparse.Namespace(
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


def test_fetch_crudsql_schema_success(monkeypatch):
    discovery_payload = b"{\"schema_url\": \"/openapi/custom.json\"}"
    schema_payload = b"{\"swagger\": \"2.0\"}"

    class DiscoveryResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return discovery_payload

    class SchemaResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return schema_payload

    calls = []

    def fake_urlopen(request):
        calls.append(request.full_url)
        assert request.headers["Authorization"] == "Bearer token123"
        assert "swain_cli" in request.get_header("User-agent")
        if request.full_url.endswith("/api/schema-location"):
            return DiscoveryResponse()
        assert request.full_url == "https://api.example.com/openapi/custom.json"
        return SchemaResponse()

    monkeypatch.setattr(cli.urllib.request, "urlopen", fake_urlopen)

    path = cli.fetch_crudsql_schema("https://api.example.com", "token123")
    try:
        data = json.loads(path.read_text())
        assert data["swagger"] == "2.0"
    finally:
        path.unlink(missing_ok=True)

    assert calls == [
        "https://api.example.com/api/schema-location",
        "https://api.example.com/openapi/custom.json",
    ]


def test_fetch_crudsql_schema_http_error(monkeypatch):
    def fake_urlopen(request):
        raise urllib.error.HTTPError(
            request.full_url,
            401,
            "unauthorized",
            hdrs=None,
            fp=io.BytesIO(b"denied"),
        )

    monkeypatch.setattr(cli.urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(cli.CLIError) as excinfo:
        cli.fetch_crudsql_schema("https://api.example.com", "token123")

    assert "401" in str(excinfo.value)


def test_fetch_crudsql_schema_falls_back(monkeypatch):
    schema_payload = b"{}"

    class SchemaResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return schema_payload

    responses = []

    def fake_urlopen(request):
        responses.append(request.full_url)
        if request.full_url.endswith("/api/schema-location"):
            raise urllib.error.HTTPError(
                request.full_url,
                404,
                "not found",
                hdrs=None,
                fp=io.BytesIO(b"missing"),
            )
        return SchemaResponse()

    monkeypatch.setattr(cli.urllib.request, "urlopen", fake_urlopen)

    path = cli.fetch_crudsql_schema("https://api.example.com", "token123")
    try:
        assert path.read_text() == "{}"
    finally:
        path.unlink(missing_ok=True)

    assert responses[-1] == "https://api.example.com/api/dynamic_swagger"


def test_extract_archive_unknown(tmp_path):
    archive = tmp_path / "archive.xyz"
    archive.write_text("dummy")

    with pytest.raises(cli.CLIError):
        cli.extract_archive(archive, tmp_path / "out")


def test_interactive_wizard_skip_generation(monkeypatch, capfd):
    monkeypatch.setenv(cli.AUTH_TOKEN_ENV_VAR, "env-token")

    responses = iter(
        [
            "",  # reuse existing token
            "n",  # CrudSQL prompt -> no
            "http://example.com/openapi.yaml",  # schema
            "sdks",  # output directory
            "TypeScript",  # languages (case-insensitive)
            "",  # config
            "",  # templates
            "n",  # additional properties
            "n",  # system properties
            "n",  # raw generator args
            "",  # use embedded (default yes)
            "n",  # skip validation
            "n",  # verbose
            "n",  # run now
        ]
    )

    def fake_input(prompt: str) -> str:
        try:
            return next(responses)
        except StopIteration:  # pragma: no cover - defensive guard
            pytest.fail("interactive wizard requested more input than expected")

    monkeypatch.setattr("builtins.input", fake_input)
    monkeypatch.setattr(cli, "guess_default_schema", lambda: None)

    result = cli.handle_interactive(argparse.Namespace(generator_version=None))
    assert result == 0

    captured = capfd.readouterr()
    assert "interactive SDK generation wizard" in captured.out
    assert "swain_cli gen -i http://example.com/openapi.yaml -o sdks -l typescript" in captured.out


def test_interactive_reprompts_on_missing_config(tmp_path, monkeypatch, capfd):
    schema = tmp_path / "openapi.yaml"
    schema.write_text("openapi: 3.0.0")
    config_valid = tmp_path / "config.yaml"
    config_valid.write_text("generator: python")

    monkeypatch.setenv(cli.AUTH_TOKEN_ENV_VAR, "env-token")

    responses = iter(
        [
            "",  # reuse existing token
            "n",  # CrudSQL prompt -> no
            str(schema),  # schema path
            str(tmp_path / "sdks"),  # output directory
            "python",  # languages
            str(tmp_path / "missing.yaml"),  # config (first attempt - invalid)
            str(config_valid),  # config (second attempt - valid)
            "",  # templates
            "n",  # additional properties
            "n",  # system properties
            "n",  # raw generator args
            "",  # use embedded (default yes)
            "n",  # skip validation
            "n",  # verbose
            "n",  # run now
        ]
    )

    def fake_input(prompt: str) -> str:
        try:
            return next(responses)
        except StopIteration:  # pragma: no cover
            pytest.fail("interactive wizard requested more input than expected")

    monkeypatch.setattr("builtins.input", fake_input)
    monkeypatch.setattr(cli, "guess_default_schema", lambda: None)

    result = cli.handle_interactive(argparse.Namespace(generator_version=None))
    assert result == 0

    out, err = capfd.readouterr()
    assert "config file" in err
    assert str(config_valid) in out


def test_auth_login_writes_config(tmp_path, monkeypatch):
    cli.get_config_paths.cache_clear()
    config_dir = tmp_path / "config"
    monkeypatch.setenv(cli.CONFIG_ENV_VAR, str(config_dir))

    try:
        args = argparse.Namespace(token="supersecret", stdin=False, no_prompt=False)
        assert cli.handle_auth_login(args) == 0

        auth_file = config_dir / cli.AUTH_FILE_NAME
        assert auth_file.exists()
        data = json.loads(auth_file.read_text())
        assert data["access_token"] == "supersecret"
    finally:
        cli.get_config_paths.cache_clear()


def test_auth_logout_removes_file(tmp_path, monkeypatch):
    cli.get_config_paths.cache_clear()
    config_dir = tmp_path / "config"
    monkeypatch.setenv(cli.CONFIG_ENV_VAR, str(config_dir))

    try:
        cli.save_auth_state(cli.AuthState("stored-token"))
        auth_file = config_dir / cli.AUTH_FILE_NAME
        assert auth_file.exists()

        assert cli.handle_auth_logout(argparse.Namespace()) == 0
        assert not auth_file.exists()
    finally:
        cli.get_config_paths.cache_clear()


def test_auth_status_prefers_env(tmp_path, monkeypatch, capfd):
    cli.get_config_paths.cache_clear()
    monkeypatch.setenv(cli.CONFIG_ENV_VAR, str(tmp_path / "config"))
    monkeypatch.setenv(cli.AUTH_TOKEN_ENV_VAR, "env-token-value")

    try:
        assert cli.handle_auth_status(argparse.Namespace()) == 0
    finally:
        cli.get_config_paths.cache_clear()

    out, err = capfd.readouterr()
    assert "environment variable" in out
    assert "env-token-value" not in out  # token should be masked
    assert "effective token" in out
    assert err == ""


def test_read_login_token_stdin(monkeypatch):
    stream = io.StringIO("stdin-token\n")
    monkeypatch.setattr(sys, "stdin", stream)
    args = argparse.Namespace(token=None, stdin=True, no_prompt=False)
    assert cli.read_login_token(args) == "stdin-token"


def test_read_login_token_no_prompt(monkeypatch):
    monkeypatch.delenv(cli.AUTH_TOKEN_ENV_VAR, raising=False)
    args = argparse.Namespace(token=None, stdin=False, no_prompt=True)
    with pytest.raises(cli.CLIError):
        cli.read_login_token(args)


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

    args = argparse.Namespace(
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
    args = argparse.Namespace(
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
