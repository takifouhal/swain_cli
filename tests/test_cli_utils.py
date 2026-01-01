import base64
import json
import os
import platform
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

import httpx
import keyring
import pytest
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError
from typer.testing import CliRunner

import swain_cli.auth as auth
import swain_cli.cli as cli
import swain_cli.constants as constants
import swain_cli.crudsql as crudsql
import swain_cli.engine as engine
import swain_cli.generator as generator
import swain_cli.swain_api as swain_api
import swain_cli.urls as urls
from swain_cli.errors import CLIError


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
    assert constants.LANGUAGE_ALIASES["typescript"] == "typescript-axios"


def test_normalize_os_variants():
    assert engine.normalize_os("Darwin") == "macos"
    assert engine.normalize_os("WINDOWS") == "windows"
    assert engine.normalize_os("linux") == "linux"
    assert engine.normalize_os("FreeBSD") == "freebsd"


def test_normalize_arch_variants():
    assert engine.normalize_arch("x86_64") == "x86_64"
    assert engine.normalize_arch("AMD64") == "x86_64"
    assert engine.normalize_arch("arm64") == "arm64"
    assert engine.normalize_arch("aarch64") == "arm64"
    assert engine.normalize_arch("riscv64") == "riscv64"


def test_cache_root_honors_env(tmp_path, monkeypatch):
    custom = tmp_path / "custom-cache"
    monkeypatch.setenv(constants.CACHE_ENV_VAR, str(custom))
    result = engine.cache_root()
    assert result == custom
    assert result.is_dir()


def test_get_jre_asset_unsupported(monkeypatch):
    engine.get_platform_info.cache_clear()
    monkeypatch.setattr(platform, "system", lambda: "Plan9")
    monkeypatch.setattr(platform, "machine", lambda: "mips")
    with pytest.raises(CLIError):
        engine.get_jre_asset()
    engine.get_platform_info.cache_clear()


def test_ensure_embedded_jre_reuses_cached_install(tmp_path, monkeypatch):
    runtime_dir = tmp_path / "jre"
    (runtime_dir / "bin").mkdir(parents=True)
    (runtime_dir / "bin" / "java").write_text("", encoding="utf-8")
    expected_sha = "cached-sha"
    (runtime_dir / constants.JRE_MARKER_FILENAME).write_text(expected_sha, encoding="utf-8")

    monkeypatch.setattr(engine, "java_binary_name", lambda: "java")
    monkeypatch.setattr(engine, "jre_install_dir", lambda *args, **kwargs: runtime_dir)
    monkeypatch.setattr(engine, "get_jre_asset", lambda: engine.JREAsset("dummy.tar.gz", None))
    monkeypatch.setattr(engine, "resolve_asset_sha256", lambda asset: expected_sha)

    def fail_fetch(*args, **kwargs):
        raise AssertionError("unexpected download while cached JRE is valid")

    monkeypatch.setattr(engine, "fetch_asset_file", fail_fetch)

    assert engine.ensure_embedded_jre(force=False) == runtime_dir
    assert (runtime_dir / "bin" / "java").exists()


def test_ensure_embedded_jre_reinstalls_on_marker_mismatch(tmp_path, monkeypatch):
    runtime_dir = tmp_path / "jre"
    (runtime_dir / "bin").mkdir(parents=True)
    (runtime_dir / "bin" / "java").write_text("old", encoding="utf-8")
    (runtime_dir / constants.JRE_MARKER_FILENAME).write_text("old-sha", encoding="utf-8")
    expected_sha = "new-sha"

    monkeypatch.setattr(engine, "java_binary_name", lambda: "java")
    monkeypatch.setattr(engine, "jre_install_dir", lambda *args, **kwargs: runtime_dir)
    monkeypatch.setattr(engine, "get_jre_asset", lambda: engine.JREAsset("dummy.tar.gz", None))
    monkeypatch.setattr(engine, "resolve_asset_sha256", lambda asset: expected_sha)

    calls = {"fetches": 0}

    def fake_fetch(asset_name, sha256, *, force=False):
        calls["fetches"] += 1
        assert asset_name == "dummy.tar.gz"
        assert sha256 == expected_sha
        assert force is False
        return tmp_path / "archive.tar.gz"

    def fake_extract(archive, dest):
        (dest / "bin").mkdir(parents=True, exist_ok=True)
        (dest / "bin" / "java").write_text("new", encoding="utf-8")

    monkeypatch.setattr(engine, "fetch_asset_file", fake_fetch)
    monkeypatch.setattr(engine, "extract_archive", fake_extract)
    monkeypatch.setattr(engine, "normalize_runtime_dir", lambda *_: None)

    assert engine.ensure_embedded_jre(force=False) == runtime_dir
    assert calls["fetches"] == 1
    assert (runtime_dir / constants.JRE_MARKER_FILENAME).read_text(encoding="utf-8").strip() == expected_sha
    assert (runtime_dir / "bin" / "java").read_text(encoding="utf-8") == "new"


def test_ensure_embedded_jre_force_reinstalls(tmp_path, monkeypatch):
    runtime_dir = tmp_path / "jre"
    (runtime_dir / "bin").mkdir(parents=True)
    (runtime_dir / "bin" / "java").write_text("old", encoding="utf-8")
    expected_sha = "force-sha"
    (runtime_dir / constants.JRE_MARKER_FILENAME).write_text(expected_sha, encoding="utf-8")

    monkeypatch.setattr(engine, "java_binary_name", lambda: "java")
    monkeypatch.setattr(engine, "jre_install_dir", lambda *args, **kwargs: runtime_dir)
    monkeypatch.setattr(engine, "get_jre_asset", lambda: engine.JREAsset("dummy.tar.gz", None))
    monkeypatch.setattr(engine, "resolve_asset_sha256", lambda asset: expected_sha)

    observed = {"force": None}

    def fake_fetch(asset_name, sha256, *, force=False):
        observed["force"] = force
        return tmp_path / "archive.tar.gz"

    def fake_extract(archive, dest):
        (dest / "bin").mkdir(parents=True, exist_ok=True)
        (dest / "bin" / "java").write_text("new", encoding="utf-8")

    monkeypatch.setattr(engine, "fetch_asset_file", fake_fetch)
    monkeypatch.setattr(engine, "extract_archive", fake_extract)
    monkeypatch.setattr(engine, "normalize_runtime_dir", lambda *_: None)

    assert engine.ensure_embedded_jre(force=True) == runtime_dir
    assert observed["force"] is True
    assert (runtime_dir / constants.JRE_MARKER_FILENAME).read_text(encoding="utf-8").strip() == expected_sha
    assert (runtime_dir / "bin" / "java").read_text(encoding="utf-8") == "new"


def test_cli_help_invocation():
    result = runner.invoke(cli.app, ["--help"])
    assert result.exit_code == 0
    assert "Usage:" in result.stdout


def test_cli_without_command_shows_help():
    result = runner.invoke(cli.app, [])
    assert result.exit_code == constants.EXIT_CODE_USAGE
    assert "Commands" in result.stdout


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


def test_crudsql_dynamic_swagger_url_variants():
    assert (
        urls.crudsql_dynamic_swagger_url("https://api.example.com")
        == "https://api.example.com/api/dynamic_swagger"
    )
    assert (
        urls.crudsql_dynamic_swagger_url("https://api.example.com/base")
        == "https://api.example.com/base/api/dynamic_swagger"
    )
    with pytest.raises(CLIError):
        urls.crudsql_dynamic_swagger_url("api.example.com")


def test_swain_url_enforces_api_prefix_by_default():
    url = urls._swain_url("https://api.example.com", "Project")
    assert str(url) == "https://api.example.com/api/Project"


def test_swain_url_can_skip_api_prefix():
    url = urls._swain_url(
        "https://api.example.com",
        "auth/login",
        enforce_api_prefix=False,
    )
    assert str(url) == "https://api.example.com/auth/login"


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
    monkeypatch.setenv(constants.TENANT_ID_ENV_VAR, "600")
    result = cli.determine_swain_tenant_id(
        constants.DEFAULT_SWAIN_BASE_URL, token, None, allow_prompt=False
    )
    assert result == "600"


def test_determine_swain_tenant_id_single_claim(monkeypatch):
    token = make_jwt({"tenant_ids": [987]})
    monkeypatch.delenv(constants.TENANT_ID_ENV_VAR, raising=False)
    result = cli.determine_swain_tenant_id(
        constants.DEFAULT_SWAIN_BASE_URL, token, None, allow_prompt=False
    )
    assert result == "987"


def test_determine_swain_tenant_id_multiple_claims_requires_choice(monkeypatch):
    token = make_jwt({"tenant_ids": [10, 20]})
    monkeypatch.delenv(constants.TENANT_ID_ENV_VAR, raising=False)
    with pytest.raises(CLIError):
        cli.determine_swain_tenant_id(
            constants.DEFAULT_SWAIN_BASE_URL, token, None, allow_prompt=False
        )


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

    monkeypatch.setattr(crudsql.httpx, "Client", fake_client)
    temp_path = crudsql.fetch_crudsql_schema(
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

    monkeypatch.setattr(crudsql.httpx, "Client", fake_client)
    with pytest.raises(CLIError) as excinfo:
        crudsql.fetch_crudsql_schema(
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

    monkeypatch.setattr(crudsql.httpx, "Client", fake_client)
    temp_path = crudsql.fetch_crudsql_schema(
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
    with pytest.raises(CLIError):
        engine.extract_archive(archive, tmp_path / "out")


def test_swain_login_with_credentials_success(monkeypatch):
    response = FakeResponse(
        "https://api.example.com/auth/login",
        json_data={"token": "abc", "refresh_token": "refresh"},
        content=b"{}",
    )

    def fake_client(**kwargs):
        return FakeClient([response])

    monkeypatch.setattr(auth.httpx, "Client", fake_client)
    data = auth.swain_login_with_credentials(
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

    monkeypatch.setattr(auth, "swain_login_with_credentials", fake_login)
    args = SimpleNamespace(
        username="alice",
        password="wonderland",
        auth_base_url="https://api.example.com",
    )
    token = auth.read_login_token(args)
    assert token == "abc"
    assert getattr(args, "login_refresh_token") == "refresh"


def test_read_login_token_prompts_for_missing_credentials(monkeypatch):
    monkeypatch.setattr(auth, "prompt_text", lambda *a, **k: "bob")
    monkeypatch.setattr(auth, "prompt_password", lambda *a, **k: "builder")
    monkeypatch.setattr(
        auth,
        "swain_login_with_credentials",
        lambda base, user, pwd: {"token": "xyz", "refresh_token": None},
    )
    args = SimpleNamespace(
        username=None,
        password=None,
        auth_base_url=None,
    )
    token = auth.read_login_token(args)
    assert token == "xyz"
    assert getattr(args, "login_refresh_token") is None


def test_handle_auth_login_with_credentials(monkeypatch):
    def fake_login(base, username, password):
        assert username == "carol"
        assert password == "password123"
        return {"token": "new-token", "refresh_token": "new-refresh"}

    monkeypatch.setattr(auth, "swain_login_with_credentials", fake_login)
    args = SimpleNamespace(
        username="carol",
        password="password123",
        auth_base_url="https://api.swain.technology",
    )
    assert auth.handle_auth_login(args) == 0
    state = auth.load_auth_state()
    assert state.access_token == "new-token"
    assert state.refresh_token == "new-refresh"


def test_interactive_auth_setup_prompts_credentials(monkeypatch):
    monkeypatch.setattr(auth, "resolve_auth_token", lambda: None)
    monkeypatch.setattr(auth, "prompt_confirm", lambda prompt, default=True: True)

    captured_args: Dict[str, Any] = {}

    def fake_read_login_token(ns):
        captured_args["auth_base_url"] = ns.auth_base_url
        setattr(ns, "login_refresh_token", "refresh-token")
        return "credential-token"

    monkeypatch.setattr(auth, "read_login_token", fake_read_login_token)

    captured_persist: Dict[str, Optional[str]] = {}

    def fake_persist(token, refresh=None):
        captured_persist["token"] = token
        captured_persist["refresh"] = refresh

    monkeypatch.setattr(auth, "persist_auth_token", fake_persist)

    auth.interactive_auth_setup(auth_base_url="https://auth.example.com")

    assert captured_args["auth_base_url"] == "https://auth.example.com"
    assert captured_persist["token"] == "credential-token"
    assert captured_persist["refresh"] == "refresh-token"


def test_auth_logout_removes_token():
    auth.persist_auth_token("supersecret", None)
    assert auth.handle_auth_logout(SimpleNamespace()) == 0
    state = auth.load_auth_state()
    assert state.access_token is None
    assert state.refresh_token is None


def test_parse_checksum_file_variants(tmp_path):
    # Common digest used across variants
    digest = "a" * 64

    # Bare digest
    p1 = tmp_path / "bare.sha256"
    p1.write_text(f"{digest}\n")
    assert engine.parse_checksum_file(p1) == digest

    # GNU coreutils format: "<hex>  filename"
    p2 = tmp_path / "gnu.sha256"
    p2.write_text(f"{digest}  swain_cli-jre-windows-x86_64.zip\n")
    assert engine.parse_checksum_file(p2) == digest

    # BSD format: "SHA256 (file) = <hex>"
    p3 = tmp_path / "bsd.sha256"
    p3.write_text(f"SHA256 (swain_cli-jre-windows-x86_64.zip) = {digest}\n")
    assert engine.parse_checksum_file(p3) == digest

    # PowerShell Get-FileHash style (header + values)
    p4 = tmp_path / "ps.sha256"
    p4.write_text(
        "Algorithm       Hash                                                       Path\n"
        f"SHA256          {digest.upper()}   C:\\tmp\\swain_cli-jre-windows-x86_64.zip\n"
    )
    assert engine.parse_checksum_file(p4) == digest


def test_auth_status_prefers_env(monkeypatch, capfd):
    monkeypatch.setenv(constants.AUTH_TOKEN_ENV_VAR, "env-token-value")
    assert auth.handle_auth_status(SimpleNamespace()) == 0
    out, err = capfd.readouterr()
    assert "environment variable" in out
    assert "env-token-value" not in out
    assert "effective token" in out
    assert err == ""


def test_handle_gen_with_crudsql(monkeypatch, tmp_path):
    schema_file = tmp_path / "schema.json"

    monkeypatch.setenv(constants.TENANT_ID_ENV_VAR, "101")

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

    monkeypatch.setattr(generator, "fetch_crudsql_schema", fake_fetch)
    monkeypatch.setattr(generator, "require_auth_token", lambda purpose="": "token-abc")
    monkeypatch.setattr(generator, "resolve_generator_jar", lambda version: tmp_path / "jar.jar")
    monkeypatch.setattr(generator, "run_openapi_generator", fake_run)

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
        schema_file.write_text("{}")
        return schema_file

    def fake_determine(base, token, provided, *, allow_prompt):
        captured["swain_base"] = base
        return "11"

    monkeypatch.setattr(generator, "fetch_crudsql_schema", fake_fetch)
    monkeypatch.setattr(generator, "determine_swain_tenant_id", fake_determine)
    monkeypatch.setattr(generator, "require_auth_token", lambda purpose="": "token-abc")
    monkeypatch.setattr(generator, "resolve_generator_jar", lambda version: tmp_path / "jar.jar")
    monkeypatch.setattr(
        generator,
        "run_openapi_generator",
        lambda jar, engine, cmd, java_opts: (0, ""),
    )

    args = SimpleNamespace(
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
        additional_properties=None,
        generator_arg=None,
        swain_tenant_id=None,
        property=[],
        skip_validate_spec=False,
        verbose=False,
    )

    assert generator.handle_gen(args) == 0
    assert captured["swain_base"] == "https://api.example.com"
    assert captured["crud_base"] == "https://api.example.com/crud"
    assert not schema_file.exists()


def test_resolve_base_urls_strips_trailing_crud():
    swain_base, crud_base = urls.resolve_base_urls(
        "https://dev-api.swain.technology/crud", None
    )
    assert swain_base == "https://dev-api.swain.technology"
    assert crud_base == "https://dev-api.swain.technology/crud"


def test_handle_gen_defaults_to_swain(monkeypatch, tmp_path):
    schema_file = tmp_path / "schema.json"

    monkeypatch.setenv(constants.TENANT_ID_ENV_VAR, "202")

    def fake_fetch(url, token, tenant_id=None):
        assert url == constants.DEFAULT_CRUDSQL_API_BASE_URL
        assert token == "token-default"
        assert tenant_id == "202"
        schema_file.write_text("{}")
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

    assert generator.handle_gen(args) == 0
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

    monkeypatch.setattr(swain_api.httpx, "Client", fake_client)
    projects = swain_api.fetch_swain_projects(
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

    monkeypatch.setattr(swain_api.httpx, "Client", fake_client)
    connections = swain_api.fetch_swain_connections(
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
        schema_file.write_text("{}")
        return schema_file

    captured: Dict[str, Any] = {}

    def fake_run(jar, engine, cmd, java_opts):
        captured["cmd"] = cmd
        captured["java_opts"] = java_opts
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

    assert generator.handle_gen(args) == 0
    assert len(calls) == 2
    first_cmd, second_cmd = calls
    assert any("apiDocs=false" in part for part in first_cmd)
    assert any("apiDocs=false" in part for part in second_cmd)

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

    text_values = iter([
        "sdks",
        "python",
    ])

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

    text_values = iter([
        "sdks",
        "go",
    ])

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
