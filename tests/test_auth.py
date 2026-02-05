from types import SimpleNamespace
from typing import Any, Dict, Optional

import pytest

import swain_cli.auth as auth
import swain_cli.constants as constants
from swain_cli.errors import CLIError


def test_determine_swain_tenant_id_env(monkeypatch, make_jwt):
    token = make_jwt({"tenant_ids": [1, 2, 3]})
    monkeypatch.setenv(constants.TENANT_ID_ENV_VAR, "600")
    result = auth.determine_swain_tenant_id(
        constants.DEFAULT_SWAIN_BASE_URL, token, None, allow_prompt=False
    )
    assert result == "600"


def test_determine_swain_tenant_id_single_claim(monkeypatch, make_jwt):
    token = make_jwt({"tenant_ids": [987]})
    monkeypatch.delenv(constants.TENANT_ID_ENV_VAR, raising=False)
    monkeypatch.setattr(auth, "_fetch_account_name_for_tenant", lambda *a, **k: None)
    result = auth.determine_swain_tenant_id(
        constants.DEFAULT_SWAIN_BASE_URL, token, None, allow_prompt=False
    )
    assert result == "987"


def test_determine_swain_tenant_id_multiple_claims_requires_choice(monkeypatch, make_jwt):
    token = make_jwt({"tenant_ids": [10, 20]})
    monkeypatch.delenv(constants.TENANT_ID_ENV_VAR, raising=False)
    with pytest.raises(CLIError):
        auth.determine_swain_tenant_id(
            constants.DEFAULT_SWAIN_BASE_URL, token, None, allow_prompt=False
        )


def test_swain_login_with_credentials_success(monkeypatch, fake_client, fake_response):
    response = fake_response(
        "https://api.example.com/auth/login",
        json_data={"token": "abc", "refresh_token": "refresh"},
        content=b"{}",
    )

    def fake_http_client(**kwargs):
        return fake_client([response])

    monkeypatch.setattr(auth.httpx, "Client", fake_http_client)
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
    assert args.login_refresh_token == "refresh"


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
    assert args.login_refresh_token is None


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
        ns.login_refresh_token = "refresh-token"
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


def test_auth_status_prefers_env(monkeypatch, capfd):
    monkeypatch.setenv(constants.AUTH_TOKEN_ENV_VAR, "env-token-value")
    monkeypatch.delenv(constants.AUTH_TOKEN_FILE_ENV_VAR, raising=False)
    assert auth.handle_auth_status(SimpleNamespace()) == 0
    out, err = capfd.readouterr()
    assert "environment variable" in out
    assert "env-token-value" not in out
    assert "effective token" in out
    assert err == ""


def test_resolve_auth_token_reads_token_file(monkeypatch, tmp_path):
    token_file = tmp_path / "token.txt"
    token_file.write_text("file-token\n", encoding="utf-8")
    monkeypatch.delenv(constants.AUTH_TOKEN_ENV_VAR, raising=False)
    monkeypatch.setenv(constants.AUTH_TOKEN_FILE_ENV_VAR, str(token_file))
    assert auth.resolve_auth_token() == "file-token"


def test_auth_status_reports_token_file(monkeypatch, tmp_path, capfd):
    token_file = tmp_path / "token.txt"
    token_file.write_text("file-token\n", encoding="utf-8")
    monkeypatch.delenv(constants.AUTH_TOKEN_ENV_VAR, raising=False)
    monkeypatch.setenv(constants.AUTH_TOKEN_FILE_ENV_VAR, str(token_file))
    assert auth.handle_auth_status(SimpleNamespace()) == 0
    out, err = capfd.readouterr()
    assert "token file" in out
    assert "file-token" not in out
    assert err == ""


def test_handle_auth_refresh_updates_token(monkeypatch, fake_client, fake_response):
    auth.persist_auth_token("old-access", "old-refresh")

    response = fake_response(
        "https://api.example.com/auth/refresh",
        json_data={"token": "new-access", "refresh_token": "new-refresh"},
        content=b"{}",
    )

    def fake_http_client(**kwargs):
        return fake_client([response])

    monkeypatch.delenv(constants.AUTH_TOKEN_ENV_VAR, raising=False)
    monkeypatch.delenv(constants.AUTH_TOKEN_FILE_ENV_VAR, raising=False)
    monkeypatch.setattr(auth.httpx, "Client", fake_http_client)

    args = SimpleNamespace(auth_base_url="https://api.example.com")
    assert auth.handle_auth_refresh(args) == 0

    state = auth.load_auth_state()
    assert state.access_token == "new-access"
    assert state.refresh_token == "new-refresh"


def test_persist_auth_token_falls_back_to_chunked_storage(monkeypatch):
    original_set_password = auth.keyring.set_password

    def flaky_set_password(service: str, username: str, password: str) -> None:
        # Simulate the Windows Credential Manager blob limit by rejecting large secrets.
        if username in {constants.KEYRING_USERNAME, constants.KEYRING_REFRESH_USERNAME}:
            if len(password) > 300:
                raise OSError("credential blob too large")
        original_set_password(service, username, password)

    monkeypatch.setattr(auth.keyring, "set_password", flaky_set_password)

    token = "x" * 1200
    refresh = "r" * 1200
    auth.persist_auth_token(token, refresh)

    state = auth.load_auth_state()
    assert state.access_token == token
    assert state.refresh_token == refresh

    # Ensure chunk entries are removed on logout.
    auth.clear_auth_state()
    chunk0 = auth.keyring.get_password(
        constants.KEYRING_SERVICE, f"{constants.KEYRING_USERNAME}__chunk_0"
    )
    assert chunk0 is None
