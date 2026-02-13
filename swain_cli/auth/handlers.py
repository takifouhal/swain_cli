"""Auth CLI handlers and interactive setup."""

from __future__ import annotations

import os
from types import SimpleNamespace

import keyring

from ..console import log, log_error
from ..constants import (
    AUTH_TOKEN_ENV_VAR,
    AUTH_TOKEN_FILE_ENV_VAR,
    DEFAULT_SWAIN_BASE_URL,
)
from ..errors import CLIError
from ..prompts import prompt_confirm, prompt_password, prompt_text
from ..utils import safe_str
from .remote import swain_login_with_credentials, swain_refresh_with_token
from .tokens import (
    clear_auth_state,
    load_auth_state,
    mask_token,
    persist_auth_token,
    resolve_auth_token,
)


def read_login_token(args: SimpleNamespace) -> str:
    username = getattr(args, "username", None)
    password = getattr(args, "password", None)
    auth_base = getattr(args, "auth_base_url", None) or DEFAULT_SWAIN_BASE_URL

    if not username:
        username = prompt_text("Username or email")
    if password is None:
        password = prompt_password("Password")

    login_payload = swain_login_with_credentials(auth_base, username, password)
    token_value = safe_str(login_payload.get("token"))
    if not token_value:
        raise CLIError("credential login did not return an access token")

    refresh_value = safe_str(
        login_payload.get("refresh_token")
        or login_payload.get("refreshToken")
        or login_payload.get("refresh-token")
    )
    args.login_response = login_payload
    args.login_refresh_token = refresh_value
    return token_value


def interactive_auth_setup(auth_base_url: str | None = None) -> None:
    existing = resolve_auth_token()
    if existing:
        log("reusing existing authentication token")
        return
    log("no authentication token configured.")
    if not prompt_confirm("Sign in before continuing?", default=True):
        raise CLIError("authentication token required; run 'swain_cli auth login'")
    args = SimpleNamespace(username=None, password=None, auth_base_url=auth_base_url)
    token = read_login_token(args)
    persist_auth_token(token, args.login_refresh_token)


def obtain_token_from_user(*, allow_reuse: bool) -> str:
    existing = resolve_auth_token()
    if existing and allow_reuse:
        log(f"authentication token detected ({mask_token(existing)})")
        if prompt_confirm("Reuse this token?", default=True):
            return existing
        log("Enter a replacement token.")
    while True:
        token = prompt_password("Access token:")
        if token:
            return token
        log_error("access token cannot be empty")


def handle_auth_login(args: SimpleNamespace) -> int:
    token = read_login_token(args)
    refresh = args.login_refresh_token
    persist_auth_token(token, refresh)
    if refresh:
        log("refresh token stored in keyring")
    return 0


def handle_auth_refresh(args: SimpleNamespace) -> int:
    if (os.environ.get(AUTH_TOKEN_ENV_VAR) or "").strip():
        raise CLIError(
            f"cannot refresh while {AUTH_TOKEN_ENV_VAR} is set; unset it or run 'swain_cli auth login'"
        )
    if (os.environ.get(AUTH_TOKEN_FILE_ENV_VAR) or "").strip():
        raise CLIError(
            f"cannot refresh while {AUTH_TOKEN_FILE_ENV_VAR} is set; unset it or run 'swain_cli auth login'"
        )

    state = load_auth_state()
    if not state.refresh_token:
        raise CLIError("no refresh token stored; run 'swain_cli auth login'")

    auth_base = getattr(args, "auth_base_url", None) or DEFAULT_SWAIN_BASE_URL
    data = swain_refresh_with_token(auth_base, state.refresh_token)
    new_access = safe_str(data.get("token") or data.get("access_token") or data.get("accessToken"))
    if not new_access:
        raise CLIError("refresh response did not include an access token")
    new_refresh = safe_str(
        data.get("refresh_token") or data.get("refreshToken") or data.get("refresh-token")
    )
    persist_auth_token(new_access, new_refresh)
    log(f"refreshed access token ({mask_token(new_access)})")
    return 0


def handle_auth_logout(_: SimpleNamespace) -> int:
    clear_auth_state()
    log("removed stored access token")
    return 0


def handle_auth_status(_: SimpleNamespace) -> int:
    env_token = os.environ.get(AUTH_TOKEN_ENV_VAR, "").strip()
    if env_token:
        log("auth token source: environment variable")
        log(f"effective token: {mask_token(env_token)}")
        return 0
    token_file = os.environ.get(AUTH_TOKEN_FILE_ENV_VAR, "").strip()
    if token_file:
        token_value = resolve_auth_token()
        if token_value:
            log("auth token source: token file")
            log(f"effective token: {mask_token(token_value)}")
            return 0
    state = load_auth_state()
    if state.access_token:
        log("auth token source: system keyring")
        log(f"effective token: {mask_token(state.access_token)}")
        if state.refresh_token:
            log("refresh token: stored")
        return 0
    log("auth token: not configured")
    backend = getattr(keyring, "get_keyring", lambda: None)()
    backend_name = backend.name if backend else "unknown"
    log(f"keyring backend: {backend_name}")
    return 0
