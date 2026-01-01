"""Authentication helpers for swain_cli."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Union

import httpx
import keyring
import questionary
from keyring.errors import NoKeyringError, PasswordDeleteError

from .console import log, log_error
from .constants import (
    AUTH_TOKEN_ENV_VAR,
    DEFAULT_SWAIN_BASE_URL,
    KEYRING_REFRESH_USERNAME,
    KEYRING_SERVICE,
    KEYRING_USERNAME,
    TENANT_ID_ENV_VAR,
)
from .errors import CLIError
from .http import (
    describe_http_error,
    http_timeout,
    normalize_tenant_id,
    request_headers,
)
from .prompts import prompt_confirm, prompt_password, prompt_select, prompt_text
from .urls import swain_url
from .utils import pick, safe_str


@dataclass
class AuthState:
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None


def load_auth_state() -> AuthState:
    env_token = os.environ.get(AUTH_TOKEN_ENV_VAR, "").strip()
    if env_token:
        return AuthState(env_token, None)

    try:
        token = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
        refresh = keyring.get_password(KEYRING_SERVICE, KEYRING_REFRESH_USERNAME)
    except NoKeyringError:
        token = None
        refresh = None
    access_value = token.strip() if token else None
    refresh_value = refresh.strip() if refresh else None
    return AuthState(access_value, refresh_value)


def persist_auth_token(token: str, refresh_token: Optional[str] = None) -> None:
    normalized = token.strip()
    if not normalized:
        raise CLIError("attempted to persist empty auth token")
    try:
        keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, normalized)
        if refresh_token is not None:
            refresh_normalized = refresh_token.strip()
            if refresh_normalized:
                keyring.set_password(
                    KEYRING_SERVICE, KEYRING_REFRESH_USERNAME, refresh_normalized
                )
            else:
                keyring.delete_password(KEYRING_SERVICE, KEYRING_REFRESH_USERNAME)
    except NoKeyringError as exc:
        raise CLIError(
            "no keyring backend available; set SWAIN_CLI_AUTH_TOKEN for this session"
        ) from exc
    log(f"stored access token ({mask_token(normalized)}) in system keyring")


def clear_auth_state() -> None:
    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_USERNAME)
        keyring.delete_password(KEYRING_SERVICE, KEYRING_REFRESH_USERNAME)
    except (NoKeyringError, PasswordDeleteError):
        return


def mask_token(token: str) -> str:
    if len(token) <= 8:
        return "*" * len(token)
    return f"{token[:4]}...{token[-4:]}"


def resolve_auth_token() -> Optional[str]:
    state = load_auth_state()
    return state.access_token


def require_auth_token(purpose: str = "perform this action") -> str:
    token = resolve_auth_token()
    if not token:
        raise CLIError(
            f"authentication token required to {purpose}; run 'swain_cli auth login'"
        )
    return token


def _decode_jwt_payload(token: str) -> Dict[str, Any]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload_segment = parts[1]
        padding = (-len(payload_segment)) % 4
        padded = payload_segment + ("=" * padding)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        data = json.loads(decoded.decode("utf-8"))
        return data if isinstance(data, dict) else {}
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return {}


def _extract_tenant_ids_from_token(token: str) -> List[str]:
    payload = _decode_jwt_payload(token)
    if not payload:
        return []

    candidates: List[str] = []
    seen: set[str] = set()

    def add(value: Any) -> None:
        normalized = normalize_tenant_id(value)
        if normalized and normalized not in seen:
            seen.add(normalized)
            candidates.append(normalized)

    for key in ("tenant_ids", "tenantIds"):
        value = payload.get(key)
        if isinstance(value, list):
            for entry in value:
                add(entry)

    for key in (
        "tenant_id",
        "tenantId",
        "accounts_id",
        "accountsId",
        "account_id",
        "accountId",
    ):
        add(payload.get(key))

    additional_data = payload.get("additional_data") or payload.get("additionalData")
    if isinstance(additional_data, dict):
        for key in ("tenant_id", "tenantId", "accounts_id", "accountsId"):
            add(additional_data.get(key))

    return candidates


def swain_request_headers(
    token: str, *, tenant_id: Optional[Union[str, int]] = None
) -> Dict[str, str]:
    return request_headers(token, tenant_id=tenant_id)


def _fetch_account_name_for_tenant(
    base_url: str, token: str, tenant_id: Union[str, int]
) -> Optional[str]:
    normalized = normalize_tenant_id(tenant_id)
    if not normalized:
        return None

    url = swain_url(base_url, f"Account/{normalized}")
    headers = request_headers(token, tenant_id=normalized)
    timeout = http_timeout()
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        try:
            response = client.get(url, headers=headers)
            if response.status_code == 404:
                return None
            response.raise_for_status()
        except httpx.HTTPStatusError:
            return None
        except httpx.HTTPError:
            return None

    try:
        payload = response.json()
    except json.JSONDecodeError:
        return None

    if isinstance(payload, dict):
        name = safe_str(pick(payload, "name"))
        if name:
            return name
        data_section = payload.get("data")
        if isinstance(data_section, dict):
            name = safe_str(pick(data_section, "name"))
            if name:
                return name
    return None


def determine_swain_tenant_id(
    base_url: str,
    token: str,
    provided: Optional[Union[str, int]],
    *,
    allow_prompt: bool,
) -> str:
    explicit = normalize_tenant_id(provided)
    if explicit:
        return explicit

    env_value = normalize_tenant_id(os.environ.get(TENANT_ID_ENV_VAR))
    if env_value:
        log(f"using tenant id {env_value} from {TENANT_ID_ENV_VAR}")
        return env_value

    candidates = _extract_tenant_ids_from_token(token)
    if candidates:
        if len(candidates) == 1:
            tenant_id = candidates[0]
            account_name = _fetch_account_name_for_tenant(base_url, token, tenant_id)
            if account_name:
                log(
                    "using tenant"
                    f" {account_name} (#{tenant_id}) derived from access token claims"
                )
            else:
                log(f"using tenant id {tenant_id} derived from access token claims")
            return tenant_id
        if allow_prompt:
            ordered_choices = []
            for candidate in candidates:
                name = _fetch_account_name_for_tenant(base_url, token, candidate)
                title = f"{name} (#{candidate})" if name else str(candidate)
                ordered_choices.append(
                    questionary.Choice(title=title, value=str(candidate))
                )
            selection = prompt_select(
                "Select Swain tenant ID",
                choices=ordered_choices,
            )
            return str(selection)
        raise CLIError(
            "multiple tenant IDs available; specify --swain-tenant-id or set SWAIN_CLI_TENANT_ID"
        )

    if allow_prompt:
        return prompt_text("Swain tenant ID")

    raise CLIError(
        "Swain tenant ID required; provide --swain-tenant-id or set SWAIN_CLI_TENANT_ID"
    )


def swain_login_with_credentials(base_url: str, username: str, password: str) -> Dict[str, Any]:
    if not username.strip():
        raise CLIError("username is required for credential login")
    if not password:
        raise CLIError("password is required for credential login")
    login_url = swain_url(base_url, "auth/login", enforce_api_prefix=False)
    headers = request_headers(content_type="application/json")
    payload = {"username": username, "password": password}
    timeout = http_timeout()
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        try:
            response = client.post(login_url, headers=headers, json=payload)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            detail = describe_http_error(exc)
            raise CLIError(f"credential login failed: {detail}") from exc
    try:
        data = response.json()
    except json.JSONDecodeError as exc:
        raise CLIError("login response was not valid JSON") from exc
    token = safe_str(data.get("token"))
    if not token:
        raise CLIError("login response did not include an access token")
    return data


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


_normalize_tenant_id = normalize_tenant_id
_swain_request_headers = swain_request_headers


def interactive_auth_setup(auth_base_url: Optional[str] = None) -> None:
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
