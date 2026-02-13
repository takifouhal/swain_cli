"""HTTP calls for Swain auth endpoints (login/refresh)."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

import httpx

from ..context import AppContext, default_http_client_factory
from ..errors import CLIError
from ..http import describe_http_error, http_timeout, request_headers
from ..urls import swain_url
from ..utils import safe_str


def swain_login_with_credentials(
    base_url: str,
    username: str,
    password: str,
    *,
    ctx: Optional[AppContext] = None,
) -> Dict[str, Any]:
    if not username.strip():
        raise CLIError("username is required for credential login")
    if not password:
        raise CLIError("password is required for credential login")
    login_url = swain_url(base_url, "auth/login", enforce_api_prefix=False)
    headers = request_headers(content_type="application/json")
    payload = {"username": username, "password": password}
    timeout = http_timeout()
    client_factory = ctx.http_client_factory if ctx is not None else default_http_client_factory
    with client_factory(timeout) as client:
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


def swain_refresh_with_token(
    base_url: str,
    refresh_token: str,
    *,
    ctx: Optional[AppContext] = None,
) -> Dict[str, Any]:
    token_value = refresh_token.strip()
    if not token_value:
        raise CLIError("refresh token is empty; run 'swain_cli auth login'")

    candidates = [
        "auth/refresh",
        "auth/refresh-token",
        "auth/refresh_token",
        "auth/token/refresh",
    ]
    payloads = [
        {"refresh_token": token_value},
        {"refreshToken": token_value},
        {"token": token_value},
    ]

    timeout = http_timeout()
    headers = request_headers(content_type="application/json")
    last_error: Optional[str] = None
    client_factory = ctx.http_client_factory if ctx is not None else default_http_client_factory
    with client_factory(timeout) as client:
        for path in candidates:
            url = swain_url(base_url, path, enforce_api_prefix=False)
            for payload in payloads:
                try:
                    response = client.post(url, headers=headers, json=payload)
                    if response.status_code in {404, 405}:
                        continue
                    response.raise_for_status()
                except httpx.HTTPError as exc:
                    last_error = describe_http_error(exc)
                    continue

                try:
                    data = response.json()
                except json.JSONDecodeError as exc:
                    raise CLIError("refresh response was not valid JSON") from exc
                if isinstance(data, dict):
                    return data
    detail = last_error or "no refresh endpoint matched"
    raise CLIError(f"refresh failed: {detail}")
