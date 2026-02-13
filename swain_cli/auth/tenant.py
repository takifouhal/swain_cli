"""Swain tenant-id discovery + request header helpers."""

from __future__ import annotations

import base64
import json
import os
from typing import Any, Dict, List, Optional, Union

import httpx
import questionary

from ..console import log
from ..constants import TENANT_ID_ENV_VAR
from ..context import AppContext, default_http_client_factory
from ..errors import CLIError
from ..http import (
    http_timeout,
    normalize_tenant_id,
    request_headers,
    request_with_retries,
)
from ..prompts import prompt_select, prompt_text
from ..urls import swain_url
from ..utils import pick, safe_str


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
    base_url: str,
    token: str,
    tenant_id: Union[str, int],
    *,
    ctx: Optional[AppContext] = None,
) -> Optional[str]:
    normalized = normalize_tenant_id(tenant_id)
    if not normalized:
        return None

    url = swain_url(base_url, f"Account/{normalized}")
    headers = request_headers(token, tenant_id=normalized)
    timeout = http_timeout()
    client_factory = (
        ctx.http_client_factory if ctx is not None else default_http_client_factory
    )
    with client_factory(timeout) as client:
        try:
            response = request_with_retries(client, "GET", url, headers=headers)
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
    ctx: Optional[AppContext] = None,
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
            tenant_value = candidates[0]
            account_name = _fetch_account_name_for_tenant(
                base_url,
                token,
                tenant_value,
                ctx=ctx,
            )
            if account_name:
                log(
                    "using tenant"
                    f" {account_name} (#{tenant_value}) derived from access token claims"
                )
            else:
                log(f"using tenant id {tenant_value} derived from access token claims")
            return tenant_value
        if allow_prompt:
            ordered_choices = []
            for candidate in candidates:
                name = _fetch_account_name_for_tenant(
                    base_url,
                    token,
                    candidate,
                    ctx=ctx,
                )
                title = f"{name} (#{candidate})" if name else str(candidate)
                ordered_choices.append(questionary.Choice(title=title, value=str(candidate)))
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
