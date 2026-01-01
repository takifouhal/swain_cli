"""CrudSQL helpers for swain_cli."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Optional, Union

import httpx

from .auth import _normalize_tenant_id
from .console import log
from .constants import HTTP_TIMEOUT_SECONDS, TENANT_HEADER_NAME
from .errors import CLIError
from .urls import crudsql_dynamic_swagger_url
from .version import USER_AGENT


def crudsql_discover_schema_url(
    base_url: str, token: str, tenant_id: Optional[Union[str, int]] = None
) -> str:
    normalized_base = base_url.rstrip("/") + "/"
    discovery_url = httpx.URL(normalized_base).join("api/schema-location")
    headers = {
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    normalized_tenant = _normalize_tenant_id(tenant_id)
    if normalized_tenant:
        headers[TENANT_HEADER_NAME] = normalized_tenant

    timeout = httpx.Timeout(HTTP_TIMEOUT_SECONDS, connect=HTTP_TIMEOUT_SECONDS)
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        response = client.get(discovery_url, headers=headers)
    if response.status_code == 404:
        return crudsql_dynamic_swagger_url(base_url)
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        detail = f"{exc.response.status_code} {exc.response.reason_phrase}".strip()
        raise CLIError(
            f"failed to resolve CrudSQL schema location from {discovery_url}: {detail}"
        ) from exc

    if not response.content or not response.content.strip():
        return crudsql_dynamic_swagger_url(base_url)

    try:
        data = response.json()
    except json.JSONDecodeError:
        return crudsql_dynamic_swagger_url(base_url)

    schema_url = data.get("schema_url") or data.get("schemaUrl")
    if not isinstance(schema_url, str) or not schema_url.strip():
        return crudsql_dynamic_swagger_url(base_url)

    return str(httpx.URL(normalized_base).join(schema_url.strip()))


def fetch_crudsql_schema(
    base_url: str, token: str, *, tenant_id: Optional[Union[str, int]] = None
) -> Path:
    schema_url = crudsql_discover_schema_url(base_url, token, tenant_id)
    log(f"fetching CrudSQL schema from {schema_url}")
    headers = {
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    normalized_tenant = _normalize_tenant_id(tenant_id)
    if normalized_tenant:
        headers[TENANT_HEADER_NAME] = normalized_tenant

    timeout = httpx.Timeout(HTTP_TIMEOUT_SECONDS, connect=HTTP_TIMEOUT_SECONDS)
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        try:
            response = client.get(schema_url, headers=headers)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            detail = ""
            if isinstance(exc, httpx.HTTPStatusError):
                status = exc.response.status_code
                reason = exc.response.reason_phrase
                detail = f"{status} {reason}".strip()
                body = exc.response.text.strip()
                if body:
                    first_line = body.splitlines()[0]
                    detail = f"{detail}: {first_line}" if detail else first_line
            if not detail:
                detail = str(exc)
            raise CLIError(
                f"failed to fetch CrudSQL schema from {schema_url}: {detail}"
            ) from exc

    if not response.content or not response.content.strip():
        raise CLIError("CrudSQL dynamic swagger response was empty")

    try:
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".json") as handle:
            handle.write(response.content)
            return Path(handle.name)
    except OSError as exc:
        raise CLIError(f"failed to persist CrudSQL schema locally: {exc}") from exc

