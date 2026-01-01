"""CrudSQL helpers for swain_cli."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Optional, Union

import httpx

from .console import log
from .errors import CLIError
from .http import describe_http_error, http_timeout, request_headers
from .urls import crudsql_dynamic_swagger_url


def crudsql_discover_schema_url(
    base_url: str, token: str, tenant_id: Optional[Union[str, int]] = None
) -> str:
    normalized_base = base_url.rstrip("/") + "/"
    discovery_url = httpx.URL(normalized_base).join("api/schema-location")
    headers = request_headers(token, tenant_id=tenant_id)

    timeout = http_timeout()
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        response = client.get(discovery_url, headers=headers)
    if response.status_code == 404:
        return crudsql_dynamic_swagger_url(base_url)
    try:
        response.raise_for_status()
    except httpx.HTTPError as exc:
        detail = describe_http_error(exc)
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
    headers = request_headers(token, tenant_id=tenant_id)

    timeout = http_timeout()
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        try:
            response = client.get(schema_url, headers=headers)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            detail = describe_http_error(exc)
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
