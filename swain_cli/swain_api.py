"""Swain API helpers for project/connection discovery."""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import httpx

from .console import log
from .errors import CLIError
from .http import describe_http_error, http_timeout, request_headers
from .urls import swain_url
from .utils import as_dict, pick, safe_int, safe_str


@dataclass(frozen=True)
class SwainProject:
    """Minimal representation of a Swain project."""

    id: int
    name: str
    raw: Dict[str, Any]
    description: Optional[str] = None


@dataclass(frozen=True)
class SwainConnection:
    """Connection with optional build metadata for SDK generation."""

    id: int
    database_name: Optional[str]
    driver: Optional[str]
    stage: Optional[str]
    project_name: Optional[str]
    schema_name: Optional[str]
    build_id: Optional[int]
    build_endpoint: Optional[str]
    connection_endpoint: Optional[str]
    raw: Dict[str, Any]

    @property
    def effective_endpoint(self) -> Optional[str]:
        candidate = (self.connection_endpoint or "").strip()
        if candidate:
            return candidate
        build_candidate = (self.build_endpoint or "").strip()
        return build_candidate or None


def fetch_swain_projects(
    base_url: str,
    token: str,
    *,
    tenant_id: Optional[Union[str, int]] = None,
    page_size: int = 50,
    max_pages: int = 25,
) -> List[SwainProject]:
    url = swain_url(base_url, "Project")
    headers = request_headers(token, tenant_id=tenant_id)
    timeout = http_timeout()
    projects: List[SwainProject] = []
    page = 1
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        while True:
            params = {"page": page, "pageSize": page_size}
            try:
                response = client.get(url, headers=headers, params=params)
                response.raise_for_status()
            except httpx.HTTPError as exc:
                detail = describe_http_error(exc)
                raise CLIError(f"failed to fetch projects from {url}: {detail}") from exc
            try:
                payload = response.json()
            except json.JSONDecodeError as exc:
                raise CLIError("project listing response was not valid JSON") from exc

            items = payload.get("data") or []
            if not isinstance(items, list):
                raise CLIError("unexpected project payload structure")
            for entry in items:
                record = as_dict(entry)
                project_id = safe_int(pick(record, "id", "project_id", "projectId"))
                if project_id is None:
                    continue
                name = safe_str(pick(record, "name"))
                if not name:
                    name = f"Project {project_id}"
                description = safe_str(pick(record, "description"))
                projects.append(
                    SwainProject(
                        id=project_id,
                        name=name,
                        description=description,
                        raw=record,
                    )
                )

            total_pages = safe_int(pick(payload, "total_pages", "totalPages")) or 1
            if page >= total_pages:
                break
            page += 1
            if page > max_pages:
                break
    return projects


def _fetch_swain_projects_with_fallback(
    primary_base: str,
    fallback_base: Optional[str],
    token: str,
    *,
    tenant_id: Optional[Union[str, int]] = None,
    page_size: int = 50,
    max_pages: int = 25,
) -> List[SwainProject]:
    try:
        return fetch_swain_projects(
            primary_base,
            token,
            tenant_id=tenant_id,
            page_size=page_size,
            max_pages=max_pages,
        )
    except CLIError as exc:
        if not fallback_base or fallback_base == primary_base:
            raise
        message = str(exc)
        if "404" not in message and "Not Found" not in message:
            raise
    return fetch_swain_projects(
        fallback_base,
        token,
        tenant_id=tenant_id,
        page_size=page_size,
        max_pages=max_pages,
    )


def _connection_filter_payload(
    *, project_id: Optional[int] = None, connection_id: Optional[int] = None
) -> Dict[str, Any]:
    expressions: List[Dict[str, Any]] = []
    if project_id is not None:
        expressions.append(
            {
                "field": "project_id",
                "operator": "eq",
                "value": project_id,
            }
        )
    if connection_id is not None:
        expressions.append(
            {
                "field": "id",
                "operator": "eq",
                "value": connection_id,
            }
        )
    expressions.extend(
        [
            {
                "relationship": "Stage",
                "scope": "filterChild",
                "include": True,
            },
            {
                "relationship": "Project",
                "scope": "filterChild",
                "include": True,
            },
            {
                "relationship": "CurrentSchema",
                "scope": "filterChild",
                "include": True,
                "expressions": [
                    {
                        "relationship": "CurrentBuild",
                        "scope": "filterChild",
                        "include": True,
                    }
                ],
            },
        ]
    )
    return {"expressions": expressions}


def _parse_swain_connection(record: Dict[str, Any]) -> Optional[SwainConnection]:
    connection_id = safe_int(pick(record, "id", "connection_id", "connectionId"))
    if connection_id is None:
        return None
    database_name = safe_str(
        pick(record, "dbname", "database_name", "databaseName", "name")
    )
    driver = safe_str(pick(record, "driver"))
    stage = safe_str(pick(as_dict(pick(record, "stage")), "name"))
    project_name = safe_str(pick(as_dict(pick(record, "project")), "name"))
    current_schema = as_dict(pick(record, "current_schema", "currentSchema"))
    schema_name = safe_str(pick(current_schema, "name"))
    current_build = as_dict(pick(current_schema, "current_build", "currentBuild"))
    build_endpoint = safe_str(pick(current_build, "api_endpoint", "apiEndpoint"))
    build_id = safe_int(pick(current_build, "id"))
    connection_endpoint = safe_str(pick(record, "api_endpoint", "apiEndpoint"))
    return SwainConnection(
        id=connection_id,
        database_name=database_name,
        driver=driver,
        stage=stage,
        project_name=project_name,
        schema_name=schema_name,
        build_id=build_id,
        build_endpoint=build_endpoint,
        connection_endpoint=connection_endpoint,
        raw=record,
    )


def fetch_swain_connections(
    base_url: str,
    token: str,
    *,
    tenant_id: Optional[Union[str, int]] = None,
    project_id: Optional[int] = None,
    connection_id: Optional[int] = None,
    page_size: int = 100,
) -> List[SwainConnection]:
    url = swain_url(base_url, "Connection/filter")
    headers = request_headers(token, tenant_id=tenant_id)
    payload = _connection_filter_payload(
        project_id=project_id, connection_id=connection_id
    )
    timeout = http_timeout()
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        params = {"page": 1, "pageSize": page_size}
        try:
            response = client.post(url, headers=headers, params=params, json=payload)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            detail = describe_http_error(exc)
            raise CLIError(f"failed to fetch connections from {url}: {detail}") from exc
        try:
            payload = response.json()
        except json.JSONDecodeError as exc:
            raise CLIError("connection filter response was not valid JSON") from exc

    items = payload.get("data") or []
    if not isinstance(items, list):
        raise CLIError("unexpected connection payload structure")

    connections: List[SwainConnection] = []
    for entry in items:
        record = as_dict(entry)
        connection = _parse_swain_connection(record)
        if connection:
            connections.append(connection)
    return connections


def _fetch_swain_connections_with_fallback(
    primary_base: str,
    fallback_base: Optional[str],
    token: str,
    *,
    tenant_id: Optional[Union[str, int]] = None,
    project_id: Optional[int] = None,
    connection_id: Optional[int] = None,
    page_size: int = 100,
) -> List[SwainConnection]:
    try:
        return fetch_swain_connections(
            primary_base,
            token,
            tenant_id=tenant_id,
            project_id=project_id,
            connection_id=connection_id,
            page_size=page_size,
        )
    except CLIError as exc:
        if not fallback_base or fallback_base == primary_base:
            raise
        message = str(exc)
        if "404" not in message and "Not Found" not in message:
            raise
    return fetch_swain_connections(
        fallback_base,
        token,
        tenant_id=tenant_id,
        project_id=project_id,
        connection_id=connection_id,
        page_size=page_size,
    )


def fetch_swain_connection_by_id(
    base_url: str,
    token: str,
    connection_id: int,
    *,
    tenant_id: Optional[Union[str, int]] = None,
) -> SwainConnection:
    connections = fetch_swain_connections(
        base_url,
        token,
        tenant_id=tenant_id,
        connection_id=connection_id,
    )
    if not connections:
        raise CLIError(f"connection {connection_id} not found")
    return connections[0]


def swain_dynamic_swagger_from_connection(connection: SwainConnection) -> str:
    endpoint = connection.effective_endpoint
    if not endpoint:
        raise CLIError(
            f"connection {connection.id} has no API endpoint on the current build"
        )
    base = endpoint.rstrip("/")
    return f"{base}/api/dynamic_swagger"


def fetch_swain_connection_schema(
    base_url: str,
    connection: SwainConnection,
    token: str,
    *,
    tenant_id: Optional[Union[str, int]] = None,
) -> Path:
    # Use the backend proxy so it can mint a per-connection preview JWT and
    # authenticate against the remote CrudSQL instance on our behalf.
    schema_url = swain_url(
        base_url,
        f"connections/{connection.id}/dynamic_swagger",
    )
    log(
        f"fetching connection dynamic swagger from {schema_url} (connection {connection.id})"
    )
    headers = request_headers(token, tenant_id=tenant_id)
    timeout = http_timeout()
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        try:
            response = client.get(schema_url, headers=headers)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            detail = describe_http_error(exc)
            raise CLIError(
                f"failed to fetch connection swagger for {connection.id}: {detail}"
            ) from exc
    if not response.content or not response.content.strip():
        raise CLIError("connection dynamic swagger response was empty")
    try:
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".json") as handle:
            handle.write(response.content)
            return Path(handle.name)
    except OSError as exc:
        raise CLIError(
            f"failed to persist connection swagger for {connection.id}: {exc}"
        ) from exc
