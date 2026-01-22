"""Shared HTTP helpers for swain_cli."""

from __future__ import annotations

import json
from typing import Dict, Optional, Union

import httpx

from .constants import HTTP_TIMEOUT_SECONDS, TENANT_HEADER_NAME
from .utils import safe_str
from .version import USER_AGENT


def http_timeout() -> httpx.Timeout:
    return httpx.Timeout(HTTP_TIMEOUT_SECONDS, connect=HTTP_TIMEOUT_SECONDS)


def normalize_tenant_id(value: Optional[Union[str, int]]) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        normalized = value.strip()
        return normalized or None
    return str(value)


def request_headers(
    token: str = "",
    *,
    tenant_id: Optional[Union[str, int]] = None,
    content_type: Optional[str] = None,
) -> Dict[str, str]:
    headers = {
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    normalized_tenant = normalize_tenant_id(tenant_id)
    if normalized_tenant:
        headers[TENANT_HEADER_NAME] = normalized_tenant
    if content_type:
        headers["Content-Type"] = content_type
    return headers


def describe_http_error(exc: httpx.HTTPError) -> str:
    detail = ""
    if isinstance(exc, httpx.HTTPStatusError):
        response = exc.response
        detail = f"{response.status_code} {response.reason_phrase}".strip()
        body = (getattr(response, "text", "") or "").strip()
        if body:
            extracted: Optional[str] = None
            try:
                data = response.json()
            except (json.JSONDecodeError, ValueError):
                data = None
            if isinstance(data, dict):
                extracted = safe_str(
                    data.get("detail") or data.get("message") or data.get("error")
                )
            if extracted:
                suffix = extracted.strip()
            else:
                suffix = body.splitlines()[0].strip()
            if suffix:
                detail = f"{detail}: {suffix}" if detail else suffix
        return detail

    request = getattr(exc, "request", None)
    target = ""
    if request is not None:
        method = getattr(request, "method", "") or ""
        url = getattr(request, "url", None)
        url_str = str(url) if url is not None else ""
        target = f"{method} {url_str}".strip()

    message = str(exc).strip()
    summary = message or exc.__class__.__name__
    if isinstance(exc, httpx.TimeoutException):
        summary = "request timed out"
        if message and "timed out" not in message.lower():
            summary = f"{summary}: {message}"
    elif isinstance(exc, httpx.ConnectError):
        summary = "failed to connect"
        if message and "connect" not in message.lower():
            summary = f"{summary}: {message}"
    elif isinstance(exc, httpx.ProxyError):
        summary = "proxy error"
        if message and "proxy" not in message.lower():
            summary = f"{summary}: {message}"
    elif isinstance(exc, httpx.RequestError):
        summary = "network error"
        if message and "network" not in message.lower():
            summary = f"{summary}: {message}"

    if target and target not in summary:
        summary = f"{summary} ({target})"
    return summary


def caused_by_status(exc: BaseException, status_code: int) -> bool:
    current: Optional[BaseException] = exc
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, httpx.HTTPStatusError):
            return current.response.status_code == status_code
        current = current.__cause__ or current.__context__
    return False
