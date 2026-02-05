"""Shared HTTP helpers for swain_cli."""

from __future__ import annotations

import json
import time
from typing import Any, Callable, Dict, Optional, Union

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


def request_with_retries(
    client: httpx.Client,
    method: str,
    url: Union[str, httpx.URL],
    *,
    headers: Optional[Dict[str, str]] = None,
    params: Any = None,
    json: Any = None,
    max_attempts: int = 3,
    backoff_initial: float = 0.5,
    backoff_max: float = 8.0,
    sleep: Callable[[float], None] = time.sleep,
    retry_post: bool = False,
) -> httpx.Response:
    method_upper = (method or "").upper().strip() or "GET"
    allow_retry = method_upper in {"GET", "HEAD"} or (
        retry_post and method_upper == "POST"
    )
    retryable_statuses = {408, 429, 500, 502, 503, 504}

    def should_retry_exc(exc: httpx.HTTPError) -> bool:
        if isinstance(exc, httpx.TimeoutException):
            return True
        if isinstance(exc, httpx.RequestError):
            return True
        return False

    def retry_delay(attempt: int, response: Optional[httpx.Response]) -> float:
        if response is not None:
            retry_after = response.headers.get("Retry-After")
            if retry_after:
                try:
                    parsed = float(retry_after)
                except ValueError:
                    parsed = 0.0
                if parsed > 0:
                    return min(parsed, backoff_max)
        if attempt <= 0:
            return 0.0
        delay = backoff_initial * (2 ** (attempt - 1))
        return min(delay, backoff_max)

    attempt = 0
    while True:
        attempt += 1
        try:
            response = client.request(
                method_upper,
                url,
                headers=headers,
                params=params,
                json=json,
            )
        except httpx.HTTPError as exc:
            if not allow_retry or attempt >= max_attempts or not should_retry_exc(exc):
                raise
            delay = retry_delay(attempt, None)
            if delay > 0:
                sleep(delay)
            continue

        if (
            allow_retry
            and response.status_code in retryable_statuses
            and attempt < max_attempts
        ):
            delay = retry_delay(attempt, response)
            if delay > 0:
                sleep(delay)
            continue
        return response


def caused_by_status(exc: BaseException, status_code: int) -> bool:
    current: Optional[BaseException] = exc
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, httpx.HTTPStatusError):
            return current.response.status_code == status_code
        current = current.__cause__ or current.__context__
    return False
