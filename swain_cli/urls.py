"""URL helpers for Swain + CrudSQL endpoints."""

from __future__ import annotations

from typing import List, Optional, Tuple

import httpx

from .constants import DEFAULT_SWAIN_BASE_URL
from .errors import CLIError


def normalize_base_url(value: Optional[str]) -> Optional[str]:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _strip_trailing_crud(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    if normalized.endswith("/api/crud"):
        return normalized[: -len("/api/crud")]
    if normalized.endswith("/crud"):
        return normalized[: -len("/crud")]
    return normalized


def _ensure_crudsql_base(swain_base_url: str) -> str:
    normalized = swain_base_url.rstrip("/")
    if normalized.endswith("/api/crud"):
        return normalized
    if normalized.endswith("/crud"):
        return f"{normalized[: -len('/crud')]}/api/crud"
    return f"{normalized}/api/crud"


def _normalize_crudsql_base(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    if normalized.endswith("/api/crud"):
        return normalized
    if normalized.endswith("/crud"):
        return f"{normalized[: -len('/crud')]}/api/crud"
    return normalized


def resolve_base_urls(
    swain_base_url: Optional[str],
    crudsql_base_url: Optional[str],
) -> Tuple[str, str]:
    """
    Determine the Swain platform base and CrudSQL base URLs.

    - Swain operations (auth, project/connection discovery) use swain_base_url.
    - CrudSQL operations (dynamic swagger, schema discovery) use crudsql_base_url.
    - When only swain_base_url is provided, the CrudSQL base is inferred by
      appending '/api/crud' for the Swain v2 backend proxy.
    - When only crudsql_base_url is provided, the Swain base falls back to the
      CrudSQL host with a trailing '/api/crud' or '/crud' stripped if present.
    """
    normalized_swain = normalize_base_url(swain_base_url)
    normalized_crud = normalize_base_url(crudsql_base_url)

    swain_base_candidate = normalized_swain or _strip_trailing_crud(normalized_crud or "")
    swain_base = _strip_trailing_crud(swain_base_candidate or DEFAULT_SWAIN_BASE_URL)
    crudsql_base = (
        _normalize_crudsql_base(normalized_crud)
        if normalized_crud
        else _ensure_crudsql_base(swain_base)
    )
    return swain_base, crudsql_base


def swain_url(
    base_url: str, path: str, *, enforce_api_prefix: bool = True
) -> httpx.URL:
    normalized_base = base_url.rstrip("/") + "/"
    base_url_obj = httpx.URL(normalized_base)
    normalized_path = path.lstrip("/")

    if enforce_api_prefix and normalized_path and not normalized_path.startswith("api/"):
        path_segments = [segment for segment in base_url_obj.path.split("/") if segment]
        if not path_segments or path_segments[-1] != "api":
            # Ensure requests target the API prefix even when the base URL omits it.
            base_url_obj = base_url_obj.join("api/")

    return base_url_obj.join(normalized_path)


def swain_auth_candidate_urls(base_url: str, path: str) -> List[httpx.URL]:
    """Return v2 and legacy auth endpoint candidates for a platform or proxy base."""

    root_base = _strip_trailing_crud(base_url)
    candidates = [
        swain_url(root_base, path, enforce_api_prefix=True),
        swain_url(root_base, path, enforce_api_prefix=False),
    ]
    unique: List[httpx.URL] = []
    seen: set[str] = set()
    for candidate in candidates:
        value = str(candidate)
        if value in seen:
            continue
        seen.add(value)
        unique.append(candidate)
    return unique


def crudsql_dynamic_swagger_url(base_url: str) -> str:
    parsed = httpx.URL(base_url)
    if not parsed.scheme or not parsed.host:
        raise CLIError(
            f"invalid CrudSQL base URL '{base_url}'; include scheme and host (e.g. https://api.example.com)"
        )
    normalized_base = base_url.rstrip("/") + "/"
    return str(httpx.URL(normalized_base).join("api/dynamic_swagger"))


_normalize_base_url = normalize_base_url
_swain_url = swain_url
