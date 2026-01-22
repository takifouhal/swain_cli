"""OpenAPI/Swagger document patch helpers."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import httpx

from .errors import CLIError


def _normalize_path(value: str) -> str:
    normalized = (value or "").strip()
    if not normalized:
        return ""
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    if normalized != "/" and normalized.endswith("/"):
        normalized = normalized.rstrip("/")
    return normalized


def _join_paths(prefix: str, suffix: str) -> str:
    prefix_norm = _normalize_path(prefix)
    suffix_norm = _normalize_path(suffix)

    if prefix_norm in ("", "/"):
        return suffix_norm or "/"
    if suffix_norm in ("", "/"):
        return prefix_norm
    if suffix_norm == prefix_norm or suffix_norm.startswith(f"{prefix_norm}/"):
        return suffix_norm
    return f"{prefix_norm}{suffix_norm}"


def _origin(url: httpx.URL) -> str:
    netloc = url.netloc
    if isinstance(netloc, bytes):
        netloc_str = netloc.decode("ascii")
    else:
        netloc_str = str(netloc)
    return f"{url.scheme}://{netloc_str}"


def _detect_spec_kind(doc: Dict[str, Any]) -> Optional[str]:
    swagger = doc.get("swagger")
    if isinstance(swagger, str) and swagger.strip():
        return "swagger2"
    openapi = doc.get("openapi")
    if isinstance(openapi, str) and openapi.strip():
        return "openapi3"
    return None


def _extract_server_path(url_value: str) -> Optional[str]:
    url_str = (url_value or "").strip()
    if not url_str:
        return None
    if "://" not in url_str:
        return url_str
    try:
        parsed = httpx.URL(url_str)
    except Exception:
        parsed = None

    if parsed is not None:
        return parsed.path

    scheme_sep = url_str.find("://")
    if scheme_sep == -1:
        return None
    authority_and_more = url_str[scheme_sep + 3 :]
    slash_idx = authority_and_more.find("/")
    if slash_idx == -1:
        return "/"
    path = authority_and_more[slash_idx:] or "/"
    for separator in ("?", "#"):
        if separator in path:
            path = path.split(separator, 1)[0] or "/"
    return path


_SERVER_VAR_PATTERN = re.compile(r"\{([^}]+)\}")


def _extract_server_path_from_entry(server_entry: Dict[str, Any]) -> Optional[str]:
    url_value = server_entry.get("url")
    if not isinstance(url_value, str):
        return None
    url_str = url_value.strip()
    if not url_str:
        return None

    extracted = _extract_server_path(url_str)

    variables = server_entry.get("variables")
    if (
        isinstance(variables, dict)
        and variables
        and "{" in url_str
        and "}" in url_str
        and (extracted is None or extracted == "/")
    ):
        defaults: Dict[str, str] = {}
        for name, definition in variables.items():
            if not isinstance(name, str):
                continue
            record = definition if isinstance(definition, dict) else {}
            default = record.get("default")
            if default is None:
                continue
            defaults[name] = str(default)

        if defaults:

            def replace(match: re.Match[str]) -> str:
                key = match.group(1)
                return defaults.get(key, match.group(0))

            url_str = _SERVER_VAR_PATTERN.sub(replace, url_str)
            extracted = _extract_server_path(url_str)

    return extracted


def inject_base_url(schema_path: Path, base_url: str) -> Optional[str]:
    """
    Best-effort patch: ensure the schema contains a concrete base URL so SDKs do
    not default to localhost.

    Returns the inferred base URL written into the document (when applied),
    otherwise None.
    """
    try:
        parsed_base = httpx.URL(base_url)
    except Exception:
        return None
    if not parsed_base.scheme or not parsed_base.host:
        return None

    try:
        raw = schema_path.read_bytes()
    except OSError as exc:
        raise CLIError(f"failed to read schema file: {exc}") from exc

    try:
        doc = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(doc, dict):
        return None

    kind = _detect_spec_kind(doc)
    if kind == "swagger2":
        netloc = parsed_base.netloc
        if isinstance(netloc, bytes):
            doc["host"] = netloc.decode("ascii")
        else:
            doc["host"] = str(netloc)

        existing_schemes = doc.get("schemes")
        schemes: Tuple[str, ...] = ()
        if isinstance(existing_schemes, list):
            schemes = tuple(
                item.strip()
                for item in existing_schemes
                if isinstance(item, str) and item.strip()
            )
        new_schemes = (parsed_base.scheme,) + tuple(
            scheme for scheme in schemes if scheme != parsed_base.scheme
        )
        doc["schemes"] = list(new_schemes)

        base_prefix = parsed_base.path
        if base_prefix == "/":
            base_prefix = ""
        existing_base_path = doc.get("basePath")
        base_path = existing_base_path if isinstance(existing_base_path, str) else ""
        doc["basePath"] = _join_paths(base_prefix, base_path)

        written_base = f"{_origin(parsed_base)}{doc['basePath']}"
    elif kind == "openapi3":
        base_prefix = parsed_base.path
        if base_prefix == "/":
            base_prefix = ""
        servers = doc.get("servers")
        server_entry: Dict[str, Any] = {}
        server_path: str = ""
        if isinstance(servers, list) and servers:
            first = servers[0]
            if isinstance(first, dict):
                server_entry = dict(first)
                extracted = _extract_server_path_from_entry(first)
                if extracted:
                    server_path = extracted
        desired_path = _join_paths(base_prefix, server_path)
        new_url = f"{_origin(parsed_base)}{'' if desired_path == '/' else desired_path}"
        server_entry["url"] = new_url
        doc["servers"] = [server_entry]
        written_base = new_url
    else:
        return None

    try:
        schema_path.write_text(
            json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise CLIError(f"failed to update schema file: {exc}") from exc
    return written_base
