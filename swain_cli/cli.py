#!/usr/bin/env python3
"""swain_cli CLI entry point."""

from __future__ import annotations

import base64
import re
import hashlib
import json
import os
import platform
import shlex
import shutil
import string
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

import httpx
import keyring
from keyring.errors import NoKeyringError, PasswordDeleteError
import pooch
import questionary
import typer
from platformdirs import PlatformDirs

PINNED_GENERATOR_VERSION = "7.6.0"
JRE_VERSION = "21.0.4"
# JRE assets were renamed after v0.3.0; use v0.3.2 where
# the filenames match entries in JRE_ASSETS.
ASSET_BASE = "https://github.com/takifouhal/swain_cli/releases/download/v0.3.2"
CACHE_ENV_VAR = "SWAIN_CLI_CACHE_DIR"
DEFAULT_CACHE_DIR_NAME = "swain_cli"
AUTH_TOKEN_ENV_VAR = "SWAIN_CLI_AUTH_TOKEN"
TENANT_ID_ENV_VAR = "SWAIN_CLI_TENANT_ID"
TENANT_HEADER_NAME = "X-Tenant-ID"
KEYRING_SERVICE = "swain_cli"
KEYRING_USERNAME = "access_token"
KEYRING_REFRESH_USERNAME = "refresh_token"
JAVA_OPTS_ENV_VAR = "SWAIN_CLI_JAVA_OPTS"
DEFAULT_JAVA_HEAP_OPTION = "-Xmx2g"
DEFAULT_JAVA_OPTS = ["-Xms2g", "-Xmx10g", "-XX:+UseG1GC"]
FALLBACK_JAVA_HEAP_OPTION = "-Xmx14g"
OOM_MARKERS = ("OutOfMemoryError", "GC overhead limit exceeded")
GLOBAL_PROPERTY_DISABLE_DOCS = "apiDocs=false,apiTests=false,modelDocs=false,modelTests=false"
DEFAULT_CRUDSQL_BASE_URL = "https://api.swain.technology"
EXIT_CODE_SUBPROCESS = 1
EXIT_CODE_USAGE = 2
EXIT_CODE_INTERRUPT = 130
LANGUAGE_ALIASES = {"typescript": "typescript-axios"}
COMMON_LANGUAGES = [
    "python",
    "typescript",
    "go",
    "java",
    "csharp",
    "ruby",
    "kotlin",
    "swift",
]
VENDOR_JAR_NAME = f"openapi-generator-cli-{PINNED_GENERATOR_VERSION}.jar"
HTTP_TIMEOUT_SECONDS = 30.0

app = typer.Typer(help="swain_cli CLI")
auth_app = typer.Typer(help="Authentication helpers")
engine_app = typer.Typer(help="Embedded engine management")
app.add_typer(auth_app, name="auth")
app.add_typer(engine_app, name="engine")


class CLIError(Exception):
    """Raised for user-facing CLI errors."""


@dataclass(frozen=True)
class JREAsset:
    filename: str
    sha256: Optional[str]
    checksum_filename: Optional[str] = None


JRE_ASSETS: Dict[Tuple[str, str], JREAsset] = {
    ("linux", "x86_64"): JREAsset(
        "swain_cli-jre-linux-x86_64.tar.gz", None, "swain_cli-jre-linux-x86_64.tar.gz.sha256"
    ),
    ("linux", "arm64"): JREAsset(
        "swain_cli-jre-linux-arm64.tar.gz", None, "swain_cli-jre-linux-arm64.tar.gz.sha256"
    ),
    ("macos", "x86_64"): JREAsset(
        "swain_cli-jre-macos-x86_64.tar.gz",
        "6574e6f5f20633ecfa95202d6e5a196936f90f300c0c99f00f34df8ad5e8aeb6",
        "swain_cli-jre-macos-x86_64.tar.gz.sha256",
    ),
    ("macos", "arm64"): JREAsset(
        "swain_cli-jre-macos-arm64.tar.gz",
        "f4bdfa2bd54a2257e8b9f77a50c61e4709ebbddb296b0370955de35d84c79964",
        "swain_cli-jre-macos-arm64.tar.gz.sha256",
    ),
    ("windows", "x86_64"): JREAsset(
        "swain_cli-jre-windows-x86_64.zip", None, "swain_cli-jre-windows-x86_64.zip.sha256"
    ),
}


@dataclass(frozen=True)
class PlatformInfo:
    os_name: str
    arch: str

    @property
    def key(self) -> Tuple[str, str]:
        return (self.os_name, self.arch)


@dataclass
class EngineSnapshot:
    platform: PlatformInfo
    runtime_dir: Path
    embedded_java: Optional[Path]
    vendor_jar: Optional[Path]
    selected_generator: Optional[Path]
    selected_generator_error: Optional[str]
    cached_jars: List[str]
    system_java: Optional[str]


@dataclass
class AuthState:
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None


@dataclass
class CLIContext:
    generator_version: Optional[str] = None


@dataclass(frozen=True)
class ResolvedJavaOptions:
    options: List[str]
    provided: bool


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


def log(message: str) -> None:
    print(f"[swain_cli] {message}")


def log_error(message: str) -> None:
    print(f"[swain_cli] {message}", file=sys.stderr)


class HTTPXDownloader:
    """Pooch downloader that uses httpx for transfers."""

    def __init__(self, timeout: float) -> None:
        self.timeout = timeout

    def __call__(
        self,
        url: str,
        output_file: str,
        pooch_obj: pooch.Pooch,
        check_only: bool = False,
        **_: Any,
    ) -> None:
        timeout = httpx.Timeout(self.timeout, connect=self.timeout)
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            if check_only:
                response = client.head(url)
                response.raise_for_status()
                return
            with client.stream("GET", url) as response:
                response.raise_for_status()
                with open(output_file, "wb") as fh:
                    for chunk in response.iter_bytes():
                        fh.write(chunk)


HTTPX_DOWNLOADER = HTTPXDownloader(timeout=HTTP_TIMEOUT_SECONDS)


@lru_cache()
def get_platform_info() -> PlatformInfo:
    system = normalize_os(platform.system())
    arch = normalize_arch(platform.machine())
    return PlatformInfo(system, arch)


def normalize_os(system: str) -> str:
    system_lower = system.lower()
    if system_lower == "darwin":
        return "macos"
    if system_lower == "windows":
        return "windows"
    if system_lower == "linux":
        return "linux"
    return system_lower


def normalize_arch(machine: str) -> str:
    value = machine.lower()
    if value in {"x86_64", "amd64"}:
        return "x86_64"
    if value in {"arm64", "aarch64"}:
        return "arm64"
    return value


def cache_root() -> Path:
    explicit = os.environ.get(CACHE_ENV_VAR)
    if explicit:
        root = Path(explicit).expanduser()
    else:
        dirs = PlatformDirs(appname=DEFAULT_CACHE_DIR_NAME, appauthor=False, roaming=True)
        root = Path(dirs.user_cache_path)
    root.mkdir(parents=True, exist_ok=True)
    return root


def jre_install_dir() -> Path:
    info = get_platform_info()
    path = cache_root() / "jre" / f"{info.os_name}-{info.arch}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def jar_cache_dir() -> Path:
    path = cache_root() / "jars"
    path.mkdir(parents=True, exist_ok=True)
    return path


def downloads_dir() -> Path:
    path = cache_root() / "downloads"
    path.mkdir(parents=True, exist_ok=True)
    return path


def vendor_jar_path() -> Path:
    return Path(__file__).resolve().parent / "vendor" / VENDOR_JAR_NAME


def assets_dir() -> Path:
    return Path(__file__).resolve().parent / "assets"


def find_vendor_jar() -> Optional[Path]:
    jar_path = vendor_jar_path()
    return jar_path if jar_path.exists() else None


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
                keyring.delete_password(
                    KEYRING_SERVICE, KEYRING_REFRESH_USERNAME
                )
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


def crudsql_dynamic_swagger_url(base_url: str) -> str:
    parsed = httpx.URL(base_url)
    if not parsed.scheme or not parsed.host:
        raise CLIError(
            f"invalid CrudSQL base URL '{base_url}'; include scheme and host (e.g. https://api.example.com)"
        )
    normalized_base = base_url.rstrip("/") + "/"
    return str(httpx.URL(normalized_base).join("api/dynamic_swagger"))


def crudsql_discover_schema_url(
    base_url: str, token: str, tenant_id: Optional[Union[str, int]] = None
) -> str:
    normalized_base = base_url.rstrip("/") + "/"
    discovery_url = httpx.URL(normalized_base).join("api/schema-location")
    headers = {
        "Accept": "application/json",
        "User-Agent": f"swain_cli/{PINNED_GENERATOR_VERSION}",
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
        "User-Agent": f"swain_cli/{PINNED_GENERATOR_VERSION}",
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


def _swain_url(
    base_url: str, path: str, *, enforce_api_prefix: bool = True
) -> httpx.URL:
    normalized_base = base_url.rstrip("/") + "/"
    base_url_obj = httpx.URL(normalized_base)
    normalized_path = path.lstrip("/")

    if (
        enforce_api_prefix
        and normalized_path
        and not normalized_path.startswith("api/")
    ):
        path_segments = [segment for segment in base_url_obj.path.split("/") if segment]
        if not any(segment == "api" for segment in path_segments):
            # Ensure requests target the API prefix even when the base URL omits it.
            base_url_obj = base_url_obj.join("api/")

    return base_url_obj.join(normalized_path)


def _normalize_tenant_id(value: Optional[Union[str, int]]) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        normalized = value.strip()
        return normalized or None
    return str(value)


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
        normalized = _normalize_tenant_id(value)
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


def _fetch_account_name_for_tenant(
    base_url: str, token: str, tenant_id: Union[str, int]
) -> Optional[str]:
    normalized = _normalize_tenant_id(tenant_id)
    if not normalized:
        return None

    url = _swain_url(base_url, f"Account/{normalized}")
    headers = _swain_request_headers(token, tenant_id=normalized)
    timeout = httpx.Timeout(HTTP_TIMEOUT_SECONDS, connect=HTTP_TIMEOUT_SECONDS)
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
        name = _safe_str(_pick(payload, "name"))
        if name:
            return name
        data_section = payload.get("data")
        if isinstance(data_section, dict):
            name = _safe_str(_pick(data_section, "name"))
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
    explicit = _normalize_tenant_id(provided)
    if explicit:
        return explicit

    env_value = _normalize_tenant_id(os.environ.get(TENANT_ID_ENV_VAR))
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
                log(
                    f"using tenant id {tenant_id} derived from access token claims"
                )
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


def _swain_request_headers(
    token: str, *, tenant_id: Optional[Union[str, int]] = None
) -> Dict[str, str]:
    headers = {
        "Accept": "application/json",
        "User-Agent": f"swain_cli/{PINNED_GENERATOR_VERSION}",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    normalized_tenant = _normalize_tenant_id(tenant_id)
    if normalized_tenant:
        headers[TENANT_HEADER_NAME] = normalized_tenant
    return headers


def _safe_int(value: Any) -> Optional[int]:
    try:
        if value is None:
            return None
        if isinstance(value, bool):
            return int(value)
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _safe_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return str(value)


def _as_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _pick(mapping: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def swain_login_with_credentials(
    base_url: str, username: str, password: str
) -> Dict[str, Any]:
    if not username.strip():
        raise CLIError("username is required for credential login")
    if not password:
        raise CLIError("password is required for credential login")
    login_url = _swain_url(base_url, "auth/login", enforce_api_prefix=False)
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": f"swain_cli/{PINNED_GENERATOR_VERSION}",
    }
    payload = {"username": username, "password": password}
    timeout = httpx.Timeout(HTTP_TIMEOUT_SECONDS, connect=HTTP_TIMEOUT_SECONDS)
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        try:
            response = client.post(login_url, headers=headers, json=payload)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            detail = ""
            if isinstance(exc, httpx.HTTPStatusError):
                status = exc.response.status_code
                reason = exc.response.reason_phrase
                detail = f"{status} {reason}".strip()
                body = exc.response.text.strip()
                if body:
                    try:
                        data = exc.response.json()
                        error_msg = _safe_str(
                            data.get("detail") if isinstance(data, dict) else None
                        )
                        if error_msg:
                            detail = f"{detail}: {error_msg}" if detail else error_msg
                    except json.JSONDecodeError:
                        first_line = body.splitlines()[0]
                        detail = f"{detail}: {first_line}" if detail else first_line
            if not detail:
                detail = str(exc)
            raise CLIError(f"credential login failed: {detail}") from exc
    try:
        data = response.json()
    except json.JSONDecodeError as exc:
        raise CLIError("login response was not valid JSON") from exc
    token = _safe_str(data.get("token"))
    if not token:
        raise CLIError("login response did not include an access token")
    return data


def fetch_swain_projects(
    base_url: str,
    token: str,
    *,
    tenant_id: Optional[Union[str, int]] = None,
    page_size: int = 50,
    max_pages: int = 25,
) -> List[SwainProject]:
    url = _swain_url(base_url, "Project")
    headers = _swain_request_headers(token, tenant_id=tenant_id)
    timeout = httpx.Timeout(HTTP_TIMEOUT_SECONDS, connect=HTTP_TIMEOUT_SECONDS)
    projects: List[SwainProject] = []
    page = 1
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        while True:
            params = {"page": page, "pageSize": page_size}
            try:
                response = client.get(url, headers=headers, params=params)
                response.raise_for_status()
            except httpx.HTTPError as exc:
                detail = ""
                if isinstance(exc, httpx.HTTPStatusError):
                    detail = f"{exc.response.status_code} {exc.response.reason_phrase}".strip()
                    body = exc.response.text.strip()
                    if body:
                        first_line = body.splitlines()[0]
                        detail = f"{detail}: {first_line}" if detail else first_line
                if not detail:
                    detail = str(exc)
                raise CLIError(
                    f"failed to fetch projects from {url}: {detail}"
                ) from exc
            try:
                payload = response.json()
            except json.JSONDecodeError as exc:
                raise CLIError(
                    "project listing response was not valid JSON"
                ) from exc

            items = payload.get("data") or []
            if not isinstance(items, list):
                raise CLIError("unexpected project payload structure")
            for entry in items:
                record = _as_dict(entry)
                project_id = _safe_int(_pick(record, "id", "project_id", "projectId"))
                if project_id is None:
                    continue
                name = _safe_str(_pick(record, "name"))
                if not name:
                    name = f"Project {project_id}"
                description = _safe_str(_pick(record, "description"))
                projects.append(
                    SwainProject(
                        id=project_id,
                        name=name,
                        description=description,
                        raw=record,
                    )
                )

            total_pages = _safe_int(_pick(payload, "total_pages", "totalPages")) or 1
            if page >= total_pages:
                break
            page += 1
            if page > max_pages:
                break
    return projects


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
    connection_id = _safe_int(_pick(record, "id", "connection_id", "connectionId"))
    if connection_id is None:
        return None
    database_name = _safe_str(
        _pick(record, "dbname", "database_name", "databaseName", "name")
    )
    driver = _safe_str(_pick(record, "driver"))
    stage = _safe_str(_pick(_as_dict(_pick(record, "stage")), "name"))
    project_name = _safe_str(
        _pick(_as_dict(_pick(record, "project")), "name")
    )
    current_schema = _as_dict(_pick(record, "current_schema", "currentSchema"))
    schema_name = _safe_str(_pick(current_schema, "name"))
    current_build = _as_dict(
        _pick(current_schema, "current_build", "currentBuild")
    )
    build_endpoint = _safe_str(
        _pick(current_build, "api_endpoint", "apiEndpoint")
    )
    build_id = _safe_int(_pick(current_build, "id"))
    connection_endpoint = _safe_str(
        _pick(record, "api_endpoint", "apiEndpoint")
    )
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
    url = _swain_url(base_url, "Connection/filter")
    headers = _swain_request_headers(token, tenant_id=tenant_id)
    payload = _connection_filter_payload(
        project_id=project_id, connection_id=connection_id
    )
    timeout = httpx.Timeout(HTTP_TIMEOUT_SECONDS, connect=HTTP_TIMEOUT_SECONDS)
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        params = {"page": 1, "pageSize": page_size}
        try:
            response = client.post(url, headers=headers, params=params, json=payload)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            detail = ""
            if isinstance(exc, httpx.HTTPStatusError):
                detail = f"{exc.response.status_code} {exc.response.reason_phrase}".strip()
                body = exc.response.text.strip()
                if body:
                    first_line = body.splitlines()[0]
                    detail = f"{detail}: {first_line}" if detail else first_line
            if not detail:
                detail = str(exc)
            raise CLIError(
                f"failed to fetch connections from {url}: {detail}"
            ) from exc
        try:
            payload = response.json()
        except json.JSONDecodeError as exc:
            raise CLIError(
                "connection filter response was not valid JSON"
            ) from exc

    items = payload.get("data") or []
    if not isinstance(items, list):
        raise CLIError("unexpected connection payload structure")

    connections: List[SwainConnection] = []
    for entry in items:
        record = _as_dict(entry)
        connection = _parse_swain_connection(record)
        if connection:
            connections.append(connection)
    return connections


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
    schema_url = _swain_url(
        base_url,
        f"connections/{connection.id}/dynamic_swagger",
    )
    log(
        f"fetching connection dynamic swagger from {schema_url} (connection {connection.id})"
    )
    headers = _swain_request_headers(token, tenant_id=tenant_id)
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


def get_jre_asset() -> JREAsset:
    info = get_platform_info()
    asset = JRE_ASSETS.get(info.key)
    if not asset:
        raise CLIError(
            f"unsupported platform {info.os_name}/{info.arch}; install Java and use --engine system"
        )
    return asset


def checksum_filename(asset: JREAsset) -> str:
    return asset.checksum_filename or f"{asset.filename}.sha256"


def parse_checksum_file(path: Path) -> str:
    try:
        lines = path.read_text().splitlines()
    except OSError as exc:
        raise CLIError(f"unable to read checksum file {path}: {exc}") from exc

    # Accept common formats:
    #  - "<hex>  filename" (GNU coreutils shasum/sha256sum)
    #  - "SHA256 (filename) = <hex>" (BSD shasum)
    #  - PowerShell Get-FileHash table output (second line contains algo, hash, path)
    #  - a bare 64-hex digest
    hex_pattern = re.compile(r"\b([A-Fa-f0-9]{64})\b")
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        match = hex_pattern.search(line)
        if match:
            return match.group(1).lower()
    raise CLIError(f"checksum file {path} did not contain a SHA-256 value")


def resolve_asset_sha256(asset: JREAsset) -> str:
    if asset.sha256:
        return asset.sha256
    filename = checksum_filename(asset)
    downloads = downloads_dir()
    checksum_path = Path(
        pooch.retrieve(
            url=f"{ASSET_BASE}/{filename}",
            path=downloads,
            fname=filename,
            known_hash=None,
            downloader=HTTPX_DOWNLOADER,
            progressbar=False,
        )
    )
    return parse_checksum_file(checksum_path)


def _bundled_asset_path(name: str) -> Optional[Path]:
    package_assets = assets_dir() / name
    if package_assets.exists():
        return package_assets
    project_root_candidate = Path(__file__).resolve().parent.parent / name
    if project_root_candidate.exists():
        return project_root_candidate
    return None


def _sha256_digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def _verify_sha256(path: Path, expected: Optional[str]) -> None:
    if not expected:
        return
    digest = _sha256_digest(path)
    if digest.lower() != expected.lower():
        raise CLIError(
            f"SHA-256 mismatch for {path.name}; expected {expected}, got {digest}"
        )


def fetch_asset_file(asset_name: str, sha256: Optional[str], force: bool = False) -> Path:
    downloads = downloads_dir()
    target = downloads / asset_name
    if force and target.exists():
        target.unlink()
    if target.exists() and not force:
        try:
            _verify_sha256(target, sha256)
        except CLIError:
            target.unlink()
        else:
            return target

    bundled = _bundled_asset_path(asset_name)
    if bundled:
        _verify_sha256(bundled, sha256)
        if bundled.resolve() != target.resolve():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(bundled, target)
        return target

    known_hash = f"sha256:{sha256}" if sha256 else None
    try:
        return Path(
            pooch.retrieve(
                url=f"{ASSET_BASE}/{asset_name}",
                path=downloads,
                fname=asset_name,
                known_hash=known_hash,
                downloader=HTTPX_DOWNLOADER,
                progressbar=False,
            )
        )
    except httpx.HTTPError as exc:
        bundled = _bundled_asset_path(asset_name)
        if bundled:
            _verify_sha256(bundled, sha256)
            if bundled.resolve() != target.resolve():
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(bundled, target)
            return target
        raise CLIError(
            f"failed to download embedded JRE asset {asset_name}: {exc}"
        ) from exc


def ensure_embedded_jre(force: bool = False) -> Path:
    asset = get_jre_asset()
    expected_sha = resolve_asset_sha256(asset)
    archive_path = fetch_asset_file(asset.filename, expected_sha, force=force)
    target_dir = jre_install_dir()

    if force and target_dir.exists():
        shutil.rmtree(target_dir)
    if target_dir.exists():
        shutil.rmtree(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    extract_archive(archive_path, target_dir)
    normalize_runtime_dir(target_dir)
    java_path = find_embedded_java(target_dir)
    if not java_path:
        raise CLIError(
            "embedded JRE installation did not produce a usable java executable"
        )
    return target_dir


def extract_archive(archive: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    try:
        shutil.unpack_archive(str(archive), str(dest))
    except (shutil.ReadError, ValueError) as exc:
        raise CLIError(f"unsupported archive format for {archive.name}") from exc


def normalize_runtime_dir(root: Path) -> None:
    java_path = root / "bin" / java_binary_name()
    if java_path.exists():
        return
    subdirs = [item for item in root.iterdir() if item.is_dir()]
    if len(subdirs) != 1:
        return
    inner = subdirs[0]
    inner_java = inner / "bin" / java_binary_name()
    if not inner_java.exists():
        return
    for item in inner.iterdir():
        shutil.move(str(item), root)
    shutil.rmtree(inner)


def java_binary_name() -> str:
    return "java.exe" if normalize_os(platform.system()) == "windows" else "java"


def find_embedded_java(root: Path) -> Optional[Path]:
    candidate = root / "bin" / java_binary_name()
    if candidate.exists():
        return candidate
    for path in root.rglob(java_binary_name()):
        if path.name == java_binary_name() and path.parent.name == "bin":
            return path
    return None


def collect_engine_snapshot(generator_version: Optional[str]) -> EngineSnapshot:
    info = get_platform_info()
    runtime_dir = jre_install_dir()
    embedded_java = find_embedded_java(runtime_dir)
    vendor = find_vendor_jar()
    selected: Optional[Path] = None
    selected_error: Optional[str] = None
    try:
        selected = resolve_generator_jar(generator_version)
    except CLIError as exc:
        selected_error = str(exc)
    cached = list_cached_jars()
    system_java = shutil.which("java")
    return EngineSnapshot(
        platform=info,
        runtime_dir=runtime_dir,
        embedded_java=embedded_java,
        vendor_jar=vendor,
        selected_generator=selected,
        selected_generator_error=selected_error,
        cached_jars=cached,
        system_java=system_java,
    )


def emit_engine_snapshot(
    snapshot: EngineSnapshot,
    *,
    include_selected_generator: bool,
    include_cached_jars: bool,
) -> None:
    runtime_dir = snapshot.runtime_dir
    log(
        f"embedded jre dir: {runtime_dir if runtime_dir.exists() else 'not initialized'}"
    )
    log(
        f"embedded java: {snapshot.embedded_java if snapshot.embedded_java else 'not installed'}"
    )
    log(
        f"bundled generator jar: {snapshot.vendor_jar if snapshot.vendor_jar else 'missing'}"
    )
    if include_selected_generator:
        if snapshot.selected_generator:
            log(f"selected generator jar: {snapshot.selected_generator}")
        elif snapshot.selected_generator_error:
            log_error(snapshot.selected_generator_error)
    if include_cached_jars:
        if snapshot.cached_jars:
            log("cached generator jars:")
            for entry in snapshot.cached_jars:
                log(f"  - {entry}")
        else:
            log("cached generator jars: none")
    log(
        f"system java: {snapshot.system_java if snapshot.system_java else 'not found'}"
    )


def resolve_generator_jar(version: Optional[str]) -> Path:
    chosen = version or os.environ.get("SWAIN_CLI_GENERATOR_VERSION")
    if not chosen:
        chosen = PINNED_GENERATOR_VERSION
    if chosen == PINNED_GENERATOR_VERSION:
        vendor = find_vendor_jar()
        if vendor:
            return vendor
        # No bundled jar; ensure the pinned version is downloaded to cache.
        return ensure_generator_jar(PINNED_GENERATOR_VERSION)
    jar_path = jar_cache_dir() / chosen / f"openapi-generator-cli-{chosen}.jar"
    if jar_path.exists():
        return jar_path
    if chosen == PINNED_GENERATOR_VERSION:
        # Should not happen because we auto-download above, but keep a friendly error.
        raise CLIError(
            "OpenAPI Generator jar missing; run 'swain_cli engine update-jar --version 7.6.0'"
        )
    raise CLIError(
        f"OpenAPI Generator {chosen} is not cached; run 'swain_cli engine update-jar --version {chosen}'"
    )


def ensure_generator_jar(version: str) -> Path:
    jar_path = jar_cache_dir() / version / f"openapi-generator-cli-{version}.jar"
    jar_path.parent.mkdir(parents=True, exist_ok=True)
    if jar_path.exists():
        return jar_path
    url = (
        "https://repo1.maven.org/maven2/org/openapitools/openapi-generator-cli/"
        f"{version}/openapi-generator-cli-{version}.jar"
    )
    target = Path(
        pooch.retrieve(
            url=url,
            path=jar_path.parent,
            fname=jar_path.name,
            known_hash=None,
            downloader=HTTPX_DOWNLOADER,
            progressbar=False,
        )
    )
    return target


def _global_property_mentions_docs(value: str) -> bool:
    entries = [item.strip() for item in value.split(",") if item.strip()]
    return any(
        entry.startswith(prefix)
        for entry in entries
        for prefix in ("apiDocs", "apiTests", "modelDocs", "modelTests")
    )


def generator_args_disable_docs(generator_args: Sequence[str]) -> bool:
    for arg in generator_args:
        if not arg.startswith("--global-property"):
            continue
        _, _, value = arg.partition("=")
        if _global_property_mentions_docs(value):
            return True
    return False


def command_disables_docs(cmd: Sequence[str]) -> bool:
    for idx, part in enumerate(cmd):
        if part == "--global-property":
            if idx + 1 < len(cmd) and _global_property_mentions_docs(cmd[idx + 1]):
                return True
        elif part.startswith("--global-property="):
            _, _, value = part.partition("=")
            if _global_property_mentions_docs(value):
                return True
    return False


def with_docs_disabled(cmd: Sequence[str]) -> List[str]:
    new_cmd = list(cmd)
    new_cmd.append(f"--global-property={GLOBAL_PROPERTY_DISABLE_DOCS}")
    return new_cmd


def replace_heap_option(java_opts: Sequence[str], new_heap: str) -> List[str]:
    replaced = False
    result: List[str] = []
    for opt in java_opts:
        if opt.startswith("-Xmx") and not replaced:
            result.append(new_heap)
            replaced = True
        else:
            result.append(opt)
    if not replaced:
        result.append(new_heap)
    return result


def resolve_java_opts(cli_opts: Sequence[str]) -> ResolvedJavaOptions:
    result: List[str] = []
    env_opts = os.environ.get(JAVA_OPTS_ENV_VAR)
    env_provided = bool(env_opts)
    if env_opts:
        result.extend(shlex.split(env_opts))
    cli_provided = bool(cli_opts)
    result.extend(cli_opts)
    provided = env_provided or cli_provided
    if not result:
        result.extend(DEFAULT_JAVA_OPTS)
    return ResolvedJavaOptions(result, provided)


def run_openapi_generator(
    jar: Path,
    engine: str,
    generator_args: Sequence[str],
    java_opts: Sequence[str],
) -> Tuple[int, str]:
    if engine not in {"embedded", "system"}:
        raise CLIError(f"unknown engine '{engine}'")
    java_options = list(java_opts)
    if engine == "embedded":
        runtime_dir = ensure_embedded_jre()
        java_exec = find_embedded_java(runtime_dir)
        if not java_exec:
            raise CLIError("embedded JRE is not installed; run 'swain_cli engine install-jre'")
        cmd = [str(java_exec), *java_options, "-jar", str(jar), *generator_args]
        env = os.environ.copy()
        env["JAVA_HOME"] = str(runtime_dir)
    else:
        java_exec = shutil.which("java")
        if not java_exec:
            raise CLIError("java executable not found in PATH; install Java or use embedded engine")
        cmd = [java_exec, *java_options, "-jar", str(jar), *generator_args]
        env = os.environ.copy()
    log(f"exec {' '.join(cmd)}")
    proc = subprocess.Popen(
        cmd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    combined_output: List[str] = []
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            sys.stdout.write(line)
            combined_output.append(line)
        proc.stdout.close()
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait()
        raise
    return proc.returncode, "".join(combined_output)


def is_url(path: str) -> bool:
    return "://" in path


class InteractionAborted(Exception):
    """Raised when the interactive session is cancelled."""


def prompt_text(
    prompt: str,
    *,
    default: Optional[str] = None,
    validate: Optional[Callable[[str], Optional[str]]] = None,
    allow_empty: bool = False,
) -> str:
    wrapped_validate: Optional[Callable[[str], Union[bool, str]]]
    if validate is None:
        wrapped_validate = None
    else:
        def wrapped_validate(value: str) -> Union[bool, str]:
            verdict = validate(value)
            return True if verdict is None else verdict
    question = questionary.text(
        prompt,
        default=default or "",
        validate=wrapped_validate,
    )
    result = question.ask()
    if result is None:
        raise InteractionAborted()
    stripped = result.strip()
    if not stripped and not allow_empty:
        log_error("please enter a value")
        return prompt_text(
            prompt,
            default=default,
            validate=validate,
            allow_empty=allow_empty,
        )
    return stripped


def prompt_confirm(prompt: str, *, default: bool) -> bool:
    result = questionary.confirm(prompt, default=default).ask()
    if result is None:
        raise InteractionAborted()
    return bool(result)


def prompt_password(prompt: str) -> str:
    result = questionary.password(prompt).ask()
    if result is None:
        raise InteractionAborted()
    return result.strip()


def prompt_select(prompt: str, choices: Sequence[Any]) -> Any:
    result = questionary.select(prompt, choices=choices).ask()
    if result is None:
        raise InteractionAborted()
    return result


def interactive_auth_setup() -> None:
    existing = resolve_auth_token()
    if existing:
        log("reusing existing authentication token")
        return
    else:
        log("no authentication token configured.")
        if not prompt_confirm("Sign in before continuing?", default=True):
            raise CLIError("authentication token required; run 'swain_cli auth login'")
    args = SimpleNamespace(username=None, password=None, auth_base_url=None)
    token = read_login_token(args)
    persist_auth_token(token, getattr(args, "login_refresh_token", None))


def guess_default_schema() -> Optional[Path]:
    for candidate in (
        Path("openapi.yaml"),
        Path("openapi.yml"),
        Path("swagger.yaml"),
        Path("swagger.yml"),
    ):
        if candidate.exists():
            return candidate
    return None


def format_cli_command(argv: Sequence[str]) -> str:
    return shlex.join(str(part) for part in argv)


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


def build_generate_command(
    schema: str, language: str, args: SimpleNamespace, out_dir: Path
) -> Tuple[str, Path, List[str]]:
    resolved_lang = LANGUAGE_ALIASES.get(language, language)
    target_dir = out_dir / resolved_lang
    target_dir.mkdir(parents=True, exist_ok=True)
    cmd: List[str] = [
        "generate",
        "-i",
        schema,
        "-g",
        resolved_lang,
        "-o",
        str(target_dir),
    ]
    if args.config:
        cmd.extend(["-c", args.config])
    if args.templates:
        cmd.extend(["-t", args.templates])
    for prop in args.additional_properties or []:
        cmd.extend(["-p", prop])
    for raw_arg in args.generator_arg or []:
        cmd.append(raw_arg)
    for var in getattr(args, "property", []) or []:
        cmd.extend(["-D", var])
    if args.skip_validate_spec:
        cmd.append("--skip-validate-spec")
    if args.verbose:
        cmd.append("-v")
    return resolved_lang, target_dir, cmd


def handle_gen(args: SimpleNamespace) -> int:
    jar = resolve_generator_jar(args.generator_version)
    engine = args.engine
    schema_arg = getattr(args, "schema", None)
    crudsql_url = getattr(args, "crudsql_url", None)
    swain_project_id = getattr(args, "swain_project_id", None)
    swain_connection_id = getattr(args, "swain_connection_id", None)
    swain_tenant_id = getattr(args, "swain_tenant_id", None)
    temp_schema: Optional[Path] = None
    selected_connection: Optional[SwainConnection] = None
    base_url = (
        crudsql_url.strip()
        if isinstance(crudsql_url, str) and crudsql_url.strip()
        else DEFAULT_CRUDSQL_BASE_URL
    )

    tenant_id_cache: Optional[str] = None

    def ensure_tenant_id(token: str) -> str:
        nonlocal tenant_id_cache
        if tenant_id_cache is None:
            tenant_id_cache = determine_swain_tenant_id(
                base_url,
                token,
                swain_tenant_id,
                allow_prompt=False,
            )
        return tenant_id_cache
    try:
        if schema_arg:
            schema = schema_arg
            if not is_url(schema):
                schema_path = Path(schema)
                if not schema_path.exists():
                    raise CLIError(f"schema not found: {schema_path}")
                schema = str(schema_path)
        else:
            purpose = (
                "fetch the Swain connection swagger document"
                if (swain_connection_id or swain_project_id)
                else "fetch the CrudSQL swagger document"
            )
            token = require_auth_token(purpose)
            tenant_id_value = ensure_tenant_id(token)
            if swain_connection_id or swain_project_id:
                project_id_value: Optional[int] = None
                connection_id_value: Optional[int] = None
                if swain_project_id is not None:
                    if isinstance(swain_project_id, int):
                        project_id_value = swain_project_id
                    else:
                        try:
                            project_id_value = int(swain_project_id)
                        except (TypeError, ValueError) as exc:
                            raise CLIError(
                                f"invalid project id '{swain_project_id}'"
                            ) from exc
                if swain_connection_id is not None:
                    if isinstance(swain_connection_id, int):
                        connection_id_value = swain_connection_id
                    else:
                        try:
                            connection_id_value = int(swain_connection_id)
                        except (TypeError, ValueError) as exc:
                            raise CLIError(
                                f"invalid connection id '{swain_connection_id}'"
                            ) from exc

                if connection_id_value is not None:
                    selected_connection = fetch_swain_connection_by_id(
                        base_url,
                        token,
                        connection_id_value,
                        tenant_id=tenant_id_value,
                    )
                    if project_id_value is not None:
                        connection_project_id = _safe_int(
                            _pick(
                                selected_connection.raw,
                                "project_id",
                                "projectId",
                            )
                        )
                        if (
                            connection_project_id is not None
                            and connection_project_id != project_id_value
                        ):
                            log(
                                "warning: connection project does not match provided project id"
                            )
                elif project_id_value is not None:
                    connections = fetch_swain_connections(
                        base_url,
                        token,
                        tenant_id=tenant_id_value,
                        project_id=project_id_value,
                    )
                    if not connections:
                        raise CLIError(
                            f"no connections found for project {project_id_value}"
                        )
                    if len(connections) > 1:
                        raise CLIError(
                            "multiple connections found; specify --swain-connection-id"
                        )
                    selected_connection = connections[0]
                else:
                    raise CLIError(
                        "--swain-connection-id or --swain-project-id is required when using Swain discovery"
                    )

                temp_schema = fetch_swain_connection_schema(
                    base_url,
                    selected_connection,
                    token,
                    tenant_id=tenant_id_value,
                )
                schema = str(temp_schema)
                log(
                    "using Swain connection"
                    f" {selected_connection.id}"
                    f" (project: {selected_connection.project_name or 'unknown'},"
                    f" schema: {selected_connection.schema_name or 'unknown'})"
                )
            else:
                temp_schema = fetch_crudsql_schema(
                    base_url,
                    token,
                    tenant_id=tenant_id_value,
                )
                schema = str(temp_schema)
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        languages = args.languages
        if not languages:
            raise CLIError("at least one --lang is required")
        # Ensure generated models include additionalProperties by default.
        # Many generators default to disallowing additionalProperties when not explicitly present in the spec.
        # Align with OAS/JSON Schema by setting disallowAdditionalPropertiesIfNotPresent=false unless the user overrides it.
        addl_props: List[str] = list(getattr(args, "additional_properties", None) or [])
        has_flag = any(
            (prop.split("=", 1)[0].strip() == "disallowAdditionalPropertiesIfNotPresent")
            for prop in addl_props
        )
        if not has_flag:
            addl_props.append("disallowAdditionalPropertiesIfNotPresent=false")
        setattr(args, "additional_properties", addl_props)
        raw_generator_args = getattr(args, "generator_arg", None) or []
        generator_args = list(raw_generator_args)
        if not generator_args_disable_docs(generator_args):
            generator_args.append(
                f"--global-property={GLOBAL_PROPERTY_DISABLE_DOCS}"
            )
        setattr(args, "generator_arg", generator_args)

        resolved_java_opts = resolve_java_opts(getattr(args, "java_opts", []))
        java_opts = list(resolved_java_opts.options)
        log(f"java options: {format_cli_command(java_opts)}")
        for lang in languages:
            resolved_lang, target_dir, cmd = build_generate_command(
                schema, lang, args, out_dir
            )
            log(f"generating {resolved_lang} into {target_dir}")
            current_cmd = list(cmd)
            current_java_opts = list(java_opts)
            docs_disabled = command_disables_docs(current_cmd)
            while True:
                rc, output = run_openapi_generator(
                    jar, engine, current_cmd, current_java_opts
                )
                if rc == 0:
                    break
                oom_detected = any(marker in output for marker in OOM_MARKERS)
                retried = False
                if rc != 0 and oom_detected:
                    new_java_opts = replace_heap_option(
                        current_java_opts, FALLBACK_JAVA_HEAP_OPTION
                    )
                    if new_java_opts != current_java_opts:
                        current_java_opts = new_java_opts
                        log(
                            "detected OutOfMemoryError; retrying"
                            f" with java options: {format_cli_command(current_java_opts)}"
                        )
                        retried = True
                    elif not docs_disabled:
                        current_cmd = with_docs_disabled(current_cmd)
                        docs_disabled = True
                        log(
                            "detected OutOfMemoryError; retrying with"
                            " OpenAPI Generator docs/tests disabled"
                        )
                        retried = True
                if not retried:
                    log_error(
                        f"generation failed for {resolved_lang} (exit code {rc})"
                    )
                    return rc if rc != 0 else EXIT_CODE_SUBPROCESS
            java_opts = current_java_opts
            resolved_java_opts = ResolvedJavaOptions(java_opts, provided=True)
    finally:
        if temp_schema:
            temp_schema.unlink(missing_ok=True)
    return 0


def handle_doctor(args: SimpleNamespace) -> int:
    system = platform.platform()
    python_version = sys.version.replace("\n", " ")
    snapshot = collect_engine_snapshot(args.generator_version)
    log("doctor report")
    log(f"python: {python_version}")
    log(f"platform: {system}")
    log(
        f"detected os/arch: {snapshot.platform.os_name}/{snapshot.platform.arch}"
    )
    emit_engine_snapshot(
        snapshot,
        include_selected_generator=True,
        include_cached_jars=False,
    )
    return 0


def list_cached_jars() -> List[str]:
    base = jar_cache_dir()
    entries: List[str] = []
    for version_dir in sorted(base.iterdir()):
        if not version_dir.is_dir():
            continue
        jar = version_dir / f"openapi-generator-cli-{version_dir.name}.jar"
        if jar.exists():
            entries.append(f"{version_dir.name} -> {jar}")
    return entries


def handle_list_generators(args: SimpleNamespace) -> int:
    jar = resolve_generator_jar(args.generator_version)
    resolved_java_opts = resolve_java_opts(getattr(args, "java_opts", []))
    java_opts = resolved_java_opts.options
    log(f"java options: {format_cli_command(java_opts)}")
    rc, _ = run_openapi_generator(jar, args.engine, ["list"], java_opts)
    if rc != 0:
        log_error("openapi-generator list failed")
        return rc if rc != 0 else EXIT_CODE_SUBPROCESS
    return 0


def handle_engine_status(args: SimpleNamespace) -> int:
    snapshot = collect_engine_snapshot(None)
    log("engine status")
    emit_engine_snapshot(
        snapshot,
        include_selected_generator=False,
        include_cached_jars=True,
    )
    return 0


def handle_engine_install_jre(args: SimpleNamespace) -> int:
    ensure_embedded_jre(force=args.force)
    runtime_dir = jre_install_dir()
    java_exec = find_embedded_java(runtime_dir)
    log(f"embedded jre ready at {runtime_dir}")
    if java_exec:
        log(f"java executable: {java_exec}")
    return 0


def handle_engine_update_jar(args: SimpleNamespace) -> int:
    ensure_generator_jar(args.version)
    log(f"cached OpenAPI Generator {args.version}")
    return 0


def handle_engine_use_system(_: SimpleNamespace) -> int:
    message = textwrap.dedent(
        """
        To use the system Java runtime, append '--engine system' to swain_cli commands.
        Example: swain_cli gen --engine system -i schema.yaml -l python -o sdks
        """
    ).strip()
    log(message)
    return 0


def handle_engine_use_embedded(_: SimpleNamespace) -> int:
    message = textwrap.dedent(
        """
        swain_cli uses the embedded runtime by default. To ensure it is ready, run:
          swain_cli engine install-jre
        You can explicitly select it with '--engine embedded'.
        """
    ).strip()
    log(message)
    return 0


def read_login_token(args: SimpleNamespace) -> str:
    username = getattr(args, "username", None)
    password = getattr(args, "password", None)
    auth_base = getattr(args, "auth_base_url", None) or DEFAULT_CRUDSQL_BASE_URL

    if not username:
        username = prompt_text("Username or email")
    if password is None:
        password = prompt_password("Password")

    login_payload = swain_login_with_credentials(auth_base, username, password)
    token_value = _safe_str(login_payload.get("token"))
    if not token_value:
        raise CLIError("credential login did not return an access token")

    refresh_value = _safe_str(
        login_payload.get("refresh_token")
        or login_payload.get("refreshToken")
        or login_payload.get("refresh-token")
    )
    setattr(args, "login_response", login_payload)
    setattr(args, "login_refresh_token", refresh_value)
    return token_value


def handle_auth_login(args: SimpleNamespace) -> int:
    token = read_login_token(args)
    refresh = getattr(args, "login_refresh_token", None)
    persist_auth_token(token, refresh)
    if refresh:
        log(
            "refresh token stored in keyring"
        )
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


def guess_default_output_dir() -> str:
    return "sdks"


def run_interactive(args: SimpleNamespace) -> int:
    log("interactive SDK generation wizard")
    log("press Ctrl+C at any time to cancel")
    interactive_auth_setup()
    crudsql_base_arg = getattr(args, "crudsql_url", None)
    crudsql_base = (
        crudsql_base_arg.strip()
        if isinstance(crudsql_base_arg, str) and crudsql_base_arg.strip()
        else DEFAULT_CRUDSQL_BASE_URL
    )
    dynamic_swagger_url: Optional[str] = None
    swain_project: Optional[SwainProject] = None
    swain_connection: Optional[SwainConnection] = None
    tenant_id: Optional[str] = None
    java_cli_opts: List[str] = list(getattr(args, "java_opts", []))
    generator_args: List[str] = list(getattr(args, "generator_args", None) or [])

    try:
        dynamic_swagger_url = crudsql_dynamic_swagger_url(crudsql_base)
        token = require_auth_token("discover Swain projects and connections")
        tenant_id = determine_swain_tenant_id(
            crudsql_base,
            token,
            tenant_id,
            allow_prompt=True,
        )
        projects = fetch_swain_projects(
            crudsql_base, token, tenant_id=tenant_id
        )
        if not projects:
            raise CLIError("no projects available on the Swain backend")
        if len(projects) == 1:
            swain_project = projects[0]
            log(
                f"Detected single project: {swain_project.name} (#{swain_project.id})"
            )
        else:
            project_options = {project.id: project for project in projects}
            project_choices = [
                questionary.Choice(
                    title=f"{project.name} (#{project.id})",
                    value=project.id,
                )
                for project in projects
            ]
            selected_project_id = prompt_select(
                "Select a project", project_choices
            )
            swain_project = project_options[selected_project_id]

        connections = fetch_swain_connections(
            crudsql_base,
            token,
            tenant_id=tenant_id,
            project_id=swain_project.id,
        )
        if not connections:
            raise CLIError(
                f"project {swain_project.name} has no connections with builds"
            )
        if len(connections) == 1:
            swain_connection = connections[0]
            log(
                "Detected single connection:"
                f" {swain_connection.database_name or swain_connection.id}"
            )
        else:
            connection_options = {conn.id: conn for conn in connections}
            connection_choices = [
                questionary.Choice(
                    title=(
                        f"#{conn.id} - {conn.database_name or 'connection'}"
                        f" ({conn.driver or 'driver'},"
                        f" schema={conn.schema_name or 'n/a'})"
                    ),
                    value=conn.id,
                )
                for conn in connections
            ]
            selected_connection_id = prompt_select(
                "Select a connection", connection_choices
            )
            swain_connection = connection_options[selected_connection_id]

        out_dir_input = prompt_text(
            "Output directory",
            default=guess_default_output_dir(),
            validate=lambda value: (
                "output path exists and is not a directory"
                if (Path(value).expanduser().exists() and not Path(value).expanduser().is_dir())
                else None
            ),
        )

        language_hint = ", ".join(COMMON_LANGUAGES)

        def parse_languages(raw: str) -> List[str]:
            entries = [item.strip() for item in raw.replace(";", ",").split(",") if item.strip()]
            return entries

        def validate_languages(raw: str) -> Optional[str]:
            if not parse_languages(raw):
                return "please provide at least one language"
            return None

        languages_raw = prompt_text(
            f"Target languages (comma separated, e.g. {language_hint})",
            default="python,typescript",
            validate=validate_languages,
        )
        languages = [lang.lower() for lang in parse_languages(languages_raw)]

        config_value = None

        templates_value = None

        additional_properties: List[str] = []

        sys_props: List[str] = []

        engine_choice = "embedded"
        skip_validate = False
        verbose = False

    except InteractionAborted:
        log_error("interactive session cancelled")
        return EXIT_CODE_INTERRUPT

    if swain_connection:
        schema_value = swain_dynamic_swagger_from_connection(swain_connection)
        schema_display = schema_value
    else:
        if dynamic_swagger_url is None:
            raise CLIError("failed to resolve dynamic swagger URL")
        schema_value = dynamic_swagger_url
        schema_display = schema_value

    out_value = str(Path(out_dir_input).expanduser())
    if not generator_args_disable_docs(generator_args):
        generator_args.append(f"--global-property={GLOBAL_PROPERTY_DISABLE_DOCS}")
    log("configuration preview")
    if swain_connection and swain_project:
        log(f"  swain base: {crudsql_base}")
        log(f"  project: {swain_project.name} (#{swain_project.id})")
        log(
            "  connection:"
            f" #{swain_connection.id}"
            f" ({swain_connection.database_name or 'connection'})"
        )
        log(f"  dynamic swagger: {schema_display}")
        if tenant_id:
            log(f"  tenant: {tenant_id}")
    elif crudsql_base:
        log(f"  crudsql base: {crudsql_base}")
        log(f"  dynamic swagger: {schema_display}")
        if tenant_id:
            log(f"  tenant: {tenant_id}")
    else:
        log(f"  schema: {schema_display}")
    log(f"  output: {out_value}")
    log(f"  languages: {', '.join(languages)}")
    if config_value:
        log(f"  config: {config_value}")
    if templates_value:
        log(f"  templates: {templates_value}")
    if additional_properties:
        log(f"  additional properties: {additional_properties}")
    if sys_props:
        log(f"  system properties: {sys_props}")
    if generator_args:
        log(f"  extra generator args: {generator_args}")
    log(f"  engine: {engine_choice}")
    log(f"  skip validate: {skip_validate}")
    log(f"  verbose: {verbose}")
    java_preview_opts = resolve_java_opts(java_cli_opts).options
    log(f"  java options: {format_cli_command(java_preview_opts)}")

    command_preview: List[str] = ["swain_cli"]
    if args.generator_version:
        command_preview.extend(["--generator-version", args.generator_version])
    command_preview.append("gen")
    if tenant_id:
        command_preview.extend(["--swain-tenant-id", tenant_id])
    if swain_connection and swain_project:
        if crudsql_base and crudsql_base != DEFAULT_CRUDSQL_BASE_URL:
            command_preview.extend(["--crudsql-url", crudsql_base])
        command_preview.extend(["--swain-project-id", str(swain_project.id)])
        command_preview.extend(["--swain-connection-id", str(swain_connection.id)])
    elif crudsql_base:
        if crudsql_base != DEFAULT_CRUDSQL_BASE_URL:
            command_preview.extend(["--crudsql-url", crudsql_base])
    else:
        command_preview.extend(["-i", schema_value])
    command_preview.extend(["-o", out_value])
    for lang in languages:
        command_preview.extend(["-l", lang])
    if config_value:
        command_preview.extend(["-c", config_value])
    if templates_value:
        command_preview.extend(["-t", templates_value])
    for prop in additional_properties:
        command_preview.extend(["-p", prop])
    for arg in generator_args:
        command_preview.extend(["--generator-arg", arg])
    for sys_prop in sys_props:
        command_preview.extend(["-D", sys_prop])
    if skip_validate:
        command_preview.append("--skip-validate-spec")
    if verbose:
        command_preview.append("-v")
    if engine_choice != "embedded":
        command_preview.extend(["--engine", engine_choice])
    preview_java_opts = (
        java_cli_opts if java_cli_opts else resolve_java_opts(java_cli_opts).options
    )
    for opt in preview_java_opts:
        command_preview.extend(["--java-opt", opt])

    log(f"equivalent command: {format_cli_command(command_preview)}")

    if not prompt_confirm("Run generation now?", default=True):
        log("generation skipped; run the command above when ready")
        return 0

    gen_args = SimpleNamespace(
        generator_version=args.generator_version,
        engine=engine_choice,
        schema=None if crudsql_base else schema_value,
        crudsql_url=crudsql_base,
        swain_project_id=swain_project.id if swain_project else None,
        swain_connection_id=swain_connection.id if swain_connection else None,
        swain_tenant_id=tenant_id,
        out=out_value,
        languages=languages,
        config=config_value,
        templates=templates_value,
        additional_properties=additional_properties,
        generator_arg=generator_args,
        java_opts=list(java_cli_opts),
        property=sys_props,
        skip_validate_spec=skip_validate,
        verbose=verbose,
    )
    return handle_gen(gen_args)


def handle_interactive(args: SimpleNamespace) -> int:
    return run_interactive(args)


@app.callback(invoke_without_command=True)
def cli_callback(
    ctx: typer.Context,
    generator_version: Optional[str] = typer.Option(
        None,
        "--generator-version",
        help="override the OpenAPI Generator version to use (must be cached)",
    ),
) -> None:
    ctx.obj = CLIContext(generator_version=generator_version)
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit(code=EXIT_CODE_USAGE)


@app.command()
def doctor(ctx: typer.Context) -> None:
    args = SimpleNamespace(generator_version=ctx.obj.generator_version)
    try:
        rc = handle_doctor(args)
    except CLIError as exc:
        log_error(f"error: {exc}")
        raise typer.Exit(code=EXIT_CODE_USAGE) from exc
    raise typer.Exit(code=rc)


@app.command("list-generators")
def list_generators(
    ctx: typer.Context,
    engine: str = typer.Option(
        "embedded",
        "--engine",
        case_sensitive=False,
        help="select Java runtime (default: embedded)",
        show_choices=True,
    ),
) -> None:
    args = SimpleNamespace(
        generator_version=ctx.obj.generator_version,
        engine=engine.lower(),
        java_opts=[],
    )
    try:
        rc = handle_list_generators(args)
    except CLIError as exc:
        log_error(f"error: {exc}")
        raise typer.Exit(code=EXIT_CODE_USAGE) from exc
    raise typer.Exit(code=rc)


@app.command()
def gen(
    ctx: typer.Context,
    schema: Optional[str] = typer.Option(None, "--schema", "-i", help="schema path or URL"),
    crudsql_url: Optional[str] = typer.Option(
        None,
        "--crudsql-url",
        help=f"CrudSQL base URL to pull dynamic swagger (default: {DEFAULT_CRUDSQL_BASE_URL})",
    ),
    lang: List[str] = typer.Option(
        [],
        "--lang",
        "-l",
        help="target generator (repeat for multiple languages)",
    ),
    out: str = typer.Option(..., "--out", "-o", help="output directory"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="generator config file"),
    templates: Optional[str] = typer.Option(None, "--templates", "-t", help="custom templates directory"),
    additional_properties: List[str] = typer.Option(
        [],
        "--additional-properties",
        "-p",
        help="key=value additional properties (repeatable)",
    ),
    generator_arg: List[str] = typer.Option(
        [],
        "--generator-arg",
        help="raw OpenAPI Generator argument (repeatable)",
    ),
    java_opt: List[str] = typer.Option(
        [],
        "--java-opt",
        help="JVM option passed to the OpenAPI Generator (repeatable)",
    ),
    swain_tenant_id: Optional[str] = typer.Option(
        None,
        "--swain-tenant-id",
        help=f"Tenant ID for Swain API requests (or set {TENANT_ID_ENV_VAR})",
    ),
    swain_project_id: Optional[int] = typer.Option(
        None,
        "--swain-project-id",
        help="select project ID from the Swain backend (requires auth token)",
    ),
    swain_connection_id: Optional[int] = typer.Option(
        None,
        "--swain-connection-id",
        help="select connection ID from the Swain backend (requires auth token)",
    ),
    property: List[str] = typer.Option(
        [],
        "-D",
        help="system properties passed to the generator",
    ),
    skip_validate_spec: bool = typer.Option(
        False,
        "--skip-validate-spec",
        help="skip OpenAPI spec validation",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="enable verbose OpenAPI Generator output",
    ),
    engine: str = typer.Option(
        "embedded",
        "--engine",
        case_sensitive=False,
        help="select Java runtime (default: embedded)",
        show_choices=True,
    ),
) -> None:
    args = SimpleNamespace(
        generator_version=ctx.obj.generator_version,
        engine=engine.lower(),
        schema=schema,
        crudsql_url=crudsql_url,
        out=out,
        languages=[entry.lower() for entry in lang],
        config=config,
        templates=templates,
        additional_properties=additional_properties,
        generator_arg=generator_arg,
        java_opts=java_opt,
        swain_tenant_id=swain_tenant_id,
        swain_project_id=swain_project_id,
        swain_connection_id=swain_connection_id,
        property=property,
        skip_validate_spec=skip_validate_spec,
        verbose=verbose,
    )
    try:
        rc = handle_gen(args)
    except CLIError as exc:
        log_error(f"error: {exc}")
        raise typer.Exit(code=EXIT_CODE_USAGE) from exc
    raise typer.Exit(code=rc)


@app.command()
def interactive(
    ctx: typer.Context,
    java_opt: List[str] = typer.Option(
        [],
        "--java-opt",
        help="JVM option passed to the OpenAPI Generator (repeatable)",
    ),
    generator_arg: List[str] = typer.Option(
        [],
        "--generator-arg",
        help="raw OpenAPI Generator argument (repeatable)",
    ),
    crudsql_url: Optional[str] = typer.Option(
        None,
        "--swain-base-url",
        "--crudsql-url",
        help=f"Swain base URL for dynamic schema (default: {DEFAULT_CRUDSQL_BASE_URL})",
    ),
) -> None:
    args = SimpleNamespace(
        generator_version=ctx.obj.generator_version,
        java_opts=java_opt,
        generator_args=generator_arg,
        crudsql_url=crudsql_url,
    )
    try:
        rc = handle_interactive(args)
    except CLIError as exc:
        log_error(f"error: {exc}")
        raise typer.Exit(code=EXIT_CODE_USAGE) from exc
    raise typer.Exit(code=rc)


@auth_app.command("login")
def auth_login(
    username: Optional[str] = typer.Option(
        None,
        "--username",
        "-u",
        help="Swain username or email for credential login",
    ),
    password: Optional[str] = typer.Option(
        None,
        "--password",
        help="Password for credential login (prompted when omitted)",
    ),
    auth_base_url: Optional[str] = typer.Option(
        None,
        "--auth-base-url",
        help=f"Authentication base URL (default: {DEFAULT_CRUDSQL_BASE_URL})",
    ),
) -> None:
    args = SimpleNamespace(
        username=username,
        password=password,
        auth_base_url=auth_base_url,
    )
    try:
        rc = handle_auth_login(args)
    except CLIError as exc:
        log_error(f"error: {exc}")
        raise typer.Exit(code=EXIT_CODE_USAGE) from exc
    raise typer.Exit(code=rc)


@auth_app.command("logout")
def auth_logout() -> None:
    rc = handle_auth_logout(SimpleNamespace())
    raise typer.Exit(code=rc)


@auth_app.command("status")
def auth_status() -> None:
    rc = handle_auth_status(SimpleNamespace())
    raise typer.Exit(code=rc)


@engine_app.command("status")
def engine_status() -> None:
    rc = handle_engine_status(SimpleNamespace())
    raise typer.Exit(code=rc)


@engine_app.command("install-jre")
def engine_install_jre(
    force: bool = typer.Option(
        False,
        "--force",
        help="reinstall even if already present",
    )
) -> None:
    args = SimpleNamespace(force=force)
    try:
        rc = handle_engine_install_jre(args)
    except CLIError as exc:
        log_error(f"error: {exc}")
        raise typer.Exit(code=EXIT_CODE_USAGE) from exc
    raise typer.Exit(code=rc)


@engine_app.command("update-jar")
def engine_update_jar(
    version: str = typer.Option(..., "--version", help="OpenAPI Generator version to download")
) -> None:
    args = SimpleNamespace(version=version)
    try:
        rc = handle_engine_update_jar(args)
    except CLIError as exc:
        log_error(f"error: {exc}")
        raise typer.Exit(code=EXIT_CODE_USAGE) from exc
    raise typer.Exit(code=rc)


@engine_app.command("use-system")
def engine_use_system() -> None:
    rc = handle_engine_use_system(SimpleNamespace())
    raise typer.Exit(code=rc)


@engine_app.command("use-embedded")
def engine_use_embedded() -> None:
    rc = handle_engine_use_embedded(SimpleNamespace())
    raise typer.Exit(code=rc)


def main(argv: Optional[Sequence[str]] = None) -> int:
    command = typer.main.get_command(app)
    try:
        command.main(
            args=list(argv) if argv is not None else None,
            prog_name="swain_cli",
            standalone_mode=False,
        )
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
