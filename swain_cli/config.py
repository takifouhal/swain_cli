"""Configuration file support for swain_cli."""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from platformdirs import PlatformDirs

from .constants import (
    CONFIG_ENV_VAR,
    DEFAULT_CACHE_DIR_NAME,
    DEFAULT_JAVA_OPTS,
    DEFAULT_SWAIN_BASE_URL,
    ENGINE_ENV_VAR,
    GENERATOR_VERSION_ENV_VAR,
    JAVA_OPTS_ENV_VAR,
    PINNED_GENERATOR_VERSION,
    TENANT_ID_ENV_VAR,
)
from .errors import CLIError
from .urls import resolve_base_urls

try:
    import tomllib  # py311+
except ModuleNotFoundError:  # pragma: no cover (py<311)
    import tomli as tomllib


@dataclass(frozen=True)
class ProfileConfig:
    """Named generation preset loaded from the config file."""

    languages: List[str] = field(default_factory=list)
    engine: Optional[str] = None
    generator_version: Optional[str] = None
    java_opts: List[str] = field(default_factory=list)
    config: Optional[str] = None
    templates: Optional[str] = None
    additional_properties: List[str] = field(default_factory=list)
    generator_arg: List[str] = field(default_factory=list)
    system_properties: List[str] = field(default_factory=list)
    patch_base_url: Optional[bool] = None
    emit_patched_schema: Optional[str] = None
    parallel: Optional[int] = None
    schema_cache_ttl: Optional[str] = None
    no_schema_cache: Optional[bool] = None
    post_hooks: List[str] = field(default_factory=list)
    post_hooks_by_language: Dict[str, List[str]] = field(default_factory=dict)
    run_hooks: Optional[bool] = None


@dataclass(frozen=True)
class ConfigFile:
    swain_base_url: Optional[str] = None
    crudsql_url: Optional[str] = None
    tenant_id: Optional[str] = None
    engine: Optional[str] = None
    generator_version: Optional[str] = None
    java_opts: List[str] = field(default_factory=list)
    languages: List[str] = field(default_factory=list)
    patch_base_url: Optional[bool] = None
    parallel: Optional[int] = None
    profiles: Dict[str, ProfileConfig] = field(default_factory=dict)


def default_config_path() -> Path:
    dirs = PlatformDirs(appname=DEFAULT_CACHE_DIR_NAME, appauthor=False, roaming=True)
    return Path(dirs.user_config_path) / "config.toml"


def resolve_config_path() -> Path:
    env_value = (os.environ.get(CONFIG_ENV_VAR) or "").strip()
    if env_value:
        return Path(env_value).expanduser()
    return default_config_path()


def _safe_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        normalized = value.strip()
        return normalized or None
    return str(value).strip() or None


def _safe_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    return None


def _safe_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _safe_str_list(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    result: List[str] = []
    for item in value:
        s = _safe_str(item)
        if s:
            result.append(s)
    return result


def _safe_str_list_map(value: Any) -> Dict[str, List[str]]:
    if not isinstance(value, dict):
        return {}
    result: Dict[str, List[str]] = {}
    for key, entry in value.items():
        name = _safe_str(key)
        if not name:
            continue
        items = _safe_str_list(entry)
        if items:
            result[name] = items
    return result


def _first_present(mapping: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def _load_profiles(value: Any) -> Dict[str, ProfileConfig]:
    profiles_raw: Dict[str, ProfileConfig] = {}
    if not isinstance(value, dict):
        return profiles_raw
    for name_raw, entry in value.items():
        name = _safe_str(name_raw)
        if not name or not isinstance(entry, dict):
            continue
        hooks_table = entry.get("hooks") or entry.get("post_hooks_by_language") or entry.get(
            "postHooksByLanguage"
        )
        profiles_raw[name] = ProfileConfig(
            languages=_safe_str_list(entry.get("languages") or entry.get("langs")),
            engine=_safe_str(entry.get("engine")),
            generator_version=_safe_str(
                entry.get("generator_version") or entry.get("generatorVersion")
            ),
            java_opts=_safe_str_list(entry.get("java_opts") or entry.get("javaOpts")),
            config=_safe_str(entry.get("config")),
            templates=_safe_str(entry.get("templates")),
            additional_properties=_safe_str_list(
                entry.get("additional_properties")
                or entry.get("additionalProperties")
                or entry.get("props")
            ),
            generator_arg=_safe_str_list(
                entry.get("generator_arg")
                or entry.get("generator_args")
                or entry.get("generatorArg")
                or entry.get("generatorArgs")
            ),
            system_properties=_safe_str_list(
                entry.get("system_properties")
                or entry.get("systemProperties")
                or entry.get("system_props")
                or entry.get("systemProps")
            ),
            patch_base_url=_safe_bool(_first_present(entry, "patch_base_url", "patchBaseUrl")),
            emit_patched_schema=_safe_str(
                entry.get("emit_patched_schema") or entry.get("emitPatchedSchema")
            ),
            parallel=_safe_int(entry.get("parallel")),
            schema_cache_ttl=_safe_str(
                entry.get("schema_cache_ttl") or entry.get("schemaCacheTtl")
            ),
            no_schema_cache=_safe_bool(_first_present(entry, "no_schema_cache", "noSchemaCache")),
            post_hooks=_safe_str_list(entry.get("post_hooks") or entry.get("postHooks")),
            post_hooks_by_language=_safe_str_list_map(hooks_table),
            run_hooks=_safe_bool(_first_present(entry, "run_hooks", "runHooks")),
        )
    return profiles_raw


def load_config(path: Optional[Path] = None) -> ConfigFile:
    config_path = path or resolve_config_path()
    if not config_path.exists():
        return ConfigFile()
    try:
        data = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CLIError(f"failed to read config file {config_path}: {exc}") from exc
    except Exception as exc:
        raise CLIError(f"failed to parse config file {config_path}: {exc}") from exc
    if not isinstance(data, dict):
        return ConfigFile()
    return ConfigFile(
        swain_base_url=_safe_str(data.get("swain_base_url") or data.get("swainBaseUrl")),
        crudsql_url=_safe_str(data.get("crudsql_url") or data.get("crudsqlUrl")),
        tenant_id=_safe_str(data.get("tenant_id") or data.get("tenantId")),
        engine=_safe_str(data.get("engine")),
        generator_version=_safe_str(
            data.get("generator_version") or data.get("generatorVersion")
        ),
        java_opts=_safe_str_list(data.get("java_opts") or data.get("javaOpts")),
        languages=_safe_str_list(data.get("languages") or data.get("langs")),
        patch_base_url=_safe_bool(_first_present(data, "patch_base_url", "patchBaseUrl")),
        parallel=_safe_int(data.get("parallel")),
        profiles=_load_profiles(data.get("profiles")),
    )


def config_template() -> str:
    return (
        "# swain_cli configuration (TOML)\n"
        "#\n"
        "# Precedence (highest -> lowest):\n"
        "#   CLI flags > environment variables > this file > built-in defaults\n"
        "\n"
        "# swain_base_url = \"https://api.swain.technology\"\n"
        "# crudsql_url = \"https://api.swain.technology/crud\"\n"
        "# tenant_id = \"123\"\n"
        "\n"
        "# engine = \"embedded\"  # or \"system\"\n"
        "# generator_version = \"7.6.0\"\n"
        "\n"
        "# java_opts = [\"-Xms2g\", \"-Xmx10g\", \"-XX:+UseG1GC\"]\n"
        "# languages = [\"python\", \"typescript\"]\n"
        "\n"
        "# patch_base_url = true\n"
        "# parallel = 1\n"
        "\n"
        "# Named generation profiles\n"
        "#\n"
        "# [profiles.frontend]\n"
        "# languages = [\"typescript\"]\n"
        "# additional_properties = [\"npmName=@acme/sdk\"]\n"
        "# generator_arg = [\"--global-property=apis=Job\", \"--skip-operation-example\"]\n"
        "# java_opts = [\"-Xms1g\", \"-Xmx6g\"]\n"
        "# parallel = 2\n"
        "#\n"
        "# post_hooks = [\"npm install\", \"npm run format\"]\n"
        "# run_hooks = false  # must be true (or pass --run-hooks) to execute hooks\n"
        "#\n"
        "# [profiles.frontend.hooks]\n"
        "# typescript-axios = [\"npm install\", \"npm run format\"]\n"
    )


def write_default_config(path: Optional[Path] = None, *, force: bool) -> Path:
    config_path = path or resolve_config_path()
    if config_path.exists() and not force:
        raise CLIError(f"config file already exists: {config_path} (use --force to overwrite)")
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(config_template(), encoding="utf-8")
    except OSError as exc:
        raise CLIError(f"failed to write config file {config_path}: {exc}") from exc
    return config_path


def effective_config(config: ConfigFile) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """
    Compute the effective config for display (no CLI flags), with sources.

    Returns (values, sources) where sources map key -> one of:
    "env", "config", "default", "derived".
    """
    sources: Dict[str, str] = {}

    swain_base = config.swain_base_url or DEFAULT_SWAIN_BASE_URL
    sources["swain_base_url"] = "config" if config.swain_base_url else "default"

    crudsql_url = config.crudsql_url
    if crudsql_url:
        sources["crudsql_url"] = "config"
    else:
        _swain, derived = resolve_base_urls(swain_base, None)
        crudsql_url = derived
        sources["crudsql_url"] = "derived"

    engine_env = (os.environ.get(ENGINE_ENV_VAR) or "").strip()
    engine = engine_env or (config.engine or "embedded")
    sources["engine"] = "env" if engine_env else ("config" if config.engine else "default")

    gen_env = (os.environ.get(GENERATOR_VERSION_ENV_VAR) or "").strip()
    generator_version = gen_env or (config.generator_version or PINNED_GENERATOR_VERSION)
    sources["generator_version"] = (
        "env" if gen_env else ("config" if config.generator_version else "default")
    )

    java_env = (os.environ.get(JAVA_OPTS_ENV_VAR) or "").strip()
    if java_env:
        java_opts = shlex.split(java_env)
        sources["java_opts"] = "env"
    elif config.java_opts:
        java_opts = list(config.java_opts)
        sources["java_opts"] = "config"
    else:
        java_opts = list(DEFAULT_JAVA_OPTS)
        sources["java_opts"] = "default"

    values: Dict[str, Any] = {
        "swain_base_url": swain_base,
        "crudsql_url": crudsql_url,
        "tenant_id": None,
        "engine": engine,
        "generator_version": generator_version,
        "java_opts": java_opts,
        "languages": list(config.languages),
        "patch_base_url": config.patch_base_url if config.patch_base_url is not None else True,
        "parallel": int(config.parallel) if config.parallel is not None else 1,
    }
    tenant_env = (os.environ.get(TENANT_ID_ENV_VAR) or "").strip()
    if tenant_env:
        values["tenant_id"] = tenant_env
        sources["tenant_id"] = "env"
    else:
        values["tenant_id"] = config.tenant_id
        sources["tenant_id"] = "config" if config.tenant_id else "default"
    sources["languages"] = "config" if config.languages else "default"
    sources["patch_base_url"] = "config" if config.patch_base_url is not None else "default"
    sources["parallel"] = "config" if config.parallel is not None else "default"
    return values, sources


def _toml_escape_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _toml_format_key(key: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_-]+", key):
        return key
    return _toml_escape_string(key)


def _toml_format_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, str):
        return _toml_escape_string(value)
    if isinstance(value, list):
        parts = [_toml_format_value(item) for item in value]
        return "[" + ", ".join(parts) + "]"
    raise CLIError(f"unsupported TOML value type: {type(value).__name__}")


def _toml_write_table(
    lines: List[str],
    *,
    path: List[str],
    table: Dict[str, Any],
) -> None:
    scalars: List[Tuple[str, Any]] = []
    subtables: List[Tuple[str, Dict[str, Any]]] = []
    for key, value in table.items():
        if value is None:
            continue
        if isinstance(value, dict):
            subtables.append((str(key), value))
        else:
            scalars.append((str(key), value))
    if path:
        header = ".".join(_toml_format_key(part) for part in path)
        lines.append(f"[{header}]")
    for key, value in scalars:
        lines.append(f"{_toml_format_key(key)} = {_toml_format_value(value)}")
    for subkey, subtable in subtables:
        if lines and lines[-1] != "":
            lines.append("")
        _toml_write_table(lines, path=path + [subkey], table=subtable)


def dump_config_toml(data: Dict[str, Any]) -> str:
    lines: List[str] = []
    top_scalars: Dict[str, Any] = {}
    top_tables: Dict[str, Dict[str, Any]] = {}
    for key, value in data.items():
        if value is None:
            continue
        if isinstance(value, dict):
            top_tables[str(key)] = value
        else:
            top_scalars[str(key)] = value

    for key, value in top_scalars.items():
        lines.append(f"{_toml_format_key(key)} = {_toml_format_value(value)}")
    for key, table in top_tables.items():
        if lines:
            lines.append("")
        _toml_write_table(lines, path=[key], table=table)
    return "\n".join(lines).rstrip() + "\n"


def load_raw_config(path: Optional[Path] = None) -> Dict[str, Any]:
    config_path = path or resolve_config_path()
    if not config_path.exists():
        return {}
    try:
        data = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CLIError(f"failed to read config file {config_path}: {exc}") from exc
    except Exception as exc:
        raise CLIError(f"failed to parse config file {config_path}: {exc}") from exc
    if not isinstance(data, dict):
        return {}
    return dict(data)


def profile_to_dict(profile: ProfileConfig) -> Dict[str, Any]:
    payload: Dict[str, Any] = {}
    if profile.languages:
        payload["languages"] = list(profile.languages)
    if profile.engine:
        payload["engine"] = profile.engine
    if profile.generator_version:
        payload["generator_version"] = profile.generator_version
    if profile.java_opts:
        payload["java_opts"] = list(profile.java_opts)
    if profile.config:
        payload["config"] = profile.config
    if profile.templates:
        payload["templates"] = profile.templates
    if profile.additional_properties:
        payload["additional_properties"] = list(profile.additional_properties)
    if profile.generator_arg:
        payload["generator_arg"] = list(profile.generator_arg)
    if profile.system_properties:
        payload["system_properties"] = list(profile.system_properties)
    if profile.patch_base_url is not None:
        payload["patch_base_url"] = bool(profile.patch_base_url)
    if profile.emit_patched_schema:
        payload["emit_patched_schema"] = profile.emit_patched_schema
    if profile.parallel is not None:
        payload["parallel"] = int(profile.parallel)
    if profile.schema_cache_ttl:
        payload["schema_cache_ttl"] = profile.schema_cache_ttl
    if profile.no_schema_cache is not None:
        payload["no_schema_cache"] = bool(profile.no_schema_cache)
    if profile.post_hooks:
        payload["post_hooks"] = list(profile.post_hooks)
    if profile.post_hooks_by_language:
        payload["hooks"] = {k: list(v) for k, v in profile.post_hooks_by_language.items() if v}
    if profile.run_hooks is not None:
        payload["run_hooks"] = bool(profile.run_hooks)
    return payload


def upsert_profile(
    name: str,
    profile: ProfileConfig,
    *,
    overwrite: bool,
    path: Optional[Path] = None,
) -> Path:
    config_path = path or resolve_config_path()
    raw = load_raw_config(config_path)
    profiles_table = raw.get("profiles")
    if profiles_table is None:
        profiles_table = {}
        raw["profiles"] = profiles_table
    if not isinstance(profiles_table, dict):
        raise CLIError(f"config file has non-table profiles key: {config_path}")
    normalized_name = name.strip()
    if not normalized_name:
        raise CLIError("profile name cannot be empty")
    if normalized_name in profiles_table and not overwrite:
        raise CLIError(f"profile already exists: {normalized_name} (use overwrite)")
    profiles_table[normalized_name] = profile_to_dict(profile)

    rendered = dump_config_toml(raw)
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(rendered, encoding="utf-8")
    except OSError as exc:
        raise CLIError(f"failed to write config file {config_path}: {exc}") from exc
    return config_path
