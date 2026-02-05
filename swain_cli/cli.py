#!/usr/bin/env python3
"""swain_cli CLI entry point."""

from __future__ import annotations

import json
import os
import platform
import sys
from contextlib import nullcontext
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from typing import Callable, List, Optional, Sequence, TypeVar

import click
import typer

from .args import GenArgs
from .auth import (
    determine_swain_tenant_id,
    handle_auth_login,
    handle_auth_logout,
    handle_auth_refresh,
    handle_auth_status,
    interactive_auth_setup,
    require_auth_token,
)
from .config import (
    ConfigFile,
    effective_config,
    load_config,
    resolve_config_path,
    write_default_config,
)
from .console import configure_console, log, log_error, logs_to_stderr, suppress_logs
from .constants import (
    DEFAULT_CRUDSQL_API_BASE_URL,
    DEFAULT_SWAIN_BASE_URL,
    ENGINE_ENV_VAR,
    EXIT_CODE_INTERRUPT,
    EXIT_CODE_USAGE,
    GENERATOR_VERSION_ENV_VAR,
    JAVA_OPTS_ENV_VAR,
    TENANT_ID_ENV_VAR,
)
from .context import AppContext
from .engine import (
    cache_root,
    collect_engine_snapshot,
    downloads_dir,
    emit_engine_snapshot,
    handle_engine_clean,
    handle_engine_install_jre,
    handle_engine_paths,
    handle_engine_prune_jars,
    handle_engine_status,
    handle_engine_update_jar,
    handle_engine_use_embedded,
    handle_engine_use_system,
    handle_list_generators,
    jar_cache_dir,
    jre_install_dir,
)
from .errors import CLIError
from .generator import handle_gen
from .interactive import (
    InteractiveDeps,
    coerce_interactive_args,
)
from .interactive import (
    run_interactive as run_interactive_wizard,
)
from .plugins import plugin_statuses
from .prompts import prompt_confirm, prompt_multi_select, prompt_select, prompt_text
from .swain_api import (
    fetch_swain_connection_by_id,
    fetch_swain_connection_schema,
    fetch_swain_connections_with_fallback,
    fetch_swain_projects_with_fallback,
)
from .updater import handle_self_update
from .urls import (
    crudsql_dynamic_swagger_url,
    resolve_base_urls,
)
from .version import cli_version

app = typer.Typer(help="swain_cli CLI")
auth_app = typer.Typer(help="Authentication helpers")
config_app = typer.Typer(help="Configuration helpers")
engine_app = typer.Typer(help="Embedded engine management")
profiles_app = typer.Typer(help="Generation profiles")
plugins_app = typer.Typer(help="Plugin helpers")
app.add_typer(auth_app, name="auth")
app.add_typer(config_app, name="config")
app.add_typer(engine_app, name="engine")
app.add_typer(profiles_app, name="profiles")
app.add_typer(plugins_app, name="plugins")


@dataclass
class CLIContext:
    generator_version: Optional[str] = None
    generator_version_source: str = "default"
    config: ConfigFile = field(default_factory=ConfigFile)
    config_path: Optional[Path] = None
    app_ctx: AppContext = field(default_factory=AppContext)


ArgsT = TypeVar("ArgsT")


def _run_handler(handler: Callable[[ArgsT], int], args: ArgsT) -> None:
    try:
        rc = handler(args)
    except CLIError as exc:
        log_error(f"error: {exc}")
        raise typer.Exit(code=EXIT_CODE_USAGE) from exc
    raise typer.Exit(code=rc)


def _param_is_default(ctx: typer.Context, name: str) -> bool:
    try:
        return ctx.get_parameter_source(name) == click.core.ParameterSource.DEFAULT
    except Exception:
        return True


def handle_doctor(args: SimpleNamespace) -> int:
    system = platform.platform()
    python_version = sys.version.replace("\n", " ")
    snapshot = collect_engine_snapshot(args.generator_version)
    output_format = getattr(args, "format", DoctorFormat.text)
    if isinstance(output_format, DoctorFormat):
        output_format_value = output_format.value
    else:
        output_format_value = str(output_format)
    pretty = bool(getattr(args, "pretty", False))

    if output_format_value == DoctorFormat.json.value:
        swain_base, crudsql_base = resolve_base_urls(
            getattr(args, "swain_base_url", None),
            getattr(args, "crudsql_url", None),
        )
        payload = {
            "cli_version": cli_version(),
            "python": python_version,
            "platform": system,
            "detected_platform": {
                "os": snapshot.platform.os_name,
                "arch": snapshot.platform.arch,
            },
            "base_urls": {
                "swain_base_url": swain_base,
                "crudsql_url": crudsql_base,
            },
            "paths": {
                "config_path": str(getattr(args, "config_path", "") or ""),
                "cache_root": str(cache_root(create=False)),
                "downloads_dir": str(downloads_dir(create=False)),
                "jar_cache_dir": str(jar_cache_dir(create=False)),
                "jre_install_dir": str(jre_install_dir(create=False)),
            },
            "engine": {
                "embedded_java": str(snapshot.embedded_java) if snapshot.embedded_java else None,
                "system_java": snapshot.system_java,
                "selected_generator": str(snapshot.selected_generator) if snapshot.selected_generator else None,
                "selected_generator_error": snapshot.selected_generator_error,
                "cached_jars": snapshot.cached_jars,
            },
        }
        typer.echo(_format_json(payload, pretty=pretty))
        return 0

    log("doctor report")
    log(f"python: {python_version}")
    log(f"platform: {system}")
    log(f"detected os/arch: {snapshot.platform.os_name}/{snapshot.platform.arch}")
    emit_engine_snapshot(
        snapshot,
        include_selected_generator=True,
        include_cached_jars=False,
    )
    return 0


def run_interactive(args: SimpleNamespace) -> int:
    app_ctx = getattr(args, "app_ctx", None)

    def handle_gen_with_ctx(gen_args: GenArgs) -> int:
        if isinstance(app_ctx, AppContext):
            return handle_gen(gen_args, ctx=app_ctx)
        return handle_gen(gen_args)

    deps = InteractiveDeps(
        prompt_confirm=prompt_confirm,
        prompt_select=prompt_select,
        prompt_multi_select=prompt_multi_select,
        prompt_text=prompt_text,
        interactive_auth_setup=interactive_auth_setup,
        require_auth_token=require_auth_token,
        determine_swain_tenant_id=determine_swain_tenant_id,
        crudsql_dynamic_swagger_url=crudsql_dynamic_swagger_url,
        handle_gen=handle_gen_with_ctx,
    )
    return run_interactive_wizard(coerce_interactive_args(args), deps)


def handle_interactive(args: SimpleNamespace) -> int:
    return run_interactive(args)


class DiscoveryFormat(str, Enum):
    json = "json"
    text = "text"
    tsv = "tsv"


class PlanFormat(str, Enum):
    json = "json"
    text = "text"


class DoctorFormat(str, Enum):
    json = "json"
    text = "text"


def _format_json(payload: object, *, pretty: bool) -> str:
    if pretty:
        return json.dumps(payload, indent=2, sort_keys=True)
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def handle_projects(args: SimpleNamespace) -> int:
    verbose = bool(getattr(args, "verbose", False))
    silencer = nullcontext() if verbose else suppress_logs()
    app_ctx = getattr(args, "app_ctx", None)
    http_ctx = app_ctx if isinstance(app_ctx, AppContext) else None

    with logs_to_stderr(), silencer:
        swain_base, crudsql_base = resolve_base_urls(
            getattr(args, "swain_base_url", None),
            getattr(args, "crudsql_url", None),
        )
        token = require_auth_token("discover Swain projects")
        tenant_id = determine_swain_tenant_id(
            swain_base,
            token,
            getattr(args, "swain_tenant_id", None),
            allow_prompt=False,
        )
        projects = fetch_swain_projects_with_fallback(
            swain_base,
            crudsql_base if crudsql_base != swain_base else None,
            token,
            tenant_id=tenant_id,
            ctx=http_ctx,
        )

    output_format = getattr(args, "format", DiscoveryFormat.json)
    pretty = bool(getattr(args, "pretty", False))
    rows = [
        {
            "id": project.id,
            "name": project.name,
            "description": project.description,
        }
        for project in projects
    ]
    if output_format == DiscoveryFormat.json:
        typer.echo(_format_json(rows, pretty=pretty))
    elif output_format == DiscoveryFormat.tsv:
        for row in rows:
            typer.echo(
                f"{row['id']}\t{row['name']}\t{row.get('description') or ''}".rstrip()
            )
    else:
        for row in rows:
            desc = row.get("description") or ""
            suffix = f" — {desc}" if desc else ""
            typer.echo(f"{row['id']}: {row['name']}{suffix}")
    return 0


def handle_connections(args: SimpleNamespace) -> int:
    project_id = getattr(args, "project_id", None)
    connection_id = getattr(args, "connection_id", None)
    if project_id is None and connection_id is None:
        raise CLIError("--project-id or --connection-id is required")

    verbose = bool(getattr(args, "verbose", False))
    silencer = nullcontext() if verbose else suppress_logs()
    app_ctx = getattr(args, "app_ctx", None)
    http_ctx = app_ctx if isinstance(app_ctx, AppContext) else None

    with logs_to_stderr(), silencer:
        swain_base, crudsql_base = resolve_base_urls(
            getattr(args, "swain_base_url", None),
            getattr(args, "crudsql_url", None),
        )
        token = require_auth_token("discover Swain connections")
        tenant_id = determine_swain_tenant_id(
            swain_base,
            token,
            getattr(args, "swain_tenant_id", None),
            allow_prompt=False,
        )
        connections = fetch_swain_connections_with_fallback(
            swain_base,
            crudsql_base if crudsql_base != swain_base else None,
            token,
            tenant_id=tenant_id,
            project_id=project_id,
            connection_id=connection_id,
            ctx=http_ctx,
        )

    output_format = getattr(args, "format", DiscoveryFormat.json)
    pretty = bool(getattr(args, "pretty", False))
    rows = [
        {
            "id": conn.id,
            "database_name": conn.database_name,
            "driver": conn.driver,
            "stage": conn.stage,
            "project_name": conn.project_name,
            "schema_name": conn.schema_name,
            "build_id": conn.build_id,
            "endpoint": conn.effective_endpoint,
        }
        for conn in connections
    ]
    if output_format == DiscoveryFormat.json:
        typer.echo(_format_json(rows, pretty=pretty))
    elif output_format == DiscoveryFormat.tsv:
        for row in rows:
            typer.echo(
                "\t".join(
                    [
                        str(row["id"]),
                        str(row.get("database_name") or ""),
                        str(row.get("driver") or ""),
                        str(row.get("stage") or ""),
                        str(row.get("schema_name") or ""),
                        str(row.get("endpoint") or ""),
                    ]
                ).rstrip()
            )
    else:
        for row in rows:
            typer.echo(
                f"{row['id']}: {row.get('database_name') or 'connection'}"
                f" (driver={row.get('driver') or 'n/a'},"
                f" stage={row.get('stage') or 'n/a'},"
                f" schema={row.get('schema_name') or 'n/a'})"
            )
    return 0


def handle_schema(args: SimpleNamespace) -> int:
    connection_id = getattr(args, "connection_id", None)
    if connection_id is None:
        raise CLIError("--connection-id is required")

    output_path = getattr(args, "out", None)

    verbose = bool(getattr(args, "verbose", False))
    silencer = nullcontext() if verbose else suppress_logs()
    app_ctx = getattr(args, "app_ctx", None)
    http_ctx = app_ctx if isinstance(app_ctx, AppContext) else None

    with logs_to_stderr(), silencer:
        swain_base, crudsql_base = resolve_base_urls(
            getattr(args, "swain_base_url", None),
            getattr(args, "crudsql_url", None),
        )
        token = require_auth_token("fetch a Swain connection swagger document")
        tenant_id = determine_swain_tenant_id(
            swain_base,
            token,
            getattr(args, "swain_tenant_id", None),
            allow_prompt=False,
        )
        try:
            connection = fetch_swain_connection_by_id(
                swain_base,
                token,
                connection_id,
                tenant_id=tenant_id,
                ctx=http_ctx,
            )
        except CLIError:
            if crudsql_base == swain_base:
                raise
            connection = fetch_swain_connection_by_id(
                crudsql_base,
                token,
                connection_id,
                tenant_id=tenant_id,
                ctx=http_ctx,
            )
        temp_schema = fetch_swain_connection_schema(
            swain_base,
            connection,
            token,
            tenant_id=tenant_id,
            ctx=http_ctx,
        )

    try:
        data = temp_schema.read_bytes()
        if output_path:
            target = Path(str(output_path)).expanduser()
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        else:
            typer.echo(data.decode("utf-8"), nl=False)
    finally:
        temp_schema.unlink(missing_ok=True)
    return 0


@app.callback(invoke_without_command=True)
def cli_callback(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="print swain_cli version and exit",
        is_eager=True,
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="suppress non-essential logs",
    ),
    generator_version: Optional[str] = typer.Option(
        None,
        "--generator-version",
        help="override the OpenAPI Generator version to use (must be cached)",
    ),
) -> None:
    if version:
        typer.echo(f"swain_cli {cli_version()}")
        raise typer.Exit(code=0)
    if quiet:
        configure_console(quiet=True)
    config_path = resolve_config_path()
    try:
        config = load_config(config_path)
    except CLIError as exc:
        log_error(f"failed to load config: {exc}")
        raise typer.Exit(code=EXIT_CODE_USAGE) from exc

    generator_version_source = "default"
    if generator_version is not None:
        generator_version_source = "flag"
    elif (os.environ.get(GENERATOR_VERSION_ENV_VAR) or "").strip():
        generator_version_source = "env"
    elif config.generator_version:
        generator_version = config.generator_version
        generator_version_source = "config"

    ctx.obj = CLIContext(
        generator_version=generator_version,
        generator_version_source=generator_version_source,
        config=config,
        config_path=config_path,
        app_ctx=AppContext(config=config, config_path=config_path),
    )
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit(code=EXIT_CODE_USAGE)


@app.command()
def doctor(
    ctx: typer.Context,
    format: DoctorFormat = typer.Option(
        DoctorFormat.text,
        "--format",
        "-f",
        help="doctor output format",
        show_choices=True,
        case_sensitive=False,
    ),
    pretty: bool = typer.Option(False, "--pretty", help="pretty-print JSON output"),
) -> None:
    args = SimpleNamespace(
        generator_version=ctx.obj.generator_version,
        format=format,
        pretty=pretty,
        swain_base_url=ctx.obj.config.swain_base_url,
        crudsql_url=ctx.obj.config.crudsql_url,
        config_path=str(ctx.obj.config_path) if ctx.obj.config_path else None,
    )
    with logs_to_stderr():
        _run_handler(handle_doctor, args)


@config_app.command("path")
def config_path_cmd(ctx: typer.Context) -> None:
    _ = ctx
    typer.echo(str(resolve_config_path()))


@config_app.command("init")
def config_init(
    force: bool = typer.Option(False, "--force", help="overwrite existing config"),
) -> None:
    try:
        path = write_default_config(force=force)
    except CLIError as exc:
        log_error(f"error: {exc}")
        raise typer.Exit(code=EXIT_CODE_USAGE) from exc
    typer.echo(f"wrote {path}")


@config_app.command("show")
def config_show(
    ctx: typer.Context,
    json: bool = typer.Option(False, "--json", help="emit effective config as JSON"),
    pretty: bool = typer.Option(False, "--pretty", help="pretty-print JSON output"),
) -> None:
    values, sources = effective_config(ctx.obj.config)
    if json:
        payload = {
            "path": str(ctx.obj.config_path) if ctx.obj.config_path else None,
            "values": values,
            "sources": sources,
        }
        typer.echo(_format_json(payload, pretty=pretty))
        return

    typer.echo(f"config path: {ctx.obj.config_path}")
    for key in sorted(values.keys()):
        value = values[key]
        source = sources.get(key, "unknown")
        typer.echo(f"{key} ({source}): {value}")


@profiles_app.command("list")
def profiles_list(
    ctx: typer.Context,
    json: bool = typer.Option(False, "--json", help="emit profiles as JSON"),
    pretty: bool = typer.Option(False, "--pretty", help="pretty-print JSON output"),
) -> None:
    profiles = ctx.obj.config.profiles if getattr(ctx.obj, "config", None) else {}
    names = sorted(profiles.keys())
    if json:
        payload = {
            "path": str(ctx.obj.config_path) if ctx.obj.config_path else None,
            "profiles": [
                {
                    "name": name,
                    "languages": list(profiles[name].languages),
                }
                for name in names
            ],
        }
        typer.echo(_format_json(payload, pretty=pretty))
        return
    for name in names:
        langs = ", ".join(profiles[name].languages) if profiles[name].languages else ""
        suffix = f" ({langs})" if langs else ""
        typer.echo(f"{name}{suffix}")


@profiles_app.command("show")
def profiles_show(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="profile name"),
    json: bool = typer.Option(False, "--json", help="emit profile as JSON"),
    pretty: bool = typer.Option(False, "--pretty", help="pretty-print JSON output"),
) -> None:
    profiles = ctx.obj.config.profiles if getattr(ctx.obj, "config", None) else {}
    profile = profiles.get(name)
    if profile is None:
        available = ", ".join(sorted(profiles.keys()))
        message = f"unknown profile: {name}"
        if available:
            message = f"{message} (available: {available})"
        log_error(f"error: {message}")
        raise typer.Exit(code=EXIT_CODE_USAGE)
    if json:
        payload = {
            "path": str(ctx.obj.config_path) if ctx.obj.config_path else None,
            "name": name,
            "profile": {
                "languages": list(profile.languages),
                "engine": profile.engine,
                "generator_version": profile.generator_version,
                "java_opts": list(profile.java_opts),
                "config": profile.config,
                "templates": profile.templates,
                "additional_properties": list(profile.additional_properties),
                "generator_arg": list(profile.generator_arg),
                "system_properties": list(profile.system_properties),
                "patch_base_url": profile.patch_base_url,
                "emit_patched_schema": profile.emit_patched_schema,
                "parallel": profile.parallel,
                "schema_cache_ttl": profile.schema_cache_ttl,
                "no_schema_cache": profile.no_schema_cache,
                "post_hooks": list(profile.post_hooks),
                "post_hooks_by_language": profile.post_hooks_by_language,
                "run_hooks": profile.run_hooks,
            },
        }
        typer.echo(_format_json(payload, pretty=pretty))
        return
    typer.echo(f"profile: {name}")
    typer.echo(f"languages: {', '.join(profile.languages) if profile.languages else ''}")
    if profile.generator_version:
        typer.echo(f"generator_version: {profile.generator_version}")
    if profile.engine:
        typer.echo(f"engine: {profile.engine}")
    if profile.parallel is not None:
        typer.echo(f"parallel: {profile.parallel}")


@plugins_app.command("list")
def plugins_list(
    json: bool = typer.Option(False, "--json", help="emit plugin info as JSON"),
    pretty: bool = typer.Option(False, "--pretty", help="pretty-print JSON output"),
) -> None:
    statuses = plugin_statuses()
    rows = []
    for info, error in statuses:
        rows.append(
            {
                "name": info.name,
                "value": info.value,
                "loaded": error is None,
                "error": error,
            }
        )
    if json:
        typer.echo(_format_json({"plugins": rows}, pretty=pretty))
        return
    if not rows:
        typer.echo("no plugins installed")
        return
    for row in rows:
        if row["loaded"]:
            typer.echo(f"{row['name']}: {row['value']}")
        else:
            typer.echo(f"{row['name']}: {row['value']} (failed: {row['error']})")


@app.command()
def projects(
    ctx: typer.Context,
    swain_base_url: Optional[str] = typer.Option(
        None,
        "--swain-base-url",
        help=f"Swain platform base URL (default: {DEFAULT_SWAIN_BASE_URL})",
    ),
    crudsql_url: Optional[str] = typer.Option(
        None,
        "--crudsql-url",
        help=f"CrudSQL base URL override (default: derived from Swain base, e.g. {DEFAULT_CRUDSQL_API_BASE_URL})",
    ),
    swain_tenant_id: Optional[str] = typer.Option(
        None,
        "--tenant-id",
        "--swain-tenant-id",
        help=f"Tenant ID for Swain API requests (or set {TENANT_ID_ENV_VAR})",
    ),
    format: DiscoveryFormat = typer.Option(
        DiscoveryFormat.json,
        "--format",
        "-f",
        help="output format",
        show_choices=True,
        case_sensitive=False,
    ),
    pretty: bool = typer.Option(False, "--pretty", help="pretty-print JSON output"),
    verbose: bool = typer.Option(False, "--verbose", help="enable diagnostic logging (stderr)"),
) -> None:
    cfg = ctx.obj.config
    merged_swain_base_url = swain_base_url or cfg.swain_base_url
    merged_crudsql_url = crudsql_url or cfg.crudsql_url
    merged_tenant_id = swain_tenant_id
    if (
        merged_tenant_id is None
        and not (os.environ.get(TENANT_ID_ENV_VAR) or "").strip()
        and cfg.tenant_id
    ):
        merged_tenant_id = cfg.tenant_id
    args = SimpleNamespace(
        swain_base_url=merged_swain_base_url,
        crudsql_url=merged_crudsql_url,
        swain_tenant_id=merged_tenant_id,
        format=format,
        pretty=pretty,
        verbose=verbose,
        app_ctx=ctx.obj.app_ctx,
    )
    _run_handler(handle_projects, args)


@app.command()
def connections(
    ctx: typer.Context,
    swain_base_url: Optional[str] = typer.Option(
        None,
        "--swain-base-url",
        help=f"Swain platform base URL (default: {DEFAULT_SWAIN_BASE_URL})",
    ),
    crudsql_url: Optional[str] = typer.Option(
        None,
        "--crudsql-url",
        help=f"CrudSQL base URL override (default: derived from Swain base, e.g. {DEFAULT_CRUDSQL_API_BASE_URL})",
    ),
    swain_tenant_id: Optional[str] = typer.Option(
        None,
        "--tenant-id",
        "--swain-tenant-id",
        help=f"Tenant ID for Swain API requests (or set {TENANT_ID_ENV_VAR})",
    ),
    project_id: Optional[int] = typer.Option(
        None,
        "--project-id",
        "--swain-project-id",
        help="filter connections by project ID",
    ),
    connection_id: Optional[int] = typer.Option(
        None,
        "--connection-id",
        "--swain-connection-id",
        help="filter connections by connection ID",
    ),
    format: DiscoveryFormat = typer.Option(
        DiscoveryFormat.json,
        "--format",
        "-f",
        help="output format",
        show_choices=True,
        case_sensitive=False,
    ),
    pretty: bool = typer.Option(False, "--pretty", help="pretty-print JSON output"),
    verbose: bool = typer.Option(False, "--verbose", help="enable diagnostic logging (stderr)"),
) -> None:
    cfg = ctx.obj.config
    merged_swain_base_url = swain_base_url or cfg.swain_base_url
    merged_crudsql_url = crudsql_url or cfg.crudsql_url
    merged_tenant_id = swain_tenant_id
    if (
        merged_tenant_id is None
        and not (os.environ.get(TENANT_ID_ENV_VAR) or "").strip()
        and cfg.tenant_id
    ):
        merged_tenant_id = cfg.tenant_id
    args = SimpleNamespace(
        swain_base_url=merged_swain_base_url,
        crudsql_url=merged_crudsql_url,
        swain_tenant_id=merged_tenant_id,
        project_id=project_id,
        connection_id=connection_id,
        format=format,
        pretty=pretty,
        verbose=verbose,
        app_ctx=ctx.obj.app_ctx,
    )
    _run_handler(handle_connections, args)


@app.command()
def schema(
    ctx: typer.Context,
    swain_base_url: Optional[str] = typer.Option(
        None,
        "--swain-base-url",
        help=f"Swain platform base URL (default: {DEFAULT_SWAIN_BASE_URL})",
    ),
    crudsql_url: Optional[str] = typer.Option(
        None,
        "--crudsql-url",
        help=f"CrudSQL base URL override (default: derived from Swain base, e.g. {DEFAULT_CRUDSQL_API_BASE_URL})",
    ),
    swain_tenant_id: Optional[str] = typer.Option(
        None,
        "--tenant-id",
        "--swain-tenant-id",
        help=f"Tenant ID for Swain API requests (or set {TENANT_ID_ENV_VAR})",
    ),
    connection_id: int = typer.Option(
        ...,
        "--connection-id",
        "--swain-connection-id",
        help="Swain connection ID to fetch schema for",
    ),
    out: Optional[str] = typer.Option(
        None,
        "--out",
        "-o",
        help="write schema to this path (default: stdout)",
    ),
    verbose: bool = typer.Option(False, "--verbose", help="enable diagnostic logging (stderr)"),
) -> None:
    cfg = ctx.obj.config
    merged_swain_base_url = swain_base_url or cfg.swain_base_url
    merged_crudsql_url = crudsql_url or cfg.crudsql_url
    merged_tenant_id = swain_tenant_id
    if (
        merged_tenant_id is None
        and not (os.environ.get(TENANT_ID_ENV_VAR) or "").strip()
        and cfg.tenant_id
    ):
        merged_tenant_id = cfg.tenant_id
    args = SimpleNamespace(
        swain_base_url=merged_swain_base_url,
        crudsql_url=merged_crudsql_url,
        swain_tenant_id=merged_tenant_id,
        connection_id=connection_id,
        out=out,
        verbose=verbose,
        app_ctx=ctx.obj.app_ctx,
    )
    _run_handler(handle_schema, args)


@app.command("list-generators")
def list_generators(
    ctx: typer.Context,
    engine: str = typer.Option(
        "embedded",
        "--engine",
        envvar=ENGINE_ENV_VAR,
        case_sensitive=False,
        help=f"select Java runtime (default: embedded, or set {ENGINE_ENV_VAR})",
        show_choices=True,
    ),
) -> None:
    cfg = ctx.obj.config
    merged_engine = engine.lower()
    if (
        merged_engine == "embedded"
        and not (os.environ.get(ENGINE_ENV_VAR) or "").strip()
        and cfg.engine
    ):
        merged_engine = cfg.engine.lower()

    merged_java_opts: List[str] = []
    if not (os.environ.get(JAVA_OPTS_ENV_VAR) or "").strip() and cfg.java_opts:
        merged_java_opts = list(cfg.java_opts)
    args = SimpleNamespace(
        generator_version=ctx.obj.generator_version,
        engine=merged_engine,
        java_opts=merged_java_opts,
    )
    _run_handler(handle_list_generators, args)


@app.command("self-update")
def self_update(
    version: str = typer.Option(
        "latest",
        "--version",
        help="release tag or version to install (default: latest)",
    ),
    no_verify: bool = typer.Option(
        False,
        "--no-verify",
        help="skip checksum verification for the downloaded binary",
    ),
    verify_signatures: bool = typer.Option(
        False,
        "--verify-signatures",
        help="verify the downloaded binary against a GPG signature (requires gpg)",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="download and verify without replacing the executable",
    ),
) -> None:
    args = SimpleNamespace(
        version=version,
        no_verify=no_verify,
        verify_signatures=verify_signatures,
        dry_run=dry_run,
    )
    with logs_to_stderr():
        _run_handler(handle_self_update, args)


@app.command()
def gen(
    ctx: typer.Context,
    schema: Optional[str] = typer.Option(None, "--schema", "-i", help="schema path or URL"),
    crudsql_url: Optional[str] = typer.Option(
        None,
        "--crudsql-url",
        help=f"CrudSQL base URL to pull dynamic swagger (default: {DEFAULT_CRUDSQL_API_BASE_URL})",
    ),
    swain_base_url: Optional[str] = typer.Option(
        None,
        "--swain-base-url",
        help=f"Swain platform base URL (default: {DEFAULT_SWAIN_BASE_URL})",
    ),
    lang: List[str] = typer.Option(
        [],
        "--lang",
        "-l",
        help="target generator (repeat for multiple languages)",
    ),
    profile: Optional[str] = typer.Option(
        None,
        "--profile",
        help="named generation profile from the config file",
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
    post_hook: List[str] = typer.Option(
        [],
        "--post-hook",
        help="command to run in each generated SDK directory (repeatable; only runs with --run-hooks)",
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
    schema_cache_ttl: Optional[str] = typer.Option(
        None,
        "--schema-cache-ttl",
        help="cache fetched schemas for this TTL (e.g. 10m, 2h); default is off",
    ),
    no_schema_cache: bool = typer.Option(
        False,
        "--no-schema-cache",
        help="disable schema caching even if a TTL is configured",
    ),
    patch_base_url: bool = typer.Option(
        True,
        "--patch-base-url/--no-patch-base-url",
        help="patch fetched schemas so generated SDKs do not default to localhost",
    ),
    emit_patched_schema: Optional[str] = typer.Option(
        None,
        "--emit-patched-schema",
        help="write the patched schema to this path (only for fetched schemas)",
    ),
    parallel: int = typer.Option(
        1,
        "--parallel",
        help="number of languages to generate in parallel (experimental)",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="print the resolved generation plan without running OpenAPI Generator",
    ),
    plan_only: bool = typer.Option(
        False,
        "--plan-only",
        help="print the plan without fetching schemas or downloading assets",
    ),
    plan_format: PlanFormat = typer.Option(
        PlanFormat.text,
        "--plan-format",
        help="plan output format (used with --dry-run/--plan-only)",
        show_choices=True,
        case_sensitive=False,
    ),
    pretty: bool = typer.Option(
        False,
        "--pretty",
        help="pretty-print JSON plan output",
    ),
    run_hooks: bool = typer.Option(
        False,
        "--run-hooks/--no-run-hooks",
        help="execute configured post-generation hooks (dangerous; opt-in)",
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
        envvar=ENGINE_ENV_VAR,
        case_sensitive=False,
        help=f"select Java runtime (default: embedded, or set {ENGINE_ENV_VAR})",
        show_choices=True,
    ),
) -> None:
    cfg = ctx.obj.config
    selected_profile = None
    if profile:
        selected_profile = cfg.profiles.get(profile)
        if selected_profile is None:
            available = ", ".join(sorted(cfg.profiles.keys()))
            message = f"unknown profile: {profile}"
            if available:
                message = f"{message} (available: {available})"
            log_error(f"error: {message}")
            raise typer.Exit(code=EXIT_CODE_USAGE)

    merged_generator_version = ctx.obj.generator_version
    if (
        selected_profile is not None
        and selected_profile.generator_version
        and ctx.obj.generator_version_source not in {"flag", "env"}
    ):
        merged_generator_version = selected_profile.generator_version

    merged_engine = engine.lower()
    if _param_is_default(ctx, "engine"):
        if selected_profile is not None and selected_profile.engine:
            merged_engine = selected_profile.engine.lower()
        elif cfg.engine:
            merged_engine = cfg.engine.lower()

    merged_swain_base_url = swain_base_url or cfg.swain_base_url
    merged_crudsql_url = crudsql_url or cfg.crudsql_url

    merged_lang = [entry.lower() for entry in lang]
    if not merged_lang:
        if selected_profile is not None and selected_profile.languages:
            merged_lang = [entry.lower() for entry in selected_profile.languages]
        elif cfg.languages:
            merged_lang = [entry.lower() for entry in cfg.languages]

    merged_java_opts = list(java_opt)
    if (
        not merged_java_opts
        and not (os.environ.get(JAVA_OPTS_ENV_VAR) or "").strip()
        and (selected_profile is not None or cfg.java_opts)
    ):
        if selected_profile is not None and selected_profile.java_opts:
            merged_java_opts = list(selected_profile.java_opts)
        elif cfg.java_opts:
            merged_java_opts = list(cfg.java_opts)

    merged_tenant_id = swain_tenant_id
    if (
        merged_tenant_id is None
        and not (os.environ.get(TENANT_ID_ENV_VAR) or "").strip()
        and cfg.tenant_id
    ):
        merged_tenant_id = cfg.tenant_id

    merged_patch_base_url = patch_base_url
    if _param_is_default(ctx, "patch_base_url"):
        if selected_profile is not None and selected_profile.patch_base_url is not None:
            merged_patch_base_url = bool(selected_profile.patch_base_url)
        elif cfg.patch_base_url is False:
            merged_patch_base_url = False

    merged_parallel = parallel
    if _param_is_default(ctx, "parallel"):
        if selected_profile is not None and selected_profile.parallel is not None:
            merged_parallel = int(selected_profile.parallel)
        elif cfg.parallel is not None:
            merged_parallel = int(cfg.parallel)

    merged_generator_config = config
    if (
        merged_generator_config is None
        and selected_profile is not None
        and selected_profile.config
        and _param_is_default(ctx, "config")
    ):
        merged_generator_config = selected_profile.config

    merged_templates = templates
    if (
        merged_templates is None
        and selected_profile is not None
        and selected_profile.templates
        and _param_is_default(ctx, "templates")
    ):
        merged_templates = selected_profile.templates

    merged_additional_properties = list(additional_properties)
    if selected_profile is not None and selected_profile.additional_properties:
        merged_additional_properties = list(selected_profile.additional_properties) + merged_additional_properties

    merged_generator_args = list(generator_arg)
    if selected_profile is not None and selected_profile.generator_arg:
        merged_generator_args = list(selected_profile.generator_arg) + merged_generator_args

    merged_post_hooks = list(post_hook)
    merged_post_hooks_by_language = {}
    merged_run_hooks = run_hooks
    if selected_profile is not None:
        if selected_profile.post_hooks:
            merged_post_hooks = list(selected_profile.post_hooks) + merged_post_hooks
        if selected_profile.post_hooks_by_language:
            merged_post_hooks_by_language = dict(selected_profile.post_hooks_by_language)
        if _param_is_default(ctx, "run_hooks") and selected_profile.run_hooks is not None:
            merged_run_hooks = bool(selected_profile.run_hooks)

    merged_system_properties = list(property)
    if selected_profile is not None and selected_profile.system_properties:
        merged_system_properties = list(selected_profile.system_properties) + merged_system_properties

    merged_schema_cache_ttl = schema_cache_ttl
    if (
        merged_schema_cache_ttl is None
        and selected_profile is not None
        and selected_profile.schema_cache_ttl
        and _param_is_default(ctx, "schema_cache_ttl")
    ):
        merged_schema_cache_ttl = selected_profile.schema_cache_ttl

    merged_no_schema_cache = no_schema_cache
    if (
        not merged_no_schema_cache
        and selected_profile is not None
        and selected_profile.no_schema_cache is True
        and _param_is_default(ctx, "no_schema_cache")
    ):
        merged_no_schema_cache = True

    merged_emit_patched_schema = emit_patched_schema
    if (
        merged_emit_patched_schema is None
        and selected_profile is not None
        and selected_profile.emit_patched_schema
        and _param_is_default(ctx, "emit_patched_schema")
    ):
        merged_emit_patched_schema = selected_profile.emit_patched_schema

    args = GenArgs(
        generator_version=merged_generator_version,
        engine=merged_engine,
        schema=schema,
        crudsql_url=merged_crudsql_url,
        swain_base_url=merged_swain_base_url,
        out=out,
        languages=merged_lang,
        config=merged_generator_config,
        templates=merged_templates,
        additional_properties=merged_additional_properties,
        generator_arg=merged_generator_args,
        post_hooks=merged_post_hooks,
        post_hooks_by_language=merged_post_hooks_by_language,
        java_opts=merged_java_opts,
        swain_tenant_id=merged_tenant_id,
        swain_project_id=swain_project_id,
        swain_connection_id=swain_connection_id,
        system_properties=merged_system_properties,
        skip_validate_spec=skip_validate_spec,
        verbose=verbose,
        dry_run=dry_run,
        plan_only=plan_only,
        plan_format=plan_format.value,
        pretty=pretty,
        patch_base_url=merged_patch_base_url,
        emit_patched_schema=merged_emit_patched_schema,
        parallel=merged_parallel,
        schema_cache_ttl=merged_schema_cache_ttl,
        no_schema_cache=merged_no_schema_cache,
        run_hooks=merged_run_hooks,
    )
    with logs_to_stderr():
        _run_handler(lambda a: handle_gen(a, ctx=ctx.obj.app_ctx), args)


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
    swain_base_url: Optional[str] = typer.Option(
        None,
        "--swain-base-url",
        help=f"Swain platform base URL (default: {DEFAULT_SWAIN_BASE_URL})",
    ),
    crudsql_url: Optional[str] = typer.Option(
        None,
        "--crudsql-url",
        help=f"CrudSQL base URL override (default: derived from Swain base, e.g. {DEFAULT_CRUDSQL_API_BASE_URL})",
    ),
    engine: str = typer.Option(
        "embedded",
        "--engine",
        envvar=ENGINE_ENV_VAR,
        case_sensitive=False,
        help=f"select Java runtime (default: embedded, or set {ENGINE_ENV_VAR})",
        show_choices=True,
    ),
    no_run: bool = typer.Option(
        False,
        "--no-run",
        help="only print the generated command (do not execute)",
    ),
) -> None:
    cfg = ctx.obj.config
    merged_engine = engine.lower()
    if (
        merged_engine == "embedded"
        and not (os.environ.get(ENGINE_ENV_VAR) or "").strip()
        and cfg.engine
    ):
        merged_engine = cfg.engine.lower()

    merged_swain_base_url = swain_base_url or cfg.swain_base_url
    merged_crudsql_url = crudsql_url or cfg.crudsql_url

    merged_java_opts = list(java_opt)
    if (
        not merged_java_opts
        and not (os.environ.get(JAVA_OPTS_ENV_VAR) or "").strip()
        and cfg.java_opts
    ):
        merged_java_opts = list(cfg.java_opts)
    args = SimpleNamespace(
        generator_version=ctx.obj.generator_version,
        java_opts=merged_java_opts,
        generator_args=generator_arg,
        swain_base_url=merged_swain_base_url,
        crudsql_url=merged_crudsql_url,
        engine=merged_engine,
        no_run=no_run,
        app_ctx=ctx.obj.app_ctx,
    )
    _run_handler(handle_interactive, args)


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
        help=f"Authentication base URL (default: {DEFAULT_SWAIN_BASE_URL})",
    ),
) -> None:
    args = SimpleNamespace(
        username=username,
        password=password,
        auth_base_url=auth_base_url,
    )
    _run_handler(handle_auth_login, args)


@auth_app.command("logout")
def auth_logout() -> None:
    _run_handler(handle_auth_logout, SimpleNamespace())


@auth_app.command("status")
def auth_status() -> None:
    _run_handler(handle_auth_status, SimpleNamespace())


@auth_app.command("refresh")
def auth_refresh(
    ctx: typer.Context,
    auth_base_url: Optional[str] = typer.Option(
        None,
        "--auth-base-url",
        help=f"Authentication base URL (default: {DEFAULT_SWAIN_BASE_URL})",
    ),
) -> None:
    cfg = ctx.obj.config
    swain_base_url, _ = resolve_base_urls(cfg.swain_base_url, cfg.crudsql_url)
    args = SimpleNamespace(
        auth_base_url=auth_base_url or swain_base_url,
    )
    _run_handler(handle_auth_refresh, args)


@engine_app.command("status")
def engine_status() -> None:
    _run_handler(handle_engine_status, SimpleNamespace())


@engine_app.command("paths")
def engine_paths(
    json: bool = typer.Option(False, "--json", help="emit paths as JSON"),
    pretty: bool = typer.Option(False, "--pretty", help="pretty-print JSON output"),
) -> None:
    args = SimpleNamespace(json=json, pretty=pretty)
    with logs_to_stderr():
        _run_handler(handle_engine_paths, args)


@engine_app.command("clean")
def engine_clean(
    force: bool = typer.Option(False, "--force", help="apply deletion (otherwise dry-run)"),
    all: bool = typer.Option(False, "--all", help="delete downloads, jars, and embedded jre"),
    downloads: bool = typer.Option(False, "--downloads", help="delete downloads cache"),
    jars: bool = typer.Option(False, "--jars", help="delete cached generator jars"),
    jre: bool = typer.Option(False, "--jre", help="delete embedded jre directory"),
    schemas: bool = typer.Option(False, "--schemas", help="delete cached schemas"),
    json: bool = typer.Option(False, "--json", help="emit results as JSON"),
    pretty: bool = typer.Option(False, "--pretty", help="pretty-print JSON output"),
) -> None:
    args = SimpleNamespace(
        force=force,
        all=all,
        downloads=downloads,
        jars=jars,
        jre=jre,
        schemas=schemas,
        json=json,
        pretty=pretty,
    )
    with logs_to_stderr():
        _run_handler(handle_engine_clean, args)


@engine_app.command("prune-jars")
def engine_prune_jars(
    keep: int = typer.Option(3, "--keep", help="number of cached versions to keep"),
    force: bool = typer.Option(False, "--force", help="apply deletion (otherwise dry-run)"),
    json: bool = typer.Option(False, "--json", help="emit results as JSON"),
    pretty: bool = typer.Option(False, "--pretty", help="pretty-print JSON output"),
) -> None:
    args = SimpleNamespace(keep=keep, force=force, json=json, pretty=pretty)
    with logs_to_stderr():
        _run_handler(handle_engine_prune_jars, args)


@engine_app.command("install-jre")
def engine_install_jre(
    force: bool = typer.Option(
        False,
        "--force",
        help="reinstall even if already present",
    )
) -> None:
    args = SimpleNamespace(force=force)
    _run_handler(handle_engine_install_jre, args)


@engine_app.command("update-jar")
def engine_update_jar(
    version: str = typer.Option(
        ...,
        "--version",
        help="OpenAPI Generator version to download",
    ),
    no_verify: bool = typer.Option(
        False,
        "--no-verify",
        help="skip checksum verification for the downloaded jar",
    ),
) -> None:
    args = SimpleNamespace(version=version, no_verify=no_verify)
    _run_handler(handle_engine_update_jar, args)


@engine_app.command("use-system")
def engine_use_system() -> None:
    _run_handler(handle_engine_use_system, SimpleNamespace())


@engine_app.command("use-embedded")
def engine_use_embedded() -> None:
    _run_handler(handle_engine_use_embedded, SimpleNamespace())


def main(argv: Optional[Sequence[str]] = None) -> int:
    command = typer.main.get_command(app)
    try:
        command.main(
            args=list(argv) if argv is not None else None,
            prog_name="swain_cli",
            standalone_mode=False,
        )
    except (KeyboardInterrupt, typer.Abort):
        log_error("interrupted")
        return EXIT_CODE_INTERRUPT
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
