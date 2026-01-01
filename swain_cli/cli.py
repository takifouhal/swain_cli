#!/usr/bin/env python3
"""swain_cli CLI entry point."""

from __future__ import annotations

import platform
import sys
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import List, Optional, Sequence

import questionary
import typer

from .auth import (
    determine_swain_tenant_id,
    handle_auth_login,
    handle_auth_logout,
    handle_auth_status,
    interactive_auth_setup,
    require_auth_token,
)
from .console import log, log_error
from .constants import (
    COMMON_LANGUAGES,
    DEFAULT_CRUDSQL_API_BASE_URL,
    DEFAULT_SWAIN_BASE_URL,
    ENGINE_ENV_VAR,
    EXIT_CODE_INTERRUPT,
    EXIT_CODE_USAGE,
    TENANT_ID_ENV_VAR,
)
from .engine import (
    collect_engine_snapshot,
    emit_engine_snapshot,
    handle_engine_install_jre,
    handle_engine_status,
    handle_engine_update_jar,
    handle_engine_use_embedded,
    handle_engine_use_system,
    handle_list_generators,
    resolve_java_opts,
)
from .errors import CLIError
from .generator import ensure_generator_arg_defaults, handle_gen
from .prompts import (
    InteractionAborted,
    prompt_confirm,
    prompt_select,
    prompt_text,
)
from .swain_api import (
    SwainConnection,
    SwainProject,
    _fetch_swain_connections_with_fallback,
    _fetch_swain_projects_with_fallback,
    swain_dynamic_swagger_from_connection,
)
from .urls import (
    _normalize_base_url,
    crudsql_dynamic_swagger_url,
    resolve_base_urls,
)
from .utils import (
    format_cli_command,
)

app = typer.Typer(help="swain_cli CLI")
auth_app = typer.Typer(help="Authentication helpers")
engine_app = typer.Typer(help="Embedded engine management")
app.add_typer(auth_app, name="auth")
app.add_typer(engine_app, name="engine")


@dataclass
class CLIContext:
    generator_version: Optional[str] = None


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


def guess_default_output_dir() -> str:
    return "sdks"


def run_interactive(args: SimpleNamespace) -> int:
    log("interactive SDK generation wizard")
    log("press Ctrl+C at any time to cancel")
    crudsql_base_arg = getattr(args, "crudsql_url", None)
    swain_base_arg = getattr(args, "swain_base_url", None)
    swain_base, crudsql_base = resolve_base_urls(swain_base_arg, crudsql_base_arg)
    # Authenticate against the CrudSQL surface (proxy or direct) since auth endpoints
    # live there; Swain discovery continues to use the platform base without /crud.
    interactive_auth_setup(auth_base_url=crudsql_base)
    dynamic_swagger_url: Optional[str] = None
    swain_project: Optional[SwainProject] = None
    swain_connection: Optional[SwainConnection] = None
    tenant_id: Optional[str] = None
    java_cli_opts: List[str] = list(getattr(args, "java_opts", []))
    generator_args: List[str] = list(getattr(args, "generator_args", None) or [])
    engine_choice = getattr(args, "engine", "embedded") or "embedded"
    engine_choice = str(engine_choice).lower()

    try:
        dynamic_swagger_url = crudsql_dynamic_swagger_url(crudsql_base)
        token = require_auth_token("discover Swain projects and connections")
        tenant_id = determine_swain_tenant_id(
            swain_base,
            token,
            tenant_id,
            allow_prompt=True,
        )
        projects = _fetch_swain_projects_with_fallback(
            swain_base,
            crudsql_base if crudsql_base != swain_base else None,
            token,
            tenant_id=tenant_id,
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

        connections = _fetch_swain_connections_with_fallback(
            swain_base,
            crudsql_base if crudsql_base != swain_base else None,
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
    generator_args = ensure_generator_arg_defaults(generator_args)
    log("configuration preview")
    swain_base_override = _normalize_base_url(swain_base_arg)
    crudsql_base_override = _normalize_base_url(crudsql_base_arg)
    if swain_connection and swain_project:
        log(f"  swain base: {swain_base}")
        log(f"  crudsql base: {crudsql_base}")
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
        log(f"  swain base: {swain_base}")
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
    if swain_base_override:
        command_preview.extend(["--swain-base-url", swain_base])
    if crudsql_base_override:
        command_preview.extend(["--crudsql-url", crudsql_base])
    if swain_connection and swain_project:
        command_preview.extend(["--swain-project-id", str(swain_project.id)])
        command_preview.extend(["--swain-connection-id", str(swain_connection.id)])
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
        crudsql_url=crudsql_base if crudsql_base_override else None,
        swain_base_url=swain_base,
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
        envvar=ENGINE_ENV_VAR,
        case_sensitive=False,
        help=f"select Java runtime (default: embedded, or set {ENGINE_ENV_VAR})",
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
        envvar=ENGINE_ENV_VAR,
        case_sensitive=False,
        help=f"select Java runtime (default: embedded, or set {ENGINE_ENV_VAR})",
        show_choices=True,
    ),
) -> None:
    args = SimpleNamespace(
        generator_version=ctx.obj.generator_version,
        engine=engine.lower(),
        schema=schema,
        crudsql_url=crudsql_url,
        swain_base_url=swain_base_url,
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
) -> None:
    args = SimpleNamespace(
        generator_version=ctx.obj.generator_version,
        java_opts=java_opt,
        generator_args=generator_arg,
        swain_base_url=swain_base_url,
        crudsql_url=crudsql_url,
        engine=engine.lower(),
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
        help=f"Authentication base URL (default: {DEFAULT_SWAIN_BASE_URL})",
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
