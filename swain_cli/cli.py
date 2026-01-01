#!/usr/bin/env python3
"""swain_cli CLI entry point."""

from __future__ import annotations

import platform
import sys
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Callable, List, Optional, Sequence, TypeVar

import typer

from .args import GenArgs
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
from .prompts import prompt_confirm, prompt_select, prompt_text
from .urls import (
    crudsql_dynamic_swagger_url,
)

app = typer.Typer(help="swain_cli CLI")
auth_app = typer.Typer(help="Authentication helpers")
engine_app = typer.Typer(help="Embedded engine management")
app.add_typer(auth_app, name="auth")
app.add_typer(engine_app, name="engine")


@dataclass
class CLIContext:
    generator_version: Optional[str] = None


ArgsT = TypeVar("ArgsT")


def _run_handler(handler: Callable[[ArgsT], int], args: ArgsT) -> None:
    try:
        rc = handler(args)
    except CLIError as exc:
        log_error(f"error: {exc}")
        raise typer.Exit(code=EXIT_CODE_USAGE) from exc
    raise typer.Exit(code=rc)


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


def run_interactive(args: SimpleNamespace) -> int:
    deps = InteractiveDeps(
        prompt_confirm=prompt_confirm,
        prompt_select=prompt_select,
        prompt_text=prompt_text,
        interactive_auth_setup=interactive_auth_setup,
        require_auth_token=require_auth_token,
        determine_swain_tenant_id=determine_swain_tenant_id,
        crudsql_dynamic_swagger_url=crudsql_dynamic_swagger_url,
        handle_gen=handle_gen,
    )
    return run_interactive_wizard(coerce_interactive_args(args), deps)


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
    _run_handler(handle_doctor, args)


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
    _run_handler(handle_list_generators, args)


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
    args = GenArgs(
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
        system_properties=property,
        skip_validate_spec=skip_validate_spec,
        verbose=verbose,
    )
    _run_handler(handle_gen, args)


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


@engine_app.command("status")
def engine_status() -> None:
    _run_handler(handle_engine_status, SimpleNamespace())


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
    version: str = typer.Option(..., "--version", help="OpenAPI Generator version to download")
) -> None:
    args = SimpleNamespace(version=version)
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
