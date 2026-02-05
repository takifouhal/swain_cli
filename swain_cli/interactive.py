"""Interactive SDK generation wizard."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, List, Optional, Protocol, Sequence

import questionary

from .args import GenArgs, InteractiveArgs
from .config import ProfileConfig, load_config, resolve_config_path, upsert_profile
from .console import log, log_error
from .constants import COMMON_LANGUAGES, EXIT_CODE_INTERRUPT, PINNED_GENERATOR_VERSION
from .engine import resolve_java_opts
from .errors import CLIError
from .generator import ensure_generator_arg_defaults
from .prompts import InteractionAborted
from .schema_cache import parse_ttl_seconds
from .swain_api import (
    SwainConnection,
    SwainProject,
    fetch_swain_connections_with_fallback,
    fetch_swain_projects_with_fallback,
    swain_dynamic_swagger_from_connection,
)
from .urls import normalize_base_url, resolve_base_urls
from .utils import format_cli_command, redact


class PromptConfirm(Protocol):
    def __call__(self, prompt: str, *, default: bool) -> bool: ...


class PromptText(Protocol):
    def __call__(
        self,
        prompt: str,
        *,
        default: Optional[str] = None,
        validate: Optional[Callable[[str], Optional[str]]] = None,
        allow_empty: bool = False,
    ) -> str: ...


class PromptSelect(Protocol):
    def __call__(self, prompt: str, choices: Sequence[Any]) -> Any: ...


class PromptMultiSelect(Protocol):
    def __call__(self, prompt: str, choices: Sequence[Any]) -> List[Any]: ...


class InteractiveAuthSetup(Protocol):
    def __call__(self, auth_base_url: Optional[str] = None) -> None: ...


class RequireAuthToken(Protocol):
    def __call__(self, purpose: str = "perform this action") -> str: ...


class DetermineTenantId(Protocol):
    def __call__(
        self,
        base_url: str,
        token: str,
        provided: Optional[str],
        *,
        allow_prompt: bool,
    ) -> str: ...


class CrudSqlDynamicSwaggerUrl(Protocol):
    def __call__(self, base_url: str) -> str: ...


@dataclass(frozen=True)
class InteractiveDeps:
    prompt_confirm: PromptConfirm
    prompt_select: PromptSelect
    prompt_multi_select: PromptMultiSelect
    prompt_text: PromptText
    interactive_auth_setup: InteractiveAuthSetup
    require_auth_token: RequireAuthToken
    determine_swain_tenant_id: DetermineTenantId
    crudsql_dynamic_swagger_url: CrudSqlDynamicSwaggerUrl
    handle_gen: Callable[[GenArgs], int]


def guess_default_output_dir() -> str:
    return "sdks"


def coerce_interactive_args(raw: Any) -> InteractiveArgs:
    crudsql_base_arg = getattr(raw, "crudsql_url", None)
    swain_base_arg = getattr(raw, "swain_base_url", None)
    generator_version = getattr(raw, "generator_version", None)
    java_opts = list(getattr(raw, "java_opts", []) or [])
    generator_args = list(getattr(raw, "generator_args", None) or [])
    no_run = bool(getattr(raw, "no_run", False))
    engine_choice = getattr(raw, "engine", "embedded") or "embedded"
    engine_choice = str(engine_choice).lower()
    return InteractiveArgs(
        generator_version=generator_version,
        java_opts=java_opts,
        generator_args=generator_args,
        swain_base_url=swain_base_arg,
        crudsql_url=crudsql_base_arg,
        engine=engine_choice,
        no_run=no_run,
    )


def _validate_output_dir(value: str) -> Optional[str]:
    candidate = Path(value).expanduser()
    if candidate.exists() and not candidate.is_dir():
        return "output path exists and is not a directory"
    return None


def _parse_languages(raw: str) -> List[str]:
    return [item.strip() for item in raw.replace(";", ",").split(",") if item.strip()]


def _validate_languages(raw: str) -> Optional[str]:
    if not _parse_languages(raw):
        return "please provide at least one language"
    return None


def run_interactive(args: InteractiveArgs, deps: InteractiveDeps) -> int:
    log("interactive SDK generation wizard")
    log("press Ctrl+C at any time to cancel")
    swain_base, crudsql_base = resolve_base_urls(args.swain_base_url, args.crudsql_url)
    # Authenticate against the CrudSQL surface (proxy or direct) since auth endpoints
    # live there; Swain discovery continues to use the platform base without /crud.
    deps.interactive_auth_setup(auth_base_url=crudsql_base)
    dynamic_swagger_url: Optional[str] = None
    swain_project: Optional[SwainProject] = None
    swain_connection: Optional[SwainConnection] = None
    tenant_id: Optional[str] = None
    java_cli_opts: List[str] = list(args.java_opts)
    generator_args: List[str] = list(args.generator_args)
    engine_choice = args.engine

    try:
        dynamic_swagger_url = deps.crudsql_dynamic_swagger_url(crudsql_base)
        token = deps.require_auth_token("discover Swain projects and connections")
        tenant_id = deps.determine_swain_tenant_id(
            swain_base,
            token,
            tenant_id,
            allow_prompt=True,
        )
        projects = fetch_swain_projects_with_fallback(
            swain_base,
            crudsql_base if crudsql_base != swain_base else None,
            token,
            tenant_id=tenant_id,
        )
        if not projects:
            raise CLIError("no projects available on the Swain backend")
        if len(projects) == 1:
            swain_project = projects[0]
            log(f"Detected single project: {swain_project.name} (#{swain_project.id})")
        else:
            project_options = {project.id: project for project in projects}
            project_choices = [
                questionary.Choice(
                    title=f"{project.name} (#{project.id})",
                    value=project.id,
                )
                for project in projects
            ]
            selected_project_id = deps.prompt_select(
                "Select a project", project_choices
            )
            swain_project = project_options[selected_project_id]

        connections = fetch_swain_connections_with_fallback(
            swain_base,
            crudsql_base if crudsql_base != swain_base else None,
            token,
            tenant_id=tenant_id,
            project_id=swain_project.id,
        )
        if not connections:
            raise CLIError(f"project {swain_project.name} has no connections with builds")
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
            selected_connection_id = deps.prompt_select(
                "Select a connection", connection_choices
            )
            swain_connection = connection_options[selected_connection_id]

        out_dir_input = deps.prompt_text(
            "Output directory",
            default=guess_default_output_dir(),
            validate=_validate_output_dir,
        )

        language_choices = [
            questionary.Choice(
                title=lang,
                value=lang,
                checked=(lang in {"python", "typescript"}),
            )
            for lang in COMMON_LANGUAGES
        ]
        languages_selected = deps.prompt_multi_select(
            "Select target languages",
            language_choices,
        )
        languages = [str(lang).strip().lower() for lang in languages_selected if str(lang).strip()]
        if not languages:
            raise CLIError("please select at least one language")

        generator_version = args.generator_version
        config_value: Optional[str] = None
        templates_value: Optional[str] = None
        additional_properties: List[str] = []
        sys_props: List[str] = []
        generator_args = list(generator_args)
        skip_validate = False
        verbose = False
        patch_base_url = True
        parallel = 1
        schema_cache_ttl: Optional[str] = None
        no_schema_cache = False
        post_hooks: List[str] = []
        run_hooks = False

        if deps.prompt_confirm("Configure advanced generator options?", default=False):
            config_value = deps.prompt_text(
                "Generator config file (-c) (leave blank to skip)",
                default="",
                allow_empty=True,
            ) or None
            if config_value:
                path = Path(config_value).expanduser()
                if not path.exists():
                    raise CLIError(f"generator config file not found: {path}")

            templates_value = deps.prompt_text(
                "Templates directory (-t) (leave blank to skip)",
                default="",
                allow_empty=True,
            ) or None
            if templates_value:
                path = Path(templates_value).expanduser()
                if not path.exists() or not path.is_dir():
                    raise CLIError(f"templates directory not found: {path}")

            if deps.prompt_confirm("Add additional properties (-p)?", default=False):
                while True:
                    prop = deps.prompt_text("Additional property (key=value)", default="")
                    if "=" not in prop or not prop.split("=", 1)[0].strip():
                        raise CLIError("additional properties must be in key=value format")
                    additional_properties.append(prop)
                    if not deps.prompt_confirm("Add another property?", default=True):
                        break

            if deps.prompt_confirm("Add system properties (-D)?", default=False):
                while True:
                    prop = deps.prompt_text("System property (key=value)", default="")
                    if "=" not in prop or not prop.split("=", 1)[0].strip():
                        raise CLIError("system properties must be in key=value format")
                    sys_props.append(prop)
                    if not deps.prompt_confirm("Add another system property?", default=True):
                        break

            if deps.prompt_confirm("Add raw OpenAPI Generator args?", default=False):
                while True:
                    arg = deps.prompt_text("Generator arg (e.g. --global-property=apis=Foo)", default="")
                    generator_args.append(arg)
                    if not deps.prompt_confirm("Add another generator arg?", default=True):
                        break

            if deps.prompt_confirm("Generate docs/tests?", default=False):
                generator_args.append(
                    "--global-property=apiDocs=true,apiTests=true,modelDocs=true,modelTests=true"
                )

            patch_base_url = deps.prompt_confirm(
                "Patch schema base URL (recommended)?",
                default=True,
            )

            parallel_raw = deps.prompt_text(
                "Parallel generation workers (1 disables parallelism)",
                default="1",
            )
            try:
                parallel_value = int(parallel_raw)
            except ValueError as exc:
                raise CLIError("parallel must be an integer >= 1") from exc
            if parallel_value < 1:
                raise CLIError("parallel must be >= 1")
            parallel = parallel_value

            if deps.prompt_confirm("Cache fetched schemas?", default=False):
                ttl_raw = deps.prompt_text("Schema cache TTL (e.g. 10m, 2h)", default="10m")
                parse_ttl_seconds(ttl_raw)
                schema_cache_ttl = ttl_raw

            if deps.prompt_confirm("Add post-generation hooks?", default=False):
                while True:
                    cmd = deps.prompt_text("Post-hook command (runs in generated dir)", default="")
                    post_hooks.append(cmd)
                    if not deps.prompt_confirm("Add another hook?", default=True):
                        break
                run_hooks = deps.prompt_confirm(
                    "Enable running hooks by default? (dangerous)",
                    default=False,
                )

            if deps.prompt_confirm("Choose OpenAPI Generator version?", default=False):
                cached_versions: List[str] = []
                try:
                    from .engine import list_cached_jars

                    for entry in list_cached_jars():
                        version = str(entry).split(" -> ", 1)[0].strip()
                        if version:
                            cached_versions.append(version)
                except Exception:
                    cached_versions = []
                seen = set()
                versions: List[str] = []
                for version in [PINNED_GENERATOR_VERSION, *sorted(cached_versions)]:
                    if version in seen:
                        continue
                    seen.add(version)
                    versions.append(version)
                choices = [
                    questionary.Choice(
                        title=f"{versions[0]} (pinned)",
                        value=versions[0],
                    )
                ]
                for version in versions[1:]:
                    suffix = " (cached)" if version in cached_versions else ""
                    choices.append(questionary.Choice(title=f"{version}{suffix}", value=version))
                generator_version = deps.prompt_select("OpenAPI Generator version", choices)

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
    swain_base_override = normalize_base_url(args.swain_base_url)
    crudsql_base_override = normalize_base_url(args.crudsql_url)
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
        log(f"  additional properties: {redact(str(additional_properties))}")
    if sys_props:
        log(f"  system properties: {redact(str(sys_props))}")
    if generator_args:
        log(f"  extra generator args: {redact(str(generator_args))}")
    if generator_version:
        log(f"  generator version: {generator_version}")
    log(f"  patch base url: {patch_base_url}")
    log(f"  parallel: {parallel}")
    if schema_cache_ttl:
        log(f"  schema cache ttl: {schema_cache_ttl}")
    if post_hooks:
        log(f"  post hooks: {len(post_hooks)} (run={run_hooks})")
    log(f"  engine: {engine_choice}")
    log(f"  skip validate: {skip_validate}")
    log(f"  verbose: {verbose}")
    java_preview_opts = resolve_java_opts(java_cli_opts).options
    log(f"  java options: {redact(format_cli_command(java_preview_opts))}")

    command_preview: List[str] = ["swain_cli"]
    if generator_version:
        command_preview.extend(["--generator-version", generator_version])
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
    if not patch_base_url:
        command_preview.append("--no-patch-base-url")
    if parallel != 1:
        command_preview.extend(["--parallel", str(parallel)])
    if schema_cache_ttl:
        command_preview.extend(["--schema-cache-ttl", schema_cache_ttl])
    if no_schema_cache:
        command_preview.append("--no-schema-cache")
    if config_value:
        command_preview.extend(["-c", config_value])
    if templates_value:
        command_preview.extend(["-t", templates_value])
    for prop in additional_properties:
        command_preview.extend(["-p", prop])
    for arg in generator_args:
        command_preview.extend(["--generator-arg", arg])
    for cmd in post_hooks:
        command_preview.extend(["--post-hook", cmd])
    if run_hooks:
        command_preview.append("--run-hooks")
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

    log(f"equivalent command: {redact(format_cli_command(command_preview))}")

    if deps.prompt_confirm("Save this configuration as a profile?", default=False):
        profile_name = deps.prompt_text(
            "Profile name",
            default="",
        ).strip()
        config_path = resolve_config_path()
        existing = load_config(config_path)
        overwrite = False
        if profile_name in existing.profiles:
            overwrite = deps.prompt_confirm(
                f"profile {profile_name!r} exists; overwrite?",
                default=False,
            )
            if not overwrite:
                log("profile not saved")
        if profile_name and (overwrite or profile_name not in existing.profiles):
            upsert_profile(
                profile_name,
                ProfileConfig(
                    languages=languages,
                    engine=engine_choice,
                    generator_version=generator_version,
                    java_opts=list(java_cli_opts),
                    config=config_value,
                    templates=templates_value,
                    additional_properties=list(additional_properties),
                    generator_arg=list(generator_args),
                    system_properties=list(sys_props),
                    patch_base_url=patch_base_url,
                    parallel=parallel,
                    schema_cache_ttl=schema_cache_ttl,
                    no_schema_cache=no_schema_cache,
                    post_hooks=list(post_hooks),
                    run_hooks=run_hooks,
                ),
                overwrite=overwrite,
                path=config_path,
            )
            log(f"saved profile {profile_name!r} to {config_path}")

    if args.no_run:
        log("no-run mode enabled; generation not executed")
        return 0

    if not deps.prompt_confirm("Run generation now?", default=True):
        log("generation skipped; run the command above when ready")
        return 0

    gen_args = GenArgs(
        generator_version=generator_version,
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
        post_hooks=post_hooks,
        run_hooks=run_hooks,
        java_opts=list(java_cli_opts),
        system_properties=sys_props,
        skip_validate_spec=skip_validate,
        verbose=verbose,
        patch_base_url=patch_base_url,
        parallel=parallel,
        schema_cache_ttl=schema_cache_ttl,
        no_schema_cache=no_schema_cache,
    )
    return deps.handle_gen(gen_args)
