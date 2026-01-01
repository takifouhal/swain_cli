"""SDK generation helpers."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from .args import GenArgs
from .auth import determine_swain_tenant_id, require_auth_token
from .console import log, log_error
from .constants import (
    EXIT_CODE_SUBPROCESS,
    FALLBACK_JAVA_HEAP_OPTION,
    GLOBAL_PROPERTY_DISABLE_DOCS,
    LANGUAGE_ALIASES,
    OOM_MARKERS,
    SKIP_OPERATION_EXAMPLE_FLAG,
)
from .crudsql import fetch_crudsql_schema
from .engine import (
    resolve_generator_jar,
    resolve_java_opts,
    run_openapi_generator,
)
from .errors import CLIError
from .swain_api import (
    SwainConnection,
    fetch_swain_connection_by_id,
    fetch_swain_connection_schema,
    fetch_swain_connections_with_fallback,
)
from .urls import resolve_base_urls
from .utils import format_cli_command, is_url, pick, safe_int


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


def generator_args_skip_examples(generator_args: Sequence[str]) -> bool:
    return any(arg.startswith(SKIP_OPERATION_EXAMPLE_FLAG) for arg in generator_args)


def ensure_generator_arg_defaults(generator_args: Sequence[str]) -> List[str]:
    result = list(generator_args)
    if not generator_args_disable_docs(result):
        result.append(f"--global-property={GLOBAL_PROPERTY_DISABLE_DOCS}")
    if not generator_args_skip_examples(result):
        result.append(SKIP_OPERATION_EXAMPLE_FLAG)
    return result


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


def build_generate_command(
    schema: str, language: str, args: GenArgs, out_dir: Path
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
    for var in args.system_properties:
        cmd.extend(["-D", var])
    if args.skip_validate_spec:
        cmd.append("--skip-validate-spec")
    if args.verbose:
        cmd.append("-v")
    return resolved_lang, target_dir, cmd


def ensure_additional_property_defaults(properties: Sequence[str]) -> List[str]:
    addl_props: List[str] = list(properties)
    has_flag = any(
        (prop.split("=", 1)[0].strip() == "disallowAdditionalPropertiesIfNotPresent")
        for prop in addl_props
    )
    if not has_flag:
        addl_props.append("disallowAdditionalPropertiesIfNotPresent=false")
    return addl_props


def handle_gen(args: GenArgs) -> int:
    jar = resolve_generator_jar(args.generator_version)
    engine = args.engine
    schema_arg = args.schema
    crudsql_url = args.crudsql_url
    swain_base_url = args.swain_base_url
    swain_project_id = args.swain_project_id
    swain_connection_id = args.swain_connection_id
    swain_tenant_id = args.swain_tenant_id
    temp_schema: Optional[Path] = None
    selected_connection: Optional[SwainConnection] = None
    swain_base, crudsql_base = resolve_base_urls(swain_base_url, crudsql_url)

    tenant_id_cache: Optional[str] = None

    def ensure_tenant_id(token: str) -> str:
        nonlocal tenant_id_cache
        if tenant_id_cache is None:
            tenant_id_cache = determine_swain_tenant_id(
                swain_base,
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
                            raise CLIError(f"invalid project id '{swain_project_id}'") from exc
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
                    try:
                        selected_connection = fetch_swain_connection_by_id(
                            swain_base,
                            token,
                            connection_id_value,
                            tenant_id=tenant_id_value,
                        )
                    except CLIError:
                        if crudsql_base != swain_base:
                            selected_connection = fetch_swain_connection_by_id(
                                crudsql_base,
                                token,
                                connection_id_value,
                                tenant_id=tenant_id_value,
                            )
                        else:
                            raise
                    if project_id_value is not None:
                        connection_project_id = safe_int(
                            pick(
                                selected_connection.raw,
                                "project_id",
                                "projectId",
                            )
                        )
                        if (
                            connection_project_id is not None
                            and connection_project_id != project_id_value
                        ):
                            log("warning: connection project does not match provided project id")
                elif project_id_value is not None:
                    connections = fetch_swain_connections_with_fallback(
                        swain_base,
                        crudsql_base if crudsql_base != swain_base else None,
                        token,
                        tenant_id=tenant_id_value,
                        project_id=project_id_value,
                    )
                    if not connections:
                        raise CLIError(f"no connections found for project {project_id_value}")
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
                    swain_base,
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
                    crudsql_base,
                    token,
                    tenant_id=tenant_id_value,
                )
                schema = str(temp_schema)
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        languages = args.languages
        if not languages:
            raise CLIError("at least one --lang is required")

        resolved_args = replace(
            args,
            additional_properties=ensure_additional_property_defaults(
                args.additional_properties
            ),
            generator_arg=ensure_generator_arg_defaults(args.generator_arg),
        )

        resolved_java_opts = resolve_java_opts(args.java_opts)
        java_opts = list(resolved_java_opts.options)
        log(f"java options: {format_cli_command(java_opts)}")
        for lang in languages:
            resolved_lang, target_dir, cmd = build_generate_command(
                schema, lang, resolved_args, out_dir
            )
            log(f"generating {resolved_lang} into {target_dir}")
            current_cmd = list(cmd)
            current_java_opts = list(java_opts)
            docs_disabled = command_disables_docs(current_cmd)
            while True:
                rc, output = run_openapi_generator(jar, engine, current_cmd, current_java_opts)
                if rc == 0:
                    break
                oom_detected = any(marker in output for marker in OOM_MARKERS)
                retried = False
                if rc != 0 and oom_detected:
                    new_java_opts = replace_heap_option(current_java_opts, FALLBACK_JAVA_HEAP_OPTION)
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
                    log_error(f"generation failed for {resolved_lang} (exit code {rc})")
                    return rc if rc != 0 else EXIT_CODE_SUBPROCESS
            java_opts = current_java_opts
    finally:
        if temp_schema:
            temp_schema.unlink(missing_ok=True)
    return 0
