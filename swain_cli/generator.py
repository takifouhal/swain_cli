"""SDK generation helpers."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .args import GenArgs
from .auth import determine_swain_tenant_id, require_auth_token
from .console import log, log_error
from .constants import (
    EXIT_CODE_SUBPROCESS,
    FALLBACK_JAVA_HEAP_OPTION,
    GENERATOR_VERSION_ENV_VAR,
    GLOBAL_PROPERTY_DISABLE_DOCS,
    LANGUAGE_ALIASES,
    OOM_MARKERS,
    PINNED_GENERATOR_VERSION,
    SKIP_OPERATION_EXAMPLE_FLAG,
)
from .context import AppContext
from .crudsql import fetch_crudsql_schema
from .engine import (
    find_embedded_java,
    jar_cache_dir,
    jre_install_dir,
    resolve_generator_jar,
    resolve_java_opts,
    run_openapi_generator,
)
from .errors import CLIError
from .openapi_spec import inject_base_url
from .plugins import resolve_schema_with_plugins
from .schema_cache import (
    get_cached_schema_path,
    parse_ttl_seconds,
    put_cached_schema,
    schema_cache_key,
)
from .swain_api import (
    SwainConnection,
    fetch_swain_connection_by_id,
    fetch_swain_connection_schema,
    fetch_swain_connections_with_fallback,
)
from .urls import crudsql_dynamic_swagger_url, resolve_base_urls, swain_url
from .utils import (
    format_cli_command,
    is_url,
    pick,
    redact,
    redact_cli_args,
    safe_int,
    write_bytes_to_tempfile,
)


def _split_hook_command(command: str) -> List[str]:
    value = str(command).strip()
    if not value:
        return []
    try:
        return shlex.split(value, posix=(os.name != "nt"))
    except ValueError as exc:
        raise CLIError(f"invalid hook command {command!r}: {exc}") from exc


def _run_hook(argv: Sequence[str], *, cwd: Path, stream: bool = True) -> Tuple[int, str]:
    proc = subprocess.Popen(
        list(argv),
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    max_capture_chars = 200_000
    captured: List[str] = []
    captured_size = 0

    def capture(line: str) -> None:
        nonlocal captured_size
        if len(line) > max_capture_chars:
            captured.clear()
            line = line[-max_capture_chars:]
            captured_size = 0
        captured.append(line)
        captured_size += len(line)
        while captured and captured_size > max_capture_chars:
            removed = captured.pop(0)
            captured_size -= len(removed)

    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            if stream:
                sys.stdout.write(line)
            capture(line)
        proc.stdout.close()
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait()
        raise
    return proc.returncode, "".join(captured)


def _hooks_for_language(args: GenArgs, language: str, resolved_language: str) -> List[str]:
    hooks: List[str] = list(getattr(args, "post_hooks", []) or [])
    mapping = getattr(args, "post_hooks_by_language", {}) or {}
    if not isinstance(mapping, dict):
        return hooks
    keys = {str(language).lower(), str(resolved_language).lower()}
    for key in sorted(keys):
        extra = mapping.get(key)
        if isinstance(extra, list):
            hooks.extend(str(item) for item in extra if str(item).strip())
    return hooks


def _run_post_hooks(args: GenArgs, *, language: str, resolved_language: str, out_dir: Path) -> int:
    hooks = _hooks_for_language(args, language, resolved_language)
    if not hooks:
        return 0
    if not getattr(args, "run_hooks", False):
        return 0
    for command in hooks:
        argv = _split_hook_command(command)
        if not argv:
            continue
        log(
            f"running post-hook for {resolved_language} in {out_dir}: "
            f"{redact(format_cli_command(argv))}"
        )
        rc, output = _run_hook(argv, cwd=out_dir, stream=True)
        if rc != 0:
            log_error(f"post-hook failed for {resolved_language} (exit code {rc})")
            if output:
                sys.stdout.write(output)
                if not output.endswith("\n"):
                    sys.stdout.write("\n")
            return rc if rc != 0 else EXIT_CODE_SUBPROCESS
    return 0


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
    schema: str,
    language: str,
    args: GenArgs,
    out_dir: Path,
    *,
    create: bool = True,
) -> Tuple[str, Path, List[str]]:
    resolved_lang = LANGUAGE_ALIASES.get(language, language)
    target_dir = out_dir / resolved_lang
    if create:
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


@dataclass(frozen=True)
class ResolvedSchema:
    schema: str
    temp_path: Optional[Path] = None
    connection: Optional[SwainConnection] = None
    tenant_id: Optional[str] = None


def resolve_input_schema(schema_arg: str) -> str:
    schema = schema_arg
    if not is_url(schema):
        schema_path = Path(schema)
        if not schema_path.exists():
            raise CLIError(f"schema not found: {schema_path}")
        schema = str(schema_path)
    return schema


def resolve_swain_connection(
    *,
    swain_base: str,
    crudsql_base: str,
    token: str,
    tenant_id: str,
    project_id: Optional[int],
    connection_id: Optional[int],
    ctx: Optional[AppContext] = None,
) -> SwainConnection:
    if connection_id is not None:
        try:
            if ctx is not None:
                selected_connection = fetch_swain_connection_by_id(
                    swain_base,
                    token,
                    connection_id,
                    tenant_id=tenant_id,
                    ctx=ctx,
                )
            else:
                selected_connection = fetch_swain_connection_by_id(
                    swain_base,
                    token,
                    connection_id,
                    tenant_id=tenant_id,
                )
        except CLIError:
            if crudsql_base != swain_base:
                if ctx is not None:
                    selected_connection = fetch_swain_connection_by_id(
                        crudsql_base,
                        token,
                        connection_id,
                        tenant_id=tenant_id,
                        ctx=ctx,
                    )
                else:
                    selected_connection = fetch_swain_connection_by_id(
                        crudsql_base,
                        token,
                        connection_id,
                        tenant_id=tenant_id,
                    )
            else:
                raise
        if project_id is not None:
            connection_project_id = safe_int(
                pick(
                    selected_connection.raw,
                    "project_id",
                    "projectId",
                )
            )
            if connection_project_id is not None and connection_project_id != project_id:
                log("warning: connection project does not match provided project id")
        return selected_connection

    if project_id is None:
        raise CLIError(
            "--swain-connection-id or --swain-project-id is required when using Swain discovery"
        )

    if ctx is not None:
        connections = fetch_swain_connections_with_fallback(
            swain_base,
            crudsql_base if crudsql_base != swain_base else None,
            token,
            tenant_id=tenant_id,
            project_id=project_id,
            ctx=ctx,
        )
    else:
        connections = fetch_swain_connections_with_fallback(
            swain_base,
            crudsql_base if crudsql_base != swain_base else None,
            token,
            tenant_id=tenant_id,
            project_id=project_id,
        )
    if not connections:
        raise CLIError(f"no connections found for project {project_id}")
    if len(connections) > 1:
        raise CLIError("multiple connections found; specify --swain-connection-id")
    return connections[0]


def resolve_schema_for_generation(
    args: GenArgs,
    swain_base: str,
    crudsql_base: str,
    *,
    ctx: Optional[AppContext] = None,
) -> ResolvedSchema:
    plugin_result = resolve_schema_with_plugins(
        args,
        swain_base=swain_base,
        crudsql_base=crudsql_base,
        ctx=ctx,
    )
    if plugin_result is not None:
        return ResolvedSchema(
            schema=plugin_result.schema,
            temp_path=plugin_result.temp_path,
        )
    if args.schema:
        return ResolvedSchema(schema=resolve_input_schema(args.schema))

    cache_ttl_seconds: Optional[int] = None
    if not getattr(args, "no_schema_cache", False):
        ttl_raw = getattr(args, "schema_cache_ttl", None)
        if ttl_raw:
            cache_ttl_seconds = parse_ttl_seconds(str(ttl_raw))

    use_swain_discovery = args.swain_connection_id is not None or args.swain_project_id is not None
    purpose = (
        "fetch the Swain connection swagger document"
        if use_swain_discovery
        else "fetch the CrudSQL swagger document"
    )
    token = require_auth_token(purpose)
    tenant_id = determine_swain_tenant_id(
        swain_base,
        token,
        args.swain_tenant_id,
        allow_prompt=False,
    )

    if use_swain_discovery:
        connection = resolve_swain_connection(
            swain_base=swain_base,
            crudsql_base=crudsql_base,
            token=token,
            tenant_id=tenant_id,
            project_id=args.swain_project_id,
            connection_id=args.swain_connection_id,
            ctx=ctx,
        )

        cache_key: Optional[str] = None
        if cache_ttl_seconds is not None:
            cache_key = schema_cache_key(
                {
                    "kind": "swain_connection",
                    "swain_base_url": swain_base,
                    "tenant_id": tenant_id,
                    "connection_id": connection.id,
                    "build_id": connection.build_id,
                }
            )
            cached = get_cached_schema_path(cache_key, cache_ttl_seconds)
            if cached:
                log(f"using cached schema for connection {connection.id} ({cached})")
                temp_schema = write_bytes_to_tempfile(
                    cached.read_bytes(),
                    suffix=".json",
                    description=f"cached schema for connection {connection.id}",
                )
                return ResolvedSchema(
                    schema=str(temp_schema),
                    temp_path=temp_schema,
                    connection=connection,
                    tenant_id=tenant_id,
                )

        if ctx is not None:
            temp_schema = fetch_swain_connection_schema(
                swain_base,
                connection,
                token,
                tenant_id=tenant_id,
                ctx=ctx,
            )
        else:
            temp_schema = fetch_swain_connection_schema(
                swain_base,
                connection,
                token,
                tenant_id=tenant_id,
            )
        if cache_key is not None:
            try:
                put_cached_schema(cache_key, temp_schema.read_bytes())
            except CLIError as exc:
                log_error(f"failed to write schema cache: {exc}")
        log(
            "using Swain connection"
            f" {connection.id}"
            f" (project: {connection.project_name or 'unknown'},"
            f" schema: {connection.schema_name or 'unknown'})"
        )
        return ResolvedSchema(
            schema=str(temp_schema),
            temp_path=temp_schema,
            connection=connection,
            tenant_id=tenant_id,
        )

    crudsql_cache_key: Optional[str] = None
    if cache_ttl_seconds is not None:
        crudsql_cache_key = schema_cache_key(
            {
                "kind": "crudsql",
                "crudsql_base_url": crudsql_base,
                "tenant_id": tenant_id,
            }
        )
        cached = get_cached_schema_path(crudsql_cache_key, cache_ttl_seconds)
        if cached:
            log(f"using cached schema ({cached})")
            temp_schema = write_bytes_to_tempfile(
                cached.read_bytes(),
                suffix=".json",
                description="cached CrudSQL schema",
            )
            return ResolvedSchema(schema=str(temp_schema), temp_path=temp_schema, tenant_id=tenant_id)

    if ctx is not None:
        temp_schema = fetch_crudsql_schema(
            crudsql_base,
            token,
            tenant_id=tenant_id,
            ctx=ctx,
        )
    else:
        temp_schema = fetch_crudsql_schema(
            crudsql_base,
            token,
            tenant_id=tenant_id,
        )
    if crudsql_cache_key is not None:
        try:
            put_cached_schema(crudsql_cache_key, temp_schema.read_bytes())
        except CLIError as exc:
            log_error(f"failed to write schema cache: {exc}")
    return ResolvedSchema(schema=str(temp_schema), temp_path=temp_schema, tenant_id=tenant_id)


def _chosen_generator_version(args: GenArgs) -> str:
    if args.generator_version:
        return args.generator_version
    env = os.environ.get(GENERATOR_VERSION_ENV_VAR, "").strip()
    if env:
        return env
    return PINNED_GENERATOR_VERSION


def _jar_path_for_version(version: str) -> Path:
    return (
        jar_cache_dir(create=False) / version / f"openapi-generator-cli-{version}.jar"
    )


def _describe_schema_plan_only(args: GenArgs, swain_base: str, crudsql_base: str) -> dict:
    if args.schema:
        schema_value = args.schema
        schema_path = Path(schema_value)
        return {
            "mode": "explicit",
            "input": schema_value,
            "kind": "url" if is_url(schema_value) else "path",
            "exists": (schema_path.exists() if not is_url(schema_value) else None),
        }

    use_swain_discovery = (
        args.swain_connection_id is not None or args.swain_project_id is not None
    )
    if use_swain_discovery:
        if args.swain_connection_id is None:
            return {
                "mode": "swain_connection",
                "error": "plan-only requires --swain-connection-id (project-only discovery needs network)",
                "auth_required": True,
                "swain_base_url": swain_base,
                "crudsql_base_url": crudsql_base,
                "swain_project_id": args.swain_project_id,
            }
        cid = args.swain_connection_id
        proxy_urls = [
            str(swain_url(swain_base, f"connections/{cid}/dynamic-swagger")),
            str(swain_url(swain_base, f"connections/{cid}/dynamic_swagger")),
        ]
        return {
            "mode": "swain_connection",
            "auth_required": True,
            "swain_base_url": swain_base,
            "crudsql_base_url": crudsql_base,
            "swain_project_id": args.swain_project_id,
            "swain_connection_id": cid,
            "proxy_urls": proxy_urls,
            "direct_url": "requires discovery (connection endpoint)",
        }

    normalized = crudsql_base.rstrip("/") + "/"
    return {
        "mode": "crudsql",
        "auth_required": True,
        "crudsql_base_url": crudsql_base,
        "discovery_url": f"{normalized}api/schema-location",
        "fallback_dynamic_swagger_url": crudsql_dynamic_swagger_url(crudsql_base),
    }


def _render_plan_text(plan: dict) -> str:
    lines: List[str] = []
    lines.append("swain_cli gen plan")
    schema = plan.get("schema") or {}
    lines.append(f"- schema mode: {schema.get('mode')}")
    if "input" in schema:
        lines.append(f"- schema input: {schema.get('input')}")
    if schema.get("schema"):
        lines.append(f"- resolved schema: {schema.get('schema')}")
    if schema.get("patched_base_url"):
        lines.append(f"- patched base url: {schema.get('patched_base_url')}")
    if "error" in schema:
        lines.append(f"- schema error: {schema.get('error')}")
    if "proxy_urls" in schema:
        lines.append("- swain proxy urls:")
        for url in schema.get("proxy_urls") or []:
            lines.append(f"  - {url}")
    if "fallback_dynamic_swagger_url" in schema:
        lines.append(
            f"- crudsql fallback swagger: {schema.get('fallback_dynamic_swagger_url')}"
        )

    settings = plan.get("settings") or {}
    lines.append(f"- patch base url: {settings.get('patch_base_url')}")
    if settings.get("emit_patched_schema"):
        lines.append(f"- emit schema: {settings.get('emit_patched_schema')}")
    lines.append(f"- parallel: {settings.get('parallel')}")
    lines.append(f"- run hooks: {settings.get('run_hooks')}")
    post_hooks = settings.get("post_hooks") or []
    if post_hooks:
        lines.append(f"- post hooks (all): {len(post_hooks)}")
    post_hooks_by_lang = settings.get("post_hooks_by_language") or {}
    if post_hooks_by_lang:
        lines.append(
            "- post hooks (by language): "
            + ", ".join(sorted(str(key) for key in post_hooks_by_lang.keys()))
        )
    if settings.get("schema_cache_ttl"):
        lines.append(f"- schema cache ttl: {settings.get('schema_cache_ttl')}")
    if settings.get("no_schema_cache"):
        lines.append("- schema cache: disabled")

    engine = plan.get("engine") or {}
    lines.append(f"- engine: {engine.get('mode')}")
    java = engine.get("java") or {}
    lines.append(f"- java: {java.get('command')}")
    java_opts = engine.get("java_opts") or {}
    opts = java_opts.get("options") or []
    lines.append(f"- java opts: {redact(format_cli_command(opts))}")

    gen = plan.get("generator") or {}
    lines.append(f"- generator version: {gen.get('version')}")
    jar = gen.get("jar") or {}
    lines.append(f"- generator jar cached: {jar.get('cached')}")
    if jar.get("path"):
        lines.append(f"- generator jar path: {jar.get('path')}")

    runs = plan.get("runs") or []
    lines.append(f"- languages: {len(runs)}")
    for run in runs:
        lines.append(
            f"  - {run.get('language')} -> {run.get('out_dir')} (generator={run.get('resolved_language')})"
        )
        cmd = run.get("generator_args") or []
        lines.append(f"    args: {redact(format_cli_command(cmd))}")
    return "\n".join(lines) + "\n"


def _redact_plan(plan: dict) -> dict:
    safe = json.loads(json.dumps(plan))
    settings = safe.get("settings") or {}
    post_hooks = settings.get("post_hooks")
    if isinstance(post_hooks, list):
        settings["post_hooks"] = redact_cli_args(post_hooks)
    post_hooks_by_language = settings.get("post_hooks_by_language")
    if isinstance(post_hooks_by_language, dict):
        redacted: dict = {}
        for key, hooks in post_hooks_by_language.items():
            if isinstance(hooks, list):
                redacted[str(key)] = redact_cli_args(hooks)
        settings["post_hooks_by_language"] = redacted
    safe["settings"] = settings
    engine = safe.get("engine") or {}
    java_opts = (engine.get("java_opts") or {}).get("options")
    if isinstance(java_opts, list):
        engine.setdefault("java_opts", {})["options"] = redact_cli_args(java_opts)
    for run in safe.get("runs") or []:
        argv = run.get("generator_args")
        if isinstance(argv, list):
            run["generator_args"] = redact_cli_args(argv)
    safe["engine"] = engine
    return safe


def handle_gen(args: GenArgs, *, ctx: Optional[AppContext] = None) -> int:
    if args.dry_run and args.plan_only:
        raise CLIError("--dry-run and --plan-only are mutually exclusive")

    mode = "execute"
    if args.plan_only:
        mode = "plan-only"
    elif args.dry_run:
        mode = "dry-run"

    engine_mode = args.engine
    swain_base, crudsql_base = resolve_base_urls(args.swain_base_url, args.crudsql_url)
    temp_schema: Optional[Path] = None

    try:
        chosen_version = _chosen_generator_version(args)
        jar_path = _jar_path_for_version(chosen_version)
        jar_cached = jar_path.exists()

        java_exec: Optional[str] = None
        if engine_mode == "embedded":
            runtime = jre_install_dir(create=False)
            embedded = find_embedded_java(runtime)
            java_exec = str(embedded) if embedded else None
        else:
            import shutil

            java_exec = shutil.which("java")

        resolved_args = replace(
            args,
            additional_properties=ensure_additional_property_defaults(args.additional_properties),
            generator_arg=ensure_generator_arg_defaults(args.generator_arg),
        )

        resolved_java_opts = resolve_java_opts(resolved_args.java_opts)
        java_opts = list(resolved_java_opts.options)
        parallel = int(getattr(resolved_args, "parallel", 1) or 1)
        if parallel < 1:
            raise CLIError("--parallel must be >= 1")

        languages = resolved_args.languages
        if not languages:
            raise CLIError("at least one --lang is required")

        out_dir = Path(resolved_args.out)

        plan_schema: dict
        schema_for_cmd: str

        if mode == "plan-only":
            plan_schema = _describe_schema_plan_only(resolved_args, swain_base, crudsql_base)
            schema_for_cmd = (
                resolved_args.schema
                if resolved_args.schema
                else plan_schema.get("fallback_dynamic_swagger_url")
                or (plan_schema.get("proxy_urls") or ["<dynamic schema>"])[0]
            )
        else:
            resolved_schema = resolve_schema_for_generation(
                resolved_args,
                swain_base,
                crudsql_base,
                ctx=ctx,
            )
            schema_for_cmd = resolved_schema.schema
            temp_schema = resolved_schema.temp_path
            plan_schema = {
                "mode": "resolved",
                "schema": schema_for_cmd,
                "temp_path": str(temp_schema) if temp_schema else None,
                "swain_connection_id": resolved_schema.connection.id if resolved_schema.connection else None,
            }
            if temp_schema:
                base_url = crudsql_base
                if resolved_schema.connection and resolved_schema.connection.effective_endpoint:
                    base_url = resolved_schema.connection.effective_endpoint
                if resolved_args.patch_base_url:
                    patched = inject_base_url(temp_schema, base_url)
                    if patched:
                        plan_schema["patched_base_url"] = patched
                        log(f"patched schema server URL to {patched}")
                else:
                    log("base-url patching disabled; using fetched schema as-is")

                if resolved_args.emit_patched_schema:
                    target = Path(resolved_args.emit_patched_schema).expanduser()
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(temp_schema.read_bytes())
                    plan_schema["emitted_schema"] = str(target)
                    log(f"wrote schema copy to {target}")

        plan: Dict[str, Any] = {
            "mode": mode,
            "schema": plan_schema,
            "settings": {
                "patch_base_url": resolved_args.patch_base_url,
                "emit_patched_schema": resolved_args.emit_patched_schema,
                "parallel": parallel,
                "run_hooks": bool(getattr(resolved_args, "run_hooks", False)),
                "post_hooks": list(getattr(resolved_args, "post_hooks", []) or []),
                "post_hooks_by_language": dict(
                    getattr(resolved_args, "post_hooks_by_language", {}) or {}
                ),
                "schema_cache_ttl": resolved_args.schema_cache_ttl,
                "no_schema_cache": resolved_args.no_schema_cache,
            },
            "engine": {
                "mode": engine_mode,
                "java": {"command": java_exec},
                "java_opts": {
                    "options": java_opts,
                    "provided": resolved_java_opts.provided,
                },
            },
            "generator": {
                "version": chosen_version,
                "jar": {"path": str(jar_path), "cached": jar_cached},
            },
            "runs": [],
        }

        for lang in languages:
            resolved_lang, target_dir, cmd = build_generate_command(
                schema_for_cmd,
                lang,
                resolved_args,
                out_dir,
                create=(mode == "execute"),
            )
            plan["runs"].append(
                {
                    "language": lang,
                    "resolved_language": resolved_lang,
                    "out_dir": str(target_dir),
                    "generator_args": cmd,
                }
            )

        if mode != "execute":
            if resolved_args.plan_format == "json":
                indent = 2 if resolved_args.pretty else None
                print(json.dumps(_redact_plan(plan), indent=indent, sort_keys=True))
            else:
                print(_render_plan_text(plan), end="")
            return 0

        jar = resolve_generator_jar(resolved_args.generator_version)
        out_dir.mkdir(parents=True, exist_ok=True)
        log(f"java options: {redact(format_cli_command(java_opts))}")
        hooks_configured = bool(getattr(resolved_args, "post_hooks", []) or []) or bool(
            getattr(resolved_args, "post_hooks_by_language", {}) or {}
        )
        if hooks_configured and not getattr(resolved_args, "run_hooks", False):
            log("post-generation hooks configured but disabled; pass --run-hooks to enable")
        elif hooks_configured and getattr(resolved_args, "run_hooks", False):
            log("post-generation hooks enabled; commands will run in generated SDK directories")
        runs = list(plan["runs"])
        if parallel > 1 and len(runs) > 1:
            from concurrent.futures import ThreadPoolExecutor, as_completed

            max_workers = min(parallel, len(runs))
            log(f"running generation in parallel (workers={max_workers})")

            def run_one(run: dict) -> Tuple[str, int, str]:
                resolved_lang = run["resolved_language"]
                target_dir = Path(run["out_dir"])
                cmd = list(run["generator_args"])
                log(f"generating {resolved_lang} into {target_dir}")
                current_cmd = list(cmd)
                current_java_opts = list(java_opts)
                docs_disabled = command_disables_docs(current_cmd)
                last_output = ""
                while True:
                    rc, output = run_openapi_generator(
                        jar,
                        engine_mode,
                        current_cmd,
                        current_java_opts,
                        stream=False,
                    )
                    last_output = output
                    if rc == 0:
                        return resolved_lang, 0, ""
                    oom_detected = any(marker in output for marker in OOM_MARKERS)
                    retried = False
                    if rc != 0 and oom_detected:
                        new_java_opts = replace_heap_option(
                            current_java_opts, FALLBACK_JAVA_HEAP_OPTION
                        )
                        if new_java_opts != current_java_opts:
                            current_java_opts = new_java_opts
                            log(
                                f"{resolved_lang}: detected OutOfMemoryError; retrying"
                                f" with java options: {redact(format_cli_command(current_java_opts))}"
                            )
                            retried = True
                        elif not docs_disabled:
                            current_cmd = with_docs_disabled(current_cmd)
                            docs_disabled = True
                            log(
                                f"{resolved_lang}: detected OutOfMemoryError; retrying with"
                                " OpenAPI Generator docs/tests disabled"
                            )
                            retried = True
                    if not retried:
                        return resolved_lang, rc, last_output

            results: List[Tuple[str, int, str]] = []
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = [pool.submit(run_one, run) for run in runs]
                for future in as_completed(futures):
                    results.append(future.result())

            failures = [(lang, rc, output) for (lang, rc, output) in results if rc != 0]
            if failures:
                for lang, rc, output in failures:
                    log_error(f"generation failed for {lang} (exit code {rc})")
                    if output:
                        sys.stdout.write(output)
                        if not output.endswith("\n"):
                            sys.stdout.write("\n")
                first_rc = failures[0][1]
                return first_rc if first_rc != 0 else EXIT_CODE_SUBPROCESS
            for run in runs:
                hook_rc = _run_post_hooks(
                    resolved_args,
                    language=run.get("language") or run.get("resolved_language") or "",
                    resolved_language=run.get("resolved_language") or run.get("language") or "",
                    out_dir=Path(run["out_dir"]),
                )
                if hook_rc != 0:
                    return hook_rc
            return 0

        for run in runs:
            resolved_lang = run["resolved_language"]
            target_dir = Path(run["out_dir"])
            cmd = list(run["generator_args"])
            log(f"generating {resolved_lang} into {target_dir}")
            current_cmd = list(cmd)
            current_java_opts = list(java_opts)
            docs_disabled = command_disables_docs(current_cmd)
            while True:
                rc, output = run_openapi_generator(
                    jar,
                    engine_mode,
                    current_cmd,
                    current_java_opts,
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
                            f" with java options: {redact(format_cli_command(current_java_opts))}"
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
            hook_rc = _run_post_hooks(
                resolved_args,
                language=run.get("language") or resolved_lang,
                resolved_language=resolved_lang,
                out_dir=target_dir,
            )
            if hook_rc != 0:
                return hook_rc
    finally:
        if temp_schema:
            temp_schema.unlink(missing_ok=True)
    return 0
