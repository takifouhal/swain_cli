"""CLI handlers for engine subcommands."""

from __future__ import annotations

import json
import shutil
import textwrap
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

from ..console import log, log_error
from ..constants import ENGINE_ENV_VAR, EXIT_CODE_SUBPROCESS
from ..errors import CLIError
from ..utils import format_cli_command, redact
from .core import (
    cache_root,
    downloads_dir,
    get_platform_info,
    jar_cache_dir,
    jre_install_dir,
)
from .jar import ensure_generator_jar, resolve_generator_jar
from .jre import ensure_embedded_jre, find_embedded_java
from .run import resolve_java_opts, run_openapi_generator
from .snapshot import collect_engine_snapshot, emit_engine_snapshot


def handle_list_generators(args: SimpleNamespace) -> int:
    jar = resolve_generator_jar(args.generator_version)
    resolved_java_opts = resolve_java_opts(getattr(args, "java_opts", []))
    java_opts = resolved_java_opts.options
    log(f"java options: {redact(format_cli_command(java_opts))}")
    rc, _ = run_openapi_generator(jar, args.engine, ["list"], java_opts)
    if rc != 0:
        log_error("openapi-generator list failed")
        return rc if rc != 0 else EXIT_CODE_SUBPROCESS
    return 0


def handle_engine_status(_: SimpleNamespace) -> int:
    snapshot = collect_engine_snapshot(None)
    log("engine status")
    emit_engine_snapshot(snapshot, include_selected_generator=False, include_cached_jars=True)
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
    ensure_generator_jar(args.version, verify=not getattr(args, "no_verify", False))
    log(f"cached OpenAPI Generator {args.version}")
    return 0


def handle_engine_paths(args: SimpleNamespace) -> int:
    info = get_platform_info()
    payload = {
        "platform": {"os": info.os_name, "arch": info.arch},
        "cache_root": str(cache_root(create=False)),
        "downloads_dir": str(downloads_dir(create=False)),
        "jar_cache_dir": str(jar_cache_dir(create=False)),
        "jre_install_dir": str(jre_install_dir(create=False)),
        "schema_cache_dir": str(cache_root(create=False) / "schemas"),
    }
    if getattr(args, "json", False):
        indent = 2 if getattr(args, "pretty", False) else None
        print(json.dumps(payload, indent=indent, sort_keys=True))
        return 0
    print(f"cache_root: {payload['cache_root']}")
    print(f"downloads_dir: {payload['downloads_dir']}")
    print(f"jar_cache_dir: {payload['jar_cache_dir']}")
    print(f"jre_install_dir: {payload['jre_install_dir']}")
    print(f"schema_cache_dir: {payload['schema_cache_dir']}")
    return 0


def _delete_path(path: Path) -> Optional[str]:
    try:
        if not path.exists():
            return None
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
    except OSError as exc:
        return str(exc)
    return None


def handle_engine_clean(args: SimpleNamespace) -> int:
    force = bool(getattr(args, "force", False))
    selected_any = any(
        bool(getattr(args, name, False))
        for name in ("downloads", "jars", "jre", "schemas", "all")
    )
    clean_downloads = bool(getattr(args, "all", False)) or bool(
        getattr(args, "downloads", False)
    )
    clean_jars = bool(getattr(args, "all", False)) or bool(getattr(args, "jars", False))
    clean_jre = bool(getattr(args, "all", False)) or bool(getattr(args, "jre", False))
    clean_schemas = bool(getattr(args, "all", False)) or bool(
        getattr(args, "schemas", False)
    )
    if not selected_any:
        clean_downloads = True

    targets: List[Path] = []
    if clean_downloads:
        targets.append(downloads_dir(create=False))
    if clean_jars:
        targets.append(jar_cache_dir(create=False))
    if clean_jre:
        targets.append(jre_install_dir(create=False))
    if clean_schemas:
        targets.append(cache_root(create=False) / "schemas")

    payload: Dict[str, Any] = {
        "dry_run": not force,
        "targets": [str(path) for path in targets],
        "deleted": [],
        "errors": [],
    }

    if not force:
        if getattr(args, "json", False):
            indent = 2 if getattr(args, "pretty", False) else None
            print(json.dumps(payload, indent=indent, sort_keys=True))
            return 0
        print("engine clean (dry-run):")
        for target in targets:
            print(f"- would delete: {target}")
        print("re-run with --force to apply")
        return 0

    for target in targets:
        err = _delete_path(target)
        if err:
            payload["errors"].append({"path": str(target), "error": err})
        else:
            payload["deleted"].append(str(target))

    if getattr(args, "json", False):
        indent = 2 if getattr(args, "pretty", False) else None
        print(json.dumps(payload, indent=indent, sort_keys=True))
    else:
        for deleted in payload["deleted"]:
            print(f"deleted: {deleted}")
        for record in payload["errors"]:
            log_error(f"failed to delete {record['path']}: {record['error']}")
    return 0 if not payload["errors"] else 1


def _version_key(value: str) -> Tuple[int, int, int, str]:
    parts = (value or "").split(".")
    nums: List[int] = []
    for part in parts[:3]:
        try:
            nums.append(int(part))
        except ValueError:
            nums.append(-1)
    while len(nums) < 3:
        nums.append(-1)
    return (nums[0], nums[1], nums[2], value)


def handle_engine_prune_jars(args: SimpleNamespace) -> int:
    keep = int(getattr(args, "keep", 3) or 0)
    if keep < 0:
        raise CLIError("--keep must be >= 0")
    force = bool(getattr(args, "force", False))

    root = jar_cache_dir(create=False)
    if not root.exists():
        print("no cached jars to prune")
        return 0

    entries: List[Tuple[str, Path]] = []
    for version_dir in root.iterdir():
        if not version_dir.is_dir():
            continue
        version = version_dir.name
        jar = version_dir / f"openapi-generator-cli-{version}.jar"
        if jar.exists():
            entries.append((version, version_dir))

    entries.sort(key=lambda item: _version_key(item[0]))
    keep_set = {version for version, _ in entries[-keep:]} if keep else set()
    prune = [path for version, path in entries if version not in keep_set]

    payload: Dict[str, Any] = {
        "dry_run": not force,
        "keep": keep,
        "kept_versions": sorted(keep_set, key=_version_key),
        "targets": [str(path) for path in prune],
        "deleted": [],
        "errors": [],
    }

    if not force:
        if getattr(args, "json", False):
            indent = 2 if getattr(args, "pretty", False) else None
            print(json.dumps(payload, indent=indent, sort_keys=True))
            return 0
        print("engine prune-jars (dry-run):")
        for target in prune:
            print(f"- would delete: {target}")
        print(f"kept versions: {', '.join(payload['kept_versions']) or 'none'}")
        print("re-run with --force to apply")
        return 0

    for target in prune:
        err = _delete_path(target)
        if err:
            payload["errors"].append({"path": str(target), "error": err})
        else:
            payload["deleted"].append(str(target))

    if getattr(args, "json", False):
        indent = 2 if getattr(args, "pretty", False) else None
        print(json.dumps(payload, indent=indent, sort_keys=True))
    else:
        for deleted in payload["deleted"]:
            print(f"deleted: {deleted}")
        for record in payload["errors"]:
            log_error(f"failed to delete {record['path']}: {record['error']}")
    return 0 if not payload["errors"] else 1


def handle_engine_use_system(_: SimpleNamespace) -> int:
    message = textwrap.dedent(
        f"""
        To use the system Java runtime, append '--engine system' to swain_cli commands
        (or export {ENGINE_ENV_VAR}=system).
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
